# shellcheck shell=bash
# DOXA terminal interface (cyan / Matrix-green theme)
shopt -u patsub_replacement 2>/dev/null || true

show_banner() {
  local -a art=(
' ____   ___  __  __    _    '
'|  _ \ / _ \ \ \/ /   / \   '
'| | | | | | | \  /   / _ \  '
'| |_| | |_| | /  \  / ___ \ '
'|____/ \___/ /_/\_\/_/   \_\'
  )
  local line
  printf '\n'
  for line in "${art[@]}"; do printf '  %s%s%s\n' "$C_GREEN$C_BOLD" "$line" "$C_RESET"; done
  printf '  %sWEB SECURITY AUDITOR  v%s%s\n' "$C_CYAN" "$DOXA_VERSION" "$C_RESET"
  printf '  %sScope-enforcing assessment and reporting - authorized use only%s\n\n' "$C_DIM" "$C_RESET"
}

usage() {
  cat <<EOF
${C_CYAN}${DOXA_NAME} v${DOXA_VERSION}${C_RESET}

${C_BOLD}Usage:${C_RESET}
  ./doxa.sh --target <url> [options]
  ./doxa.sh --check-tools
  ./doxa.sh                      (interactive menu)

${C_BOLD}Scan profiles (--mode):${C_RESET}
  passive     Passive reconnaissance: normal page requests, headers, cookies, TLS handshake
  standard    Standard assessment (default): passive set + nmap web ports, exposed-file probes,
              gobuster, nikto, nuclei (safe tags)
  full        Full non-destructive assessment: deeper scans + parameter indicator probing
              (probing and default-login checks need approval)
  custom      Choose modules with --modules a,b,c
  Active modules: nmap api gobuster nikto nuclei params (+ the dns subdomain wordlist); passive: recon whatweb http tls dns js evidence

${C_BOLD}Options:${C_RESET}
  -u, --target URL       Target, e.g. https://example.com  (IPv4, [IPv6], hostnames, ports supported)
  -m, --mode NAME        passive | standard | full | custom
      --modules LIST     Modules for --mode custom: recon,nmap,whatweb,http,tls,dns,js,api,gobuster,nikto,nuclei,params,evidence
      --skip LIST        Modules to skip
  -o, --output DIR       Report root directory (default: ./reports_out)
  -t, --threads N        Concurrency for gobuster/nuclei (1-100)
  -r, --rate N           Global maximum requests per second (1-1000)
      --timeout SEC      Per-tool timeout (default 900)
      --http-timeout S   Per-request timeout (default 15)
  -w, --wordlist FILE    Gobuster wordlist
      --authorized       Confirm authorization non-interactively
      --scope-host H     Approve an additional host (exact, IP or *.domain.tld). Default: target host only
      --scope-port P     Approve an additional port. Default: the target port (or 80 and 443)
      --ca-cert FILE     Trust this CA file for HTTPS (lab CAs). Certificates are verified by default
      --insecure-tls-diagnostic
                         DISABLE certificate verification. Authorized diagnostics only; recorded in the report
      --allow-dangerous  Pre-approve checks that otherwise ask (parameter probing, nuclei default-login, DNS zone transfer)
      --oast             Allow Nuclei out-of-band (interactsh) checks (contacts a third-party server)
      --compare SPEC     Compare with a previous scan: a report directory, or "auto" (latest earlier scan of this host)
      --no-pdf           Do not create report.pdf (needs chromium, wkhtmltopdf or weasyprint)
      --dns-passive-sources
                         Let the dns module use subfinder third-party passive sources (sends the domain name to external services)
      --check-tools      Show dependency status
      --no-color  -v/--verbose  -h/--help  --version

${C_BOLD}Examples:${C_RESET}
  ./doxa.sh --target https://example.com --mode passive
  ./doxa.sh --target http://127.0.0.1:3000 --mode standard --authorized
  ./doxa.sh --target https://lab.local --ca-cert ./lab-ca.pem --scope-host api.lab.local --authorized
  ./doxa.sh --target https://[::1]:8443 --mode custom --modules recon,http,tls --authorized
EOF
}

# interactive_menu -> MENU_ARGS
interactive_menu() {
  local choice target modules
  MENU_ARGS=()
  show_banner
  printf '%s  1)%s Passive reconnaissance\n%s  2)%s Standard security assessment\n%s  3)%s Full non-destructive assessment\n' "$C_GREEN" "$C_RESET" "$C_GREEN" "$C_RESET" "$C_GREEN" "$C_RESET"
  printf '%s  4)%s Custom assessment (choose modules)\n%s  5)%s Check tools\n%s  6)%s Help\n%s  0)%s Exit\n\n' "$C_GREEN" "$C_RESET" "$C_GREEN" "$C_RESET" "$C_GREEN" "$C_RESET" "$C_GREEN" "$C_RESET"
  read -r -p "Select an option: " choice
  case $choice in
    1) MENU_ARGS=(--mode passive) ;;
    2) MENU_ARGS=(--mode standard) ;;
    3) MENU_ARGS=(--mode full) ;;
    4) read -r -p "Modules (comma separated, e.g. recon,http,tls): " modules; MENU_ARGS=(--mode custom --modules "$modules") ;;
    5) MENU_ARGS=(--check-tools); return 0 ;;
    6) MENU_ARGS=(--help); return 0 ;;
    *) echo "Bye."; exit 0 ;;
  esac
  read -r -p "Target URL (e.g. https://example.com): " target
  MENU_ARGS+=(--target "$target")
}

show_summary() {
  local s n name st dur detail col
  printf '\n%s============================ ASSESSMENT SUMMARY ============================%s\n' "$C_GREEN" "$C_RESET"
  printf '  Target   : %s%s%s (%s)\n' "$C_CYAN" "$TARGET_URL" "$C_RESET" "${IPS[*]:-n/a}"
  printf '  Mode     : %s    Duration: %s    TLS verification: %s\n' "$MODE" "$(fmt_dur "$DURATION")" "$( ((INSECURE_TLS)) && echo DISABLED || echo enabled )"
  printf '  Scope    : %s requests blocked as out-of-scope\n' "$SCOPE_OOS_COUNT"
  printf '  Findings : %s total (overall risk: %s, %s CVSS-scored)\n' "$TOTAL" "$OVERALL_RISK" "$CVSS_SCORED"
  if (( COMPARE_DONE )); then
    printf '  Compared : new %s, resolved %s, persistent %s, severity changed %s, not re-tested %s (vs %s)\n' "$CMP_NEW" "$CMP_RESOLVED" "$CMP_PERSISTENT" "$CMP_CHANGED" "$CMP_NOTRETESTED" "$(basename "$COMPARE_DIR")"
  elif [[ -n $COMPARE_SPEC ]]; then
    printf '  Compared : unavailable (%s)\n' "$COMPARE_ERROR"
  fi
  for s in "${SEVERITIES[@]}"; do n="CNT_$s"; printf '    %s %s\n' "$(sev_tag "$s")" "${!n}"; done
  printf '\n  Modules:\n'
  if [[ -s ${MODULES_TSV:-/dev/null} ]]; then
    while IFS=$'\t' read -r name st dur detail; do
      case $st in OK) col=$C_GREEN ;; SKIPPED) col=$C_GREY ;; TIMEOUT) col=$C_YELLOW ;; *) col=$C_RED ;; esac
      printf '    %-10s %s%-11s%s %s\n' "$name" "$col" "$st" "$C_RESET" "$detail"
    done <"$MODULES_TSV"
  fi
  printf '\n  Report directory : %s%s%s\n' "$C_CYAN" "$OUTDIR" "$C_RESET"
  printf '    report.html  report.txt  findings.json  findings.csv  reconnaissance.txt  logs/\n    PDF: %s\n' "${PDF_STATUS:-not attempted}"
  printf '%s============================================================================%s\n' "$C_GREEN" "$C_RESET"
  (( MODULE_PROBLEMS )) && warn "$MODULE_PROBLEMS module(s) failed, timed out or were interrupted - see the report limitations section."
  return 0
}
