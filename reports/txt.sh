# shellcheck shell=bash
# DOXA plain-text report (report.txt)
shopt -u patsub_replacement 2>/dev/null || true

generate_text_report() {
  local R="$OUTDIR/report.txt" line="==============================================================================" dash="------------------------------------------------------------------------------"
  local id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn s st k
  {
    echo "$line"; echo "  $DOXA_NAME v$DOXA_VERSION - Security Assessment Report"; echo "$line"
    echo "Target       : $TARGET_URL"
    echo "Host / IPs   : $HOST / ${IPS[*]}"
    echo "Mode         : $MODE   Threads: $THREADS   Max req/s: $RATE"
    echo "Started      : $START_ISO"
    echo "Finished     : $END_ISO ($DURATION seconds)"
    echo "Server       : ${SERVER_HDR:-n/a}"
    echo; echo "1. SCOPE AND AUTHORIZATION"; echo "$dash"
    echo "Authorization: ${AUTH_METHOD:-unknown} at ${AUTH_TIME:-n/a} (operator confirmed ownership or written permission)"
    echo "Approved hosts: ${SCOPE_HOSTS[*]}"
    echo "Approved ports: ${SCOPE_PORTS[*]}"
    echo "Out-of-scope requests blocked: $SCOPE_OOS_COUNT"
    echo "TLS verification: $( ((INSECURE_TLS)) && echo 'DISABLED (diagnostic override)' || echo enabled )"
    echo; echo "2. EXECUTIVE SUMMARY"; echo "$dash"
    echo "Overall risk: $OVERALL_RISK    Findings: $TOTAL    CVSS-scored: $CVSS_SCORED    Duplicates suppressed: $FIND_DUP"
    for s in "${SEVERITIES[@]}"; do printf '  %-14s %s\n' "$s" "${SEV_COUNT[$s]}"; done
    echo "Classification:"
    for st in "${STATUSES[@]}"; do printf '  %-40s %s\n' "$st" "${STATUS_COUNT[$st]}"; done
    echo; echo "3. OWASP TOP 10 (2021) MAPPING (indicative, not a compliance statement)"; echo "$dash"
    for k in "${!OWASP_COUNT[@]}"; do printf '  %-55s %s\n' "$k" "${OWASP_COUNT[$k]}"; done | sort
    echo; echo "4. TECHNOLOGIES"; echo "$dash"
    report_technologies | sed 's/^/  - /'
    echo; echo "5. OPEN PORTS AND SERVICES"; echo "$dash"
    if [[ -s $LOG_DIR/open_ports.txt ]]; then sed 's/^/  /' "$LOG_DIR/open_ports.txt"; else echo "  (no port scan data)"; fi
    echo; echo "6. FINDINGS"; echo "$dash"
    while IFS=$'\037' read -r id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn; do
      echo; echo "[$sev] $id  $title"
      echo "  Classification : $status   Confidence: $conf"
      echo "  Affected URL   : $url"
      echo "  OWASP          : $owasp"
      if [[ -n $cs ]]; then echo "  CVSS 3.1       : $cs ($(cvss_rating "$cs"))  $cv"; else echo "  CVSS           : not scored"; fi
      echo "  CVSS note      : $cj"
      echo "  Module / tool  : $module / $tool   at $ts"
      echo "  Description    : $(unesc "$desc")"
      echo "  Impact         : $(unesc "$impact")"
      echo "  Evidence       :"; printf '%s\n' "$(unesc "$ev")" | sed 's/^/      /'
      echo "  Remediation    : $rem"
      [[ -n $fpn ]] && echo "  False positives: $fpn"
    done <"$FINAL_TSV"
    echo; echo "7. MODULE AND TOOL EXECUTION"; echo "$dash"
    if [[ -s $MODULES_TSV ]]; then awk -F'\t' '{ printf "  %-10s %-12s %4ss  %s\n", $1, $2, $3, $4 }' "$MODULES_TSV"; fi
    echo
    if [[ -s $TOOLS_TSV ]]; then awk -F'\t' '{ printf "  $ %s   [exit %s, %ss]\n", $2, $3, $4 }' "$TOOLS_TSV"; fi
    echo; echo "8. LIMITATIONS AND UNTESTED AREAS"; echo "$dash"
    report_limitations | sed 's/^/  - /'
    echo; echo "9. EVIDENCE INTEGRITY (SHA-256)"; echo "$dash"
    echo "  Artefact manifest: logs/evidence.sha256 ($(wc -l <"$LOG_DIR/evidence.sha256" 2>/dev/null | tr -d ' ') files); report files: logs/reports.sha256"
    echo; echo "$line"; echo "Confidential: contains security-sensitive information. Secrets are redacted."; echo "$line"
  } >"$R"
}
