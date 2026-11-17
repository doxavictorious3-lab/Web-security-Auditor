#!/usr/bin/env bash
# =============================================================================
#  DOXA Web Security Auditor  v2.0.0
#  Modular, scope-enforcing web application assessment and reporting (Kali / Debian).
#
#  FOR AUTHORIZED TESTING ONLY. Scan only systems you own or have explicit written
#  permission to test. DOXA never exploits vulnerabilities, extracts credentials,
#  modifies data, uploads files, brute-forces logins or performs denial of service.
#
#  Exit codes: 0 ok | 1 usage/validation | 2 missing dependency
#              3 finished with failed modules | 4 finished, HIGH/CRITICAL found | 130 interrupted
# =============================================================================

if [[ -z "${BASH_VERSION:-}" ]] || (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  echo "DOXA requires Bash >= 4.4" >&2; exit 1
fi
# Strict mode without "set -e": a failing scanner must not abort the audit. Each module
# reports its own failure through run_module, and failures are written to the report.
set -uo pipefail
shopt -u patsub_replacement 2>/dev/null || true

readonly DOXA_NAME="DOXA Web Security Auditor"
readonly DOXA_VERSION="2.1.0"
DOXA_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DOXA_HOME
readonly EX_OK=0 EX_USAGE=1 EX_DEPS=2 EX_MODFAIL=3 EX_HIGHRISK=4 EX_INT=130

# ---- libraries ---------------------------------------------------------------
# shellcheck source=lib/logging.sh
source "$DOXA_HOME/lib/logging.sh"
source "$DOXA_HOME/lib/common.sh"
source "$DOXA_HOME/lib/validation.sh"
source "$DOXA_HOME/lib/scope.sh"
source "$DOXA_HOME/lib/findings.sh"
source "$DOXA_HOME/lib/config.sh"
source "$DOXA_HOME/lib/compare.sh"
source "$DOXA_HOME/lib/ui.sh"
for _m in recon nmap whatweb http tls dns javascript api directories nikto nuclei params evidence; do
  source "$DOXA_HOME/modules/$_m.sh"
done
for _r in common json txt html pdf; do
  if [[ -r "$DOXA_HOME/reports/$_r.sh" ]]; then source "$DOXA_HOME/reports/$_r.sh"; fi
done
unset _m _r

# ---- global state --------------------------------------------------------------
TARGET="" MODE="standard" OUTPUT_ROOT="$DOXA_HOME/reports_out" WORDLIST=""
THREADS="" RATE="" TOOL_TIMEOUT=900 CURL_TIMEOUT=15 DEFAULT_THREADS="" DEFAULT_RATE=""
SKIP_MODULES="" CUSTOM_MODULES="" AUTHORIZED=0 ALLOW_DANGEROUS=0 USE_OAST=0 CHECK_TOOLS=0 VERBOSE=0
AUTH_METHOD="" AUTH_TIME="" SELECTED_MODULES="" PROFILE_DESC="" PROFILE_MODULES="" PROFILE_THREADS="" PROFILE_RATE=""
SCHEME="" HOST="" PORT="" PATH_PREFIX="" BASE_URL="" TARGET_URL="" IS_IP=0 IS_IPV6=0 HOST_URL=""
HTTP_BASE="" HTTPS_BASE="" HTTPS_PORT=443 SCAN_BASE="" SCAN_URL=""
HTTP_OK=0 HTTPS_OK=0 HTTPS_PRESENT=0 WEB_OK=0
IPS=() IP="" LIMITS=()
OUTDIR="" TMPD="" LOG_DIR="" TOOLS_TSV="" MODULES_TSV="" RECON_FILE="" TECH_FILE=""
ROOT_HDR="" ROOT_BODY="" ROOT_URL="" ROOT_CODE="" COOKIE_HDR="" CHAIN_ALL_HDR="" SERVER_HDR="" PAGE_TITLE="" B404_CODE="" B404_LEN="" B404_MD5=""
CHILD_PID="" CURRENT_MODULE="" MODULE_START=0 MODULE_IDX=0 MODULE_TOTAL=0 MODULE_STATUS="" MODULE_DETAIL="" SKIP_REASON=""
INTERRUPTING=0 START_EPOCH=0 START_ISO="" END_ISO="" DURATION=0 MODULE_PROBLEMS=0
SCOPE_PORTS_DEFAULTED=1 FINDINGS_TSV="/dev/null"
declare -A TOOL_VER=()
declare -A MOD_FUNC=([recon]=collect_recon [nmap]=run_nmap [whatweb]=run_whatweb [http]=check_http_headers [tls]=check_tls
                     [dns]=run_dns [js]=run_js [api]=run_api
                     [gobuster]=run_gobuster [nikto]=run_nikto [nuclei]=run_nuclei [params]=run_params [evidence]=collect_evidence)
# Requirements: tool names, @web (verified web service reachable), @tls (HTTPS endpoint present)
declare -A MOD_REQ=([recon]="curl" [nmap]="nmap" [whatweb]="whatweb @web" [http]="curl @web" [tls]="openssl @tls"
                    [dns]="dig" [js]="curl @web" [api]="curl @web"
                    [gobuster]="gobuster @web" [nikto]="nikto @web" [nuclei]="nuclei @web" [params]="curl @web" [evidence]="@web")
readonly MODULE_ORDER=(recon nmap whatweb http tls dns js api gobuster nikto nuclei params evidence)
readonly PASSIVE_MODULES="recon whatweb http tls dns js evidence"

REQUIRED_TOOLS=(curl awk sed grep timeout mktemp date sort md5sum sha256sum od head tr wc cut)
OPTIONAL_TOOLS=(nmap nikto gobuster whatweb nuclei sslyze openssl dig jq subfinder wkhtmltopdf weasyprint)

# ---- dependency checks ------------------------------------------------------------
# bad_version TEXT: true when a tool printed usage/error text instead of a version
bad_version() { [[ -z $1 ]] || grep -qiE 'usage:|no help topic|unknown (command|flag|option)|unrecognized|invalid|error|not found' <<<"$1"; }

tool_version() {
  local t=$1 v="" a
  case $t in
    curl) v=$(curl --version 2>&1 | head -1) ;;
    jq) v=$(jq --version 2>&1 | head -1) ;;
    nmap) v=$(nmap --version 2>&1 | head -1) ;;
    nikto) v=$(timeout 20 nikto -Version 2>&1 </dev/null | grep -iE 'nikto' | head -1) ;;
    gobuster) for a in version --version -v; do v=$(timeout 20 gobuster "$a" 2>&1 </dev/null | head -1); bad_version "$v" || break; v=""; done ;;
    whatweb) v=$(timeout 20 whatweb --version 2>&1 </dev/null | head -1) ;;
    nuclei) v=$(timeout 20 nuclei -version 2>&1 </dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -i version | head -1) ;;
    sslyze) for a in --version -V; do v=$(timeout 20 sslyze "$a" 2>&1 </dev/null | head -1); bad_version "$v" || break; v=""; done
            [[ -n $v ]] || { v=$(python3 -c 'import sslyze; print("sslyze " + sslyze.__version__)' 2>/dev/null); } ;;
    openssl) v=$(openssl version 2>&1 | head -1) ;;
    dig) v=$(dig -v 2>&1 | head -1) ;;
  esac
  v=${v#\[INF\] }
  if bad_version "$v" && have dpkg-query; then
    v=$(dpkg-query -W -f='${Version}' "$t" 2>/dev/null)
    [[ -n $v ]] && v="$t (package $v)"
  fi
  bad_version "$v" && v="installed (version not reported)"
  printf '%s' "$v" | cut -c1-80
}

check_dependencies() { # $1=1 verbose
  local verbose=${1:-0} t miss_req=0
  (( verbose )) && printf '%sRequired tools%s\n' "$C_BOLD" "$C_RESET"
  for t in "${REQUIRED_TOOLS[@]}"; do
    if have "$t"; then (( verbose )) && printf '  %s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$t"
    else miss_req=$((miss_req + 1)); printf '  %s[MISSING]%s %s (required)\n' "$C_RED" "$C_RESET" "$t"; fi
  done
  (( verbose )) && printf '\n%sOptional tools (a module whose tool is missing is SKIPPED and reported)%s\n' "$C_BOLD" "$C_RESET"
  for t in "${OPTIONAL_TOOLS[@]}"; do
    if have "$t"; then
      TOOL_VER[$t]=$(tool_version "$t")
      (( verbose )) && printf '  %s[ OK ]%s %-9s %s%s%s\n' "$C_GREEN" "$C_RESET" "$t" "$C_DIM" "${TOOL_VER[$t]}" "$C_RESET"
    else
      (( verbose )) && printf '  %s[MISSING]%s %s\n' "$C_YELLOW" "$C_RESET" "$t"
    fi
  done
  if (( verbose )); then
    local shot=none; for t in chromium chromium-browser google-chrome gowitness; do have "$t" && { shot=$t; break; }; done
    printf '  screenshot tool: %s\n' "$shot"
    pdf_tool_detect; printf '  PDF tool: %s\n' "${PDF_TOOL:-none (report.pdf will be skipped)}"
    printf '\nInstall on Kali/Debian:  ./install.sh   (or: sudo apt install -y curl jq nmap nikto gobuster whatweb nuclei sslyze dnsutils openssl chromium)\n'
    printf 'Nuclei templates:        nuclei -update-templates\n'
  fi
  (( miss_req == 0 ))
}

resolve_target() {
  local out
  if (( IS_IP )); then IPS=("$HOST"); IP=$HOST; return 0; fi
  if have getent; then out=$(getent ahosts "$HOST" 2>/dev/null | awk '{print $1}' | sort -u)
  elif have dig; then out=$(dig +short +time=3 +tries=1 "$HOST" A 2>/dev/null | grep -E '^[0-9.]+$')
  else out=""; fi
  [[ -n $out ]] || return 1
  mapfile -t IPS <<<"$out"; IP=${IPS[0]}
  return 0
}

confirm_authorization() {
  if (( AUTHORIZED )); then AUTH_METHOD="command-line flag (--authorized)"; AUTH_TIME=$(now_iso); log AUTH "asserted via --authorized for $TARGET_URL"; return 0; fi
  [[ -t 0 ]] || die $EX_USAGE "Non-interactive session: pass --authorized to confirm you may test $HOST"
  printf '%s!! LEGAL NOTICE !!%s\n' "$C_RED$C_BOLD" "$C_RESET"
  printf '  Target: %s%s%s (%s)\n  Approved hosts: %s   Approved ports: %s\n' "$C_CYAN" "$TARGET_URL" "$C_RESET" "${IPS[*]}" "${SCOPE_HOSTS[*]}" "${SCOPE_PORTS[*]}"
  printf '  Scanning systems without permission is illegal. Continue only if you own this\n  system or hold explicit written authorization.\n\n'
  local a; read -r -p "  Type 'I AUTHORIZE' to continue: " a
  [[ $a == "I AUTHORIZE" ]] || die $EX_USAGE "Authorization not confirmed. Aborting."
  AUTH_METHOD="interactive confirmation"; AUTH_TIME=$(now_iso); log AUTH "confirmed interactively for $TARGET_URL"
}

init_workspace() {
  local ts safe
  ts=$(date +%Y%m%d_%H%M%S)
  safe=${HOST//[^A-Za-z0-9._-]/_}; [[ -n $PORT ]] && safe+="_$PORT"
  OUTDIR="$OUTPUT_ROOT/${safe}_${ts}"
  umask 077
  mkdir -p "$OUTDIR"/{nmap,nuclei,nikto,gobuster,screenshots,logs} || die $EX_USAGE "Cannot create $OUTDIR"
  OUTDIR=$(cd "$OUTDIR" && pwd)
  make_tmpdir || die $EX_USAGE "Cannot create a temporary directory"
  LOG_DIR="$OUTDIR/logs"; MAIN_LOG="$LOG_DIR/doxa.log"
  FINDINGS_TSV="$LOG_DIR/findings.raw.tsv"; : >"$FINDINGS_TSV"
  MODULES_TSV="$LOG_DIR/modules.tsv"; : >"$MODULES_TSV"
  TOOLS_TSV="$LOG_DIR/tools.tsv"; : >"$TOOLS_TSV"
  RECON_FILE="$OUTDIR/reconnaissance.txt"; : >"$RECON_FILE"
  TECH_FILE="$LOG_DIR/technologies.txt"; : >"$TECH_FILE"
  ROOT_HDR="$TMPD/root.hdr"; ROOT_BODY="$TMPD/root.body"; : >"$ROOT_HDR"; : >"$ROOT_BODY"
  log INFO "$DOXA_NAME $DOXA_VERSION started; target=$TARGET_URL mode=$MODE threads=$THREADS rate=$RATE tls_verify=$((1 - INSECURE_TLS))"
}

# ---- module framework ------------------------------------------------------------
select_modules() {
  local m
  case $MODE in
    custom) [[ -n $CUSTOM_MODULES ]] || die $EX_USAGE "--mode custom requires --modules a,b,c" ;;
  esac
  load_profile "$MODE" "$DOXA_HOME/config/profiles.conf" || die $EX_USAGE "Unknown or missing profile '$MODE' in config/profiles.conf"
  [[ $MODE == custom ]] && PROFILE_MODULES=$CUSTOM_MODULES
  SELECTED_MODULES=""
  for m in "${MODULE_ORDER[@]}"; do
    if [[ ,$PROFILE_MODULES, == *,$m,* && ,$SKIP_MODULES, != *,$m,* ]]; then SELECTED_MODULES+="${SELECTED_MODULES:+,}$m"; fi
  done
  [[ -n $SELECTED_MODULES ]] || die $EX_USAGE "No modules selected (check --modules/--skip)"
  MODULE_TOTAL=$(tr ',' '\n' <<<"$SELECTED_MODULES" | wc -l | tr -d ' ')
}

record_module() { # name status duration detail
  local d=${4//$'\t'/ }; d=${d//$'\n'/ }
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$d" >>"$MODULES_TSV"
}

finish_module() {
  local col
  case $2 in OK) col=$C_GREEN ;; SKIPPED) col=$C_GREY ;; TIMEOUT) col=$C_YELLOW ;; *) col=$C_RED ;; esac
  record_module "$1" "$2" "$3" "$4"
  printf '    %s%-11s%s %s %s(%ss)%s\n' "$col" "$2" "$C_RESET" "$4" "$C_DIM" "$3" "$C_RESET"
  case $2 in FAILED|TIMEOUT|INTERRUPTED) MODULE_PROBLEMS=$((MODULE_PROBLEMS + 1)); log WARN "module $1: $2 - $4" ;; esac
}

run_module() { # run_module name
  local name=$1 func=${MOD_FUNC[$1]} r rc=0 dur st
  MODULE_IDX=$((MODULE_IDX + 1))
  printf '\n%s[%02d/%02d]%s %s%-9s%s %s\n' "$C_CYAN" "$MODULE_IDX" "$MODULE_TOTAL" "$C_RESET" "$C_BOLD" "${name^^}" "$C_RESET" "$(progress_bar "$MODULE_IDX" "$MODULE_TOTAL")"
  for r in ${MOD_REQ[$name]}; do
    case $r in
      @web) (( WEB_OK )) || { finish_module "$name" SKIPPED 0 "no verified HTTP(S) service reachable"; return 0; } ;;
      @tls) (( HTTPS_OK || HTTPS_PRESENT )) || { finish_module "$name" SKIPPED 0 "no HTTPS endpoint detected"; return 0; } ;;
      *) have "$r" || { finish_module "$name" SKIPPED 0 "required tool not installed: $r"; return 0; } ;;
    esac
  done
  CURRENT_MODULE=$name; MODULE_START=$SECONDS; MODULE_STATUS=""; MODULE_DETAIL=""
  "$func" || rc=$?
  dur=$((SECONDS - MODULE_START))
  if [[ -n $MODULE_STATUS ]]; then st=$MODULE_STATUS
  elif (( rc == 0 )); then st=OK
  elif (( rc == 124 )); then st=TIMEOUT
  else st=FAILED; fi
  CURRENT_MODULE=""
  finish_module "$name" "$st" "$dur" "${MODULE_DETAIL:-exit code $rc}"
  return 0
}

run_selected_modules() {
  local m
  for m in "${MODULE_ORDER[@]}"; do
    if [[ ,$SELECTED_MODULES, == *,$m,* ]]; then run_module "$m"
    elif [[ ,$SKIP_MODULES, == *,$m,* ]]; then record_module "$m" SKIPPED 0 "skipped by --skip"
    else record_module "$m" SKIPPED 0 "not part of the '$MODE' profile"; fi
  done
}

# ---- finalisation -------------------------------------------------------------------
finalize_reports() {
  END_ISO=$(now_iso)
  DURATION=$(( $(date +%s) - START_EPOCH ))
  report_prepare
  compare_scans || true
  write_hashes
  pdf_tool_detect
  generate_html_report || err "HTML report failed"
  generate_pdf_report || true
  generate_json_report || err "JSON report failed"
  generate_csv_report || err "CSV report failed"
  generate_comparison_csv || err "comparison CSV failed"
  generate_text_report || err "TXT report failed"
  write_report_hashes
}

on_interrupt() {
  (( INTERRUPTING )) && exit $EX_INT
  INTERRUPTING=1
  printf '\n'; warn "Interrupted - stopping tools and writing a partial report"
  [[ -n $CHILD_PID ]] && kill -TERM "$CHILD_PID" 2>/dev/null
  if [[ -n $CURRENT_MODULE ]]; then
    record_module "$CURRENT_MODULE" INTERRUPTED $((SECONDS - MODULE_START)) "interrupted by user"
    MODULE_PROBLEMS=$((MODULE_PROBLEMS + 1))
  fi
  if [[ -n $OUTDIR && -n $TMPD ]]; then finalize_reports; show_summary; fi
  exit $EX_INT
}

# ---- argument parsing -------------------------------------------------------------------
need_arg() { [[ $2 -ge 2 ]] || die $EX_USAGE "Option $1 requires a value"; }

parse_args() {
  local mode_set=""
  while (( $# )); do
    case $1 in
      -u|--url|--target) need_arg "$1" $#; TARGET=$2; shift 2 ;;
      --url=*|--target=*) TARGET=${1#*=}; shift ;;
      -m|--mode)      need_arg "$1" $#; MODE=${2,,}; mode_set=1; shift 2 ;;
      --mode=*)       MODE=${1#*=}; MODE=${MODE,,}; mode_set=1; shift ;;
      --passive)      MODE=passive; mode_set=1; shift ;;
      --full)         MODE=full; mode_set=1; shift ;;
      --modules)      need_arg "$1" $#; CUSTOM_MODULES=${2,,}; shift 2 ;;
      -o|--output)    need_arg "$1" $#; OUTPUT_ROOT=$2; shift 2 ;;
      -w|--wordlist)  need_arg "$1" $#; WORDLIST=$2; shift 2 ;;
      -t|--threads)   need_arg "$1" $#; THREADS=$2; shift 2 ;;
      -r|--rate)      need_arg "$1" $#; RATE=$2; shift 2 ;;
      --timeout)      need_arg "$1" $#; TOOL_TIMEOUT=$2; shift 2 ;;
      --http-timeout) need_arg "$1" $#; CURL_TIMEOUT=$2; shift 2 ;;
      --skip)         need_arg "$1" $#; SKIP_MODULES=${2,,}; shift 2 ;;
      --scope-host)   need_arg "$1" $#; scope_add_host "$2" || die $EX_USAGE "$VALIDATION_ERROR"; shift 2 ;;
      --scope-port)   need_arg "$1" $#; scope_add_port "$2" || die $EX_USAGE "$VALIDATION_ERROR"; shift 2 ;;
      --ca-cert)      need_arg "$1" $#; CA_CERT=$2; shift 2 ;;
      --insecure-tls-diagnostic) INSECURE_TLS=1; shift ;;
      --compare)      need_arg "$1" $#; COMPARE_SPEC=$2; shift 2 ;;
      --no-pdf)       NO_PDF=1; shift ;;
      --dns-passive-sources) DNS_PASSIVE_SOURCES=1; shift ;;
      --authorized)   AUTHORIZED=1; shift ;;
      --allow-dangerous) ALLOW_DANGEROUS=1; shift ;;
      --oast)         USE_OAST=1; shift ;;
      --no-color)     OPT_NO_COLOR=1; setup_colors; shift ;;
      --check-tools)  CHECK_TOOLS=1; shift ;;
      -v|--verbose)   VERBOSE=1; shift ;;
      -h|--help)      usage; exit $EX_OK ;;
      --version)      echo "$DOXA_NAME $DOXA_VERSION"; exit $EX_OK ;;
      *)              err "Unknown option: $1"; usage >&2; exit $EX_USAGE ;;
    esac
  done
  : "$mode_set"
  case $MODE in passive|standard|full|custom) ;; *) die $EX_USAGE "Unknown mode '$MODE' (passive, standard, full, custom)" ;; esac
  if [[ -n $THREADS ]]; then validate_int "--threads" "$THREADS" 1 100 || die $EX_USAGE "$VALIDATION_ERROR"; fi
  if [[ -n $RATE ]]; then validate_int "--rate" "$RATE" 1 1000 || die $EX_USAGE "$VALIDATION_ERROR"; fi
  validate_int "--timeout" "$TOOL_TIMEOUT" 10 86400 || die $EX_USAGE "$VALIDATION_ERROR"
  validate_int "--http-timeout" "$CURL_TIMEOUT" 2 300 || die $EX_USAGE "$VALIDATION_ERROR"
  validate_output_dir "$OUTPUT_ROOT" || die $EX_USAGE "$VALIDATION_ERROR"
  if [[ -n $WORDLIST && ! -r $WORDLIST ]]; then die $EX_USAGE "Wordlist not readable: $WORDLIST"; fi
  if [[ -n $CA_CERT && ! -r $CA_CERT ]]; then die $EX_USAGE "CA certificate not readable: $CA_CERT"; fi
  local m
  for m in ${CUSTOM_MODULES//,/ } ${SKIP_MODULES//,/ }; do
    [[ -n ${MOD_FUNC[$m]:-} ]] || die $EX_USAGE "Unknown module '$m' (valid: ${MODULE_ORDER[*]})"
  done
}

main() {
  trap on_interrupt INT TERM
  trap cleanup EXIT
  load_settings "$DOXA_HOME/config/settings.conf"
  if (( $# == 0 )) && [[ -t 0 && -t 1 || -n ${DOXA_MENU_STDIN:-} ]]; then interactive_menu; set -- "${MENU_ARGS[@]}"; fi
  parse_args "$@"
  setup_colors

  if (( CHECK_TOOLS )); then show_banner; check_dependencies 1; exit $(( $? == 0 ? EX_OK : EX_DEPS )); fi
  [[ -n $TARGET ]] || { show_banner; err "No target supplied (--target URL)."; usage >&2; exit $EX_USAGE; }

  show_banner
  validate_target "$TARGET" || die $EX_USAGE "Invalid target '$TARGET': $VALIDATION_ERROR"
  check_dependencies 0 || die $EX_DEPS "Required tools are missing. Run: ./doxa.sh --check-tools"
  resolve_target || die $EX_USAGE "Cannot resolve '$HOST'. Check the hostname or DNS."
  scope_init
  select_modules
  : "${THREADS:=${PROFILE_THREADS:-10}}"; : "${RATE:=${PROFILE_RATE:-30}}"
  [[ -n $DEFAULT_THREADS && -z ${PROFILE_THREADS:-} ]] && THREADS=$DEFAULT_THREADS
  validate_int "threads" "$THREADS" 1 100 && validate_int "rate" "$RATE" 1 1000 || die $EX_USAGE "$VALIDATION_ERROR"
  build_curl_base
  confirm_authorization
  init_workspace

  START_EPOCH=$(date +%s); START_ISO=$(now_iso)
  scan_meta_write
  info "Target     : ${C_CYAN}${TARGET_URL}${C_RESET}  (${IPS[*]})"
  info "Scope      : hosts=[${SCOPE_HOSTS[*]}] ports=[${SCOPE_PORTS[*]}]"
  info "Profile    : ${MODE} - ${PROFILE_DESC}"
  info "Modules    : ${SELECTED_MODULES//,/ }"
  info "Limits     : threads=${THREADS} rate=${RATE}/s tool-timeout=${TOOL_TIMEOUT}s tls-verify=$( ((INSECURE_TLS)) && echo OFF || echo on )"
  info "Output     : ${OUTDIR}"
  if (( INSECURE_TLS )); then
    warn "TLS certificate verification is DISABLED (--insecure-tls-diagnostic). Use only on systems you are authorized to test."
    CURRENT_MODULE=core
    add_finding "TLS certificate verification disabled for this scan" "$TARGET_URL" "TLS configuration" INFORMATIONAL "Informational observation" \
      "The operator disabled certificate verification as an explicit diagnostic override; HTTPS results do not prove the certificate is valid." \
      "--insecure-tls-diagnostic was supplied" "doxa-core" High "Re-run without the override once a trusted certificate (or --ca-cert) is available." ""
    CURRENT_MODULE=""
  fi

  run_selected_modules

  printf '\n%s[*]%s Normalising findings and generating reports...\n' "$C_CYAN" "$C_RESET"
  finalize_reports
  show_summary
  if (( CNT_CRITICAL + CNT_HIGH > 0 )); then exit $EX_HIGHRISK; fi
  if (( MODULE_PROBLEMS > 0 )); then exit $EX_MODFAIL; fi
  exit $EX_OK
}

if [[ ${DOXA_SOURCE_ONLY:-0} != 1 ]]; then main "$@"; fi
