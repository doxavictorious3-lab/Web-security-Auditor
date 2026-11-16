# shellcheck shell=bash
# DOXA reporting core. All reports are generated from the same data:
#   logs/findings.final.tsv (sorted by severity, stable IDs DOXA-001...), modules.tsv, tools.tsv.
# Final record layout (20 fields):
#  1 id 2 fingerprint 3 severity 4 title 5 url 6 category 7 classification 8 confidence 9 module
#  10 tool 11 timestamp 12 owasp 13 cvss_score 14 cvss_vector 15 cvss_justification
#  16 description 17 impact 18 evidence 19 remediation 20 false_positive_notes
shopt -u patsub_replacement 2>/dev/null || true

FINAL_TSV=""
declare -A SEV_COUNT=() STATUS_COUNT=() OWASP_COUNT=()
TOTAL=0 CNT_CRITICAL=0 CNT_HIGH=0 CNT_MEDIUM=0 CNT_LOW=0 CNT_INFORMATIONAL=0
CVSS_SCORED=0 OVERALL_RISK="Informational"
readonly SEVERITIES=(CRITICAL HIGH MEDIUM LOW INFORMATIONAL)
readonly STATUSES=("Confirmed vulnerability" "Potential vulnerability" "Informational observation" "False positive or unverified result")

# unesc: restore newlines stored as RS
unesc() { printf '%s' "${1//$'\036'/$'\n'}"; }

report_prepare() {
  FINAL_TSV="$LOG_DIR/findings.final.tsv"
  : >"$FINAL_TSV"
  if [[ -s $FINDINGS_TSV ]]; then
    LC_ALL=C awk -F'\037' -v OFS='\037' '{ r=($2=="CRITICAL")?5:($2=="HIGH")?4:($2=="MEDIUM")?3:($2=="LOW")?2:1; print r, $0 }' "$FINDINGS_TSV" \
      | LC_ALL=C sort -t $'\037' -k1,1nr -k4,4 -s \
      | LC_ALL=C awk -F'\037' -v OFS='\037' '{ $1 = sprintf("DOXA-%03d", NR); print }' >"$FINAL_TSV"
  fi
  SEV_COUNT=(); STATUS_COUNT=(); OWASP_COUNT=(); TOTAL=0; CVSS_SCORED=0
  local s st; for s in "${SEVERITIES[@]}"; do SEV_COUNT[$s]=0; done
  for st in "${STATUSES[@]}"; do STATUS_COUNT[$st]=0; done
  local id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn
  while IFS=$'\037' read -r id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn; do
    TOTAL=$((TOTAL + 1))
    SEV_COUNT[$sev]=$(( ${SEV_COUNT[$sev]:-0} + 1 ))
    STATUS_COUNT[$status]=$(( ${STATUS_COUNT[$status]:-0} + 1 ))
    OWASP_COUNT[$owasp]=$(( ${OWASP_COUNT[$owasp]:-0} + 1 ))
    [[ -n $cs ]] && CVSS_SCORED=$((CVSS_SCORED + 1))
  done <"$FINAL_TSV"
  CNT_CRITICAL=${SEV_COUNT[CRITICAL]}; CNT_HIGH=${SEV_COUNT[HIGH]}; CNT_MEDIUM=${SEV_COUNT[MEDIUM]}
  CNT_LOW=${SEV_COUNT[LOW]}; CNT_INFORMATIONAL=${SEV_COUNT[INFORMATIONAL]}
  if (( CNT_CRITICAL )); then OVERALL_RISK=Critical
  elif (( CNT_HIGH )); then OVERALL_RISK=High
  elif (( CNT_MEDIUM )); then OVERALL_RISK=Medium
  elif (( CNT_LOW )); then OVERALL_RISK=Low
  else OVERALL_RISK=Informational; fi
}

# Static limitations plus dynamic ones (skipped/failed modules, approvals, diagnostics)
report_limitations() { # prints one limitation per line
  {
    echo "Point-in-time, unauthenticated black-box assessment; authenticated areas, session handling after login and business logic were not tested."
    echo "Automated scanners produce false positives and false negatives; every finding classified as Potential or Unverified requires manual validation."
    echo "No exploitation, credential extraction, data modification, file upload, brute-force or denial-of-service testing was performed."
    echo "Only approved hosts and ports were contacted; redirects to unapproved destinations were not followed."
    echo "Wordlist-based discovery cannot prove absence of content; JavaScript-rendered routes and authenticated API endpoints were not enumerated."
    echo "OWASP Top 10 mapping is indicative. It does not establish compliance or non-compliance with any standard."
    echo "CVSS scores are provided only where the evidence supports a defensible vector; all other findings are intentionally not scored."
    [[ $MODE == passive ]] && echo "Passive mode: scanners and path probing were not run."
    (( INSECURE_TLS )) && echo "TLS certificate verification was DISABLED for this scan (--insecure-tls-diagnostic); results over HTTPS do not prove certificate validity."
    local x; for x in "${LIMITS[@]}"; do echo "$x"; done
    [[ -s $MODULES_TSV ]] && awk -F'\t' '$2 != "OK" { printf "Module %s %s: %s\n", $1, tolower($2), $4 }' "$MODULES_TSV"
  } | awk '!seen[$0]++'
}

report_technologies() { sort -u "$TECH_FILE" 2>/dev/null | grep -v '^$'; }
report_open_ports() { [[ -s $LOG_DIR/open_ports.txt ]] && cat "$LOG_DIR/open_ports.txt"; return 0; }

write_hashes() { # artefact manifest (excludes reports and the append-only main log)
  ( cd "$OUTDIR" && find . -type f ! -name evidence.sha256 ! -name reports.sha256 ! -name doxa.log \
      ! -name 'report.*' ! -name 'findings.json' ! -name 'findings.csv' -print0 \
      | LC_ALL=C sort -z | xargs -0 -r sha256sum >logs/evidence.sha256 ) 2>/dev/null || true
}
write_report_hashes() {
  ( cd "$OUTDIR" && sha256sum logs/doxa.log report.html report.txt report.pdf findings.json findings.csv 2>/dev/null >logs/reports.sha256 ) || true
}

