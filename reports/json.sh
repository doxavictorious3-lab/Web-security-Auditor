# shellcheck shell=bash
# DOXA JSON report (findings.json). Built in Bash; validity is covered by tests/run_tests.sh.
shopt -u patsub_replacement 2>/dev/null || true

json_array_lines() { # stdin lines -> JSON array of strings
  local line first=1
  printf '['
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    (( first )) || printf ','
    first=0; json_str "$line"
  done
  printf ']'
}

json_num() { [[ $1 =~ ^[0-9]+(\.[0-9]+)?$ ]] && printf '%s' "$1" || printf 'null'; }

generate_json_report() {
  local J="$OUTDIR/findings.json" first=1 s st k
  {
    printf '{\n"framework":{"name":%s,"version":%s,"report_schema":"2.0"},\n' "$(json_str "$DOXA_NAME")" "$(json_str "$DOXA_VERSION")"
    printf '"assessment":{"target":%s,"host":%s,"ip_addresses":%s,"mode":%s,"profile_description":%s,"modules_selected":%s,' \
      "$(json_str "$TARGET_URL")" "$(json_str "$HOST")" "$(printf '%s\n' "${IPS[@]}" | json_array_lines)" "$(json_str "$MODE")" \
      "$(json_str "${PROFILE_DESC:-}")" "$(tr ',' '\n' <<<"${SELECTED_MODULES:-}" | json_array_lines)"
    printf '"scan_base":%s,"started":%s,"finished":%s,"duration_seconds":%s,"threads":%s,"max_requests_per_second":%s,"operator":%s,' \
      "$(json_str "${SCAN_BASE:-}")" "$(json_str "$START_ISO")" "$(json_str "$END_ISO")" "$(json_num "$DURATION")" "$(json_num "$THREADS")" "$(json_num "$RATE")" \
      "$(json_str "$(whoami 2>/dev/null)@$(hostname 2>/dev/null)")"
    printf '"authorization":{"method":%s,"confirmed_at":%s,"statement":%s},' "$(json_str "${AUTH_METHOD:-unknown}")" "$(json_str "${AUTH_TIME:-}")" \
      "$(json_str "Operator confirmed ownership of, or written permission to test, the in-scope assets.")"
    printf '"scope":{"approved_hosts":%s,"approved_ports":%s,"ports_defaulted":%s,"out_of_scope_requests_blocked":%s,"tls_verification":%s,"ca_cert":%s}},\n' \
      "$(printf '%s\n' "${SCOPE_HOSTS[@]}" | json_array_lines)" "$(printf '%s\n' "${SCOPE_PORTS[@]}" | json_array_lines)" \
      "$( ((${SCOPE_PORTS_DEFAULTED:-1})) && echo true || echo false )" "$(json_num "$SCOPE_OOS_COUNT")" \
      "$(json_str "$( ((INSECURE_TLS)) && echo 'DISABLED (diagnostic override)' || echo enabled )")" "$(json_str "${CA_CERT:-}")"
    printf '"target_info":{"http_available":%s,"https_available":%s,"server_header":%s,"page_title":%s},\n' \
      "$( ((HTTP_OK)) && echo true || echo false )" "$( ((HTTPS_OK)) && echo true || echo false )" "$(json_str "${SERVER_HDR:-}")" "$(json_str "${PAGE_TITLE:-}")"
    printf '"summary":{"total":%s,"by_severity":{' "$TOTAL"
    first=1; for s in "${SEVERITIES[@]}"; do (( first )) || printf ','; first=0; printf '%s:%s' "$(json_str "$s")" "${SEV_COUNT[$s]}"; done
    printf '},"by_classification":{'
    first=1; for st in "${STATUSES[@]}"; do (( first )) || printf ','; first=0; printf '%s:%s' "$(json_str "$st")" "${STATUS_COUNT[$st]}"; done
    printf '},"by_owasp_category":{'
    first=1; for k in "${!OWASP_COUNT[@]}"; do (( first )) || printf ','; first=0; printf '%s:%s' "$(json_str "$k")" "${OWASP_COUNT[$k]}"; done
    printf '},"overall_risk":%s,"cvss_scored_findings":%s,"duplicates_suppressed":%s},\n' "$(json_str "$OVERALL_RISK")" "$CVSS_SCORED" "$FIND_DUP"
    printf '"findings":['
    local id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn rating
    first=1
    while IFS=$'\037' read -r id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn; do
      (( first )) || printf ','
      first=0
      if [[ -n $cs ]]; then rating=$(cvss_rating "$cs"); else rating=""; fi
      printf '\n{"id":%s,"fingerprint":%s,"title":%s,"description":%s,"affected_url":%s,"severity":%s,' \
        "$(json_str "$id")" "$(json_str "$fp")" "$(json_str "$title")" "$(json_str "$(unesc "$desc")")" "$(json_str "$url")" "$(json_str "$sev")"
      printf '"cvss":{"score":%s,"version":%s,"vector":%s,"rating":%s,"justification":%s},' \
        "$(json_num "$cs")" "$( [[ -n $cs ]] && echo '"3.1"' || echo null )" "$(json_str "$cv")" "$(json_str "$rating")" "$(json_str "$cj")"
      printf '"owasp_category":%s,"confidence":%s,"classification":%s,"evidence":%s,"impact":%s,"remediation":%s,"module":%s,"tool":%s,"timestamp":%s,"false_positive_notes":%s,"category":%s}' \
        "$(json_str "$owasp")" "$(json_str "$conf")" "$(json_str "$status")" "$(json_str "$(unesc "$ev")")" "$(json_str "$(unesc "$impact")")" \
        "$(json_str "$rem")" "$(json_str "$module")" "$(json_str "$tool")" "$(json_str "$ts")" "$(json_str "$fpn")" "$(json_str "$cat")"
    done <"$FINAL_TSV"
    printf '\n],\n"technologies":%s,\n"open_ports":%s,\n' "$(report_technologies | json_array_lines)" "$(report_open_ports | json_array_lines)"
    printf '"modules":['
    first=1; local name mst dur detail
    while IFS=$'\t' read -r name mst dur detail; do
      [[ -n $name ]] || continue
      (( first )) || printf ','; first=0
      printf '{"name":%s,"status":%s,"duration_seconds":%s,"detail":%s}' "$(json_str "$name")" "$(json_str "$mst")" "$(json_num "$dur")" "$(json_str "$detail")"
    done <"$MODULES_TSV"
    printf '],\n"tool_executions":['
    first=1; local label cmd rc dur2 logf
    while IFS=$'\t' read -r label cmd rc dur2 logf; do
      [[ -n $label ]] || continue
      (( first )) || printf ','; first=0
      printf '{"tool":%s,"command":%s,"exit_code":%s,"duration_seconds":%s,"log":%s}' "$(json_str "$label")" "$(json_str "$cmd")" "$(json_num "$rc")" "$(json_num "$dur2")" "$(json_str "$logf")"
    done <"$TOOLS_TSV"
    printf '],\n"tool_versions":{'
    first=1; for k in "${!TOOL_VER[@]}"; do (( first )) || printf ','; first=0; printf '%s:%s' "$(json_str "$k")" "$(json_str "${TOOL_VER[$k]}")"; done
    printf '},\n"limitations":%s,\n' "$(report_limitations | json_array_lines)"
    printf '"integrity":{"algorithm":"SHA-256","manifest":"logs/evidence.sha256","note":"Raw artefacts are hashed before the reports are written; report files and the main log are hashed in logs/reports.sha256.","files":['
    first=1; local h p
    if [[ -s $LOG_DIR/evidence.sha256 ]]; then
      while read -r h p; do
        (( first )) || printf ','; first=0
        printf '{"path":%s,"sha256":%s}' "$(json_str "${p#\*}")" "$(json_str "$h")"
      done <"$LOG_DIR/evidence.sha256"
    fi
    printf ']}\n}\n'
  } >"$J"
}

generate_csv_report() {
  local C="$OUTDIR/findings.csv"
  local id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn
  {
    printf 'id,severity,cvss_score,cvss_version,cvss_vector,owasp_category,title,affected_url,classification,confidence,module,tool,timestamp,impact,remediation\r\n'
    while IFS=$'\037' read -r id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn; do
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\r\n' \
        "$(csv_field "$id")" "$(csv_field "$sev")" "$(csv_field "$cs")" "$(csv_field "$( [[ -n $cs ]] && echo 3.1 )")" "$(csv_field "$cv")" \
        "$(csv_field "$owasp")" "$(csv_field "$title")" "$(csv_field "$url")" "$(csv_field "$status")" "$(csv_field "$conf")" \
        "$(csv_field "$module")" "$(csv_field "$tool")" "$(csv_field "$ts")" "$(csv_field "$impact")" "$(csv_field "$rem")"
    done <"$FINAL_TSV"
  } >"$C"
}
