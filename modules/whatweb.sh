# shellcheck shell=bash
# DOXA module: whatweb - technology fingerprinting (passive-friendly, stays on the in-scope origin)
shopt -u patsub_replacement 2>/dev/null || true

run_whatweb() {
  local json="$OUTDIR/logs/whatweb.json" agg=1 rc=0 techs
  [[ $MODE == full ]] && agg=3
  scope_assert_url "$SCAN_URL/" || return 1
  # --max-redirects=0: never follow redirects to hosts outside the approved scope.
  run_tool whatweb "$TOOL_TIMEOUT" "$LOG_DIR/whatweb.log" whatweb -a "$agg" --max-redirects=0 --color=never --user-agent "$UA" --log-json="$json" "$SCAN_URL" || rc=$?
  if [[ ! -s $json ]]; then MODULE_DETAIL="no whatweb output (exit $rc)"; return "${rc/#0/1}"; fi
  if ! have jq; then MODULE_DETAIL="jq is required to parse whatweb output"; return 1; fi
  techs=$(jq -r '(if type=="array" then .[] else . end) | objects | select(.plugins) | .plugins | to_entries[]
      | .key + ((.value.version // .value.string // []) | if length>0 then "[" + (map(tostring)|join(",")) + "]" else "" end)' "$json" 2>/dev/null | sort -u)
  if [[ -z $techs ]]; then MODULE_DETAIL="whatweb output could not be parsed"; return 1; fi
  printf '%s\n' "$techs" >>"$TECH_FILE"
  add_finding "Detected web technologies" "$SCAN_URL" "Technology fingerprinting" INFORMATIONAL "Informational observation" \
    "WhatWeb fingerprinted the following technologies (aggression level $agg)." "$techs" "whatweb" Medium \
    "Reduce unnecessary technology disclosure (version banners, generator tags) and keep all components patched." \
    "Fingerprinting is heuristic; versions may be inaccurate or masked."
  local jq_ver php_ver
  jq_ver=$(jq -r '[(if type=="array" then .[] else . end) | objects | .plugins.JQuery.version[0]?] | map(select(.!=null))[0] // empty' "$json" 2>/dev/null)
  if [[ -n $jq_ver ]] && ver_lt "$jq_ver" "3.5.0"; then
    add_finding "Outdated jQuery detected ($jq_ver)" "$SCAN_URL" "Known vulnerable software" LOW "Potential vulnerability" \
      "jQuery versions before 3.5.0 have known XSS issues in HTML parsing (CVE-2020-11022, CVE-2020-11023)." "jQuery version: $jq_ver" "whatweb" Medium \
      "Upgrade jQuery to the latest 3.x release." "Exploitability depends on how the application passes untrusted HTML to jQuery."
  fi
  php_ver=$(grep -oiE 'PHP/[0-9]+\.[0-9]+(\.[0-9]+)?' "$TECH_FILE" 2>/dev/null | head -1 | sed 's/.*PHP\///I')
  if [[ -n $php_ver ]] && ver_lt "$php_ver" "8.1"; then
    add_finding "End-of-life PHP version disclosed ($php_ver)" "$SCAN_URL" "Known vulnerable software" MEDIUM "Potential vulnerability" \
      "The advertised PHP version no longer receives security updates." "PHP version: $php_ver" "whatweb" Medium \
      "Upgrade to a supported PHP release and suppress version disclosure (expose_php=Off)." \
      "Distributions may back-port patches while keeping the old version string."
  fi
  MODULE_DETAIL="$(wc -l <<<"$techs" | tr -d ' ') technologies"
  return 0
}
