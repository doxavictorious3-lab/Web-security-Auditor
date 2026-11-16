# shellcheck shell=bash
# DOXA module: nikto - web server checks with non-intrusive tuning only.
# Tuning excludes DoS (6), command execution (8), SQL injection (9), file upload (0) and remote inclusion (c).
shopt -u patsub_replacement 2>/dev/null || true

# nikto_classify MSG -> N_SEV N_STATUS N_CONF N_CAT
nikto_classify() {
  local m=$1
  if   grep -qiE 'remote code execution|command execution|sql injection|shellshock' <<<"$m"; then N_SEV=HIGH; N_STATUS="Potential vulnerability"; N_CONF=Low; N_CAT="Injection / code execution"
  elif grep -qiE 'CVE-|OSVDB-|appears to be outdated|vulnerable|end of life' <<<"$m"; then N_SEV=MEDIUM; N_STATUS="Potential vulnerability"; N_CONF=Low; N_CAT="Known vulnerable software"
  elif grep -qiE 'directory index|directory listing|index of /' <<<"$m"; then N_SEV=MEDIUM; N_STATUS="Potential vulnerability"; N_CONF=Medium; N_CAT="Information disclosure"
  elif grep -qiE 'backup|\.bak|\.old|\.sql|\.git|\.env|password|credential|phpinfo|htpasswd|dump' <<<"$m"; then N_SEV=MEDIUM; N_STATUS="Potential vulnerability"; N_CONF=Low; N_CAT="Sensitive file exposure"
  elif grep -qiE 'xss|cross.site|traversal|inclusion' <<<"$m"; then N_SEV=MEDIUM; N_STATUS="Potential vulnerability"; N_CONF=Low; N_CAT="Injection indicators"
  elif grep -qiE 'Allowed HTTP Methods|TRACE|WebDAV' <<<"$m"; then N_SEV=LOW; N_STATUS="Potential vulnerability"; N_CONF=Low; N_CAT="Security misconfiguration"
  elif grep -qiE 'Server:|banner|x-powered-by|ETag|inode|retrieved' <<<"$m"; then N_SEV=INFORMATIONAL; N_STATUS="Informational observation"; N_CONF=Medium; N_CAT="Information disclosure"
  else N_SEV=INFORMATIONAL; N_STATUS="False positive or unverified result"; N_CONF=Low; N_CAT="Scanner observation"; fi
}

nikto_ingest() { # json-file
  local id method path msg n=0
  while IFS=$'\037' read -r id method path msg; do
    [[ -n $msg ]] || continue
    # header checks are covered (with better evidence) by the http module
    grep -qiE 'X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy|Referrer-Policy|X-XSS-Protection|Permissions-Policy|anti-clickjacking' <<<"$msg" && continue
    if grep -qiE 'directory index' <<<"$msg" && finding_exists "Directory listing enabled" "$SCAN_BASE$path" "Information disclosure"; then
      log DEDUP "nikto directory-indexing item already confirmed by the http/gobuster modules: $path"; continue
    fi
    nikto_classify "$msg"
    add_finding "Nikto: ${msg:0:90}" "$SCAN_BASE$path" "$N_CAT" "$N_SEV" "$N_STATUS" "$msg" \
      "Nikto id $id, method $method: $msg" "nikto" "$N_CONF" \
      "Manually verify the Nikto observation; remove or restrict the exposed resource, patch the affected software or harden the server configuration." \
      "Nikto is signature based and frequently reports items that are not exploitable. Verify manually before treating as a vulnerability."
    n=$((n + 1))
  done < <(jq -r '[.. | objects | select(has("msg") and has("url"))] | unique_by([.msg,.url]) | .[:100][]
      | [(.id // "n/a"|tostring), (.method // "GET"|tostring), (.url|tostring), (.msg|tostring)]
      | map(gsub("[\r\n\t\u001f]";" ")) | join("\u001f")' "$1" 2>>"$LOG_DIR/nikto.parse.err")
  NIKTO_ITEMS=$n
}

run_nikto() {
  local json="$OUTDIR/nikto/nikto.json" txt="$OUTDIR/nikto/nikto.txt" tuning maxt rc=0
  NIKTO_ITEMS=0
  scope_assert_url "$SCAN_URL/" || return 1
  if [[ $MODE == full ]]; then tuning="12345abe"; maxt=1200; else tuning="1234b"; maxt=600; fi
  (( maxt > TOOL_TIMEOUT )) && maxt=$TOOL_TIMEOUT
  local -a cmd=(nikto -h "$SCAN_URL" -ask no -nointeractive -maxtime "${maxt}s" -timeout 10 -Tuning "$tuning" -Format json -output "$json")
  (( RATE <= 2 )) && cmd+=(-Pause 1)
  run_tool nikto $((maxt + 60)) "$txt" "${cmd[@]}" || rc=$?
  if [[ -s $json ]] && have jq && jq -e . "$json" >/dev/null 2>&1; then
    nikto_ingest "$json"
  elif [[ -s $txt ]]; then
    NIKTO_ITEMS=$(grep -c '^+ ' "$txt" 2>/dev/null)
    add_finding "Nikto raw output only (JSON unavailable)" "$SCAN_URL" "Scanner observation" INFORMATIONAL "False positive or unverified result" \
      "Nikto did not produce parsable JSON (or jq is missing); raw output is saved in nikto/nikto.txt." "$(grep '^+ ' "$txt" | head -20)" "nikto" Low \
      "Review nikto/nikto.txt manually." "Unparsed output."
  else
    MODULE_DETAIL="no nikto output (exit $rc); see nikto/nikto.txt"
    return "${rc/#0/1}"
  fi
  LIMITS+=("Nikto manages its own TLS handling; DOXA cannot enforce certificate validation inside Nikto, Nuclei or WhatWeb.")
  MODULE_DETAIL="${NIKTO_ITEMS:-0} nikto item(s)"
  return 0
}
