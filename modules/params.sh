# shellcheck shell=bash
# DOXA module: params (ported from v1.0.0, hardened for v2.0)
shopt -u patsub_replacement 2>/dev/null || true

run_params() {
  if ! require_approval "Active parameter probing: sends harmless marker strings and a single quote to up to 15 same-host URLs that have query parameters (no data is modified)"; then
    MODULE_STATUS=SKIPPED; MODULE_DETAIL="manual approval not granted (use --allow-dangerous)"
    LIMITS+=("Parameter probing (reflection / SQL-error indicators) was not run (manual approval not granted).")
    return 0
  fi
  local links l url base q i j key canary payload newq body_base nurl found=0 tested=0
  local sqlerr='You have an error in your SQL syntax|mysql_fetch|mysqli_|Warning: mysql|ORA-[0-9]{5}|SQLSTATE\[|PostgreSQL.*ERROR|PG::SyntaxError|SQLite3?::|SQLITE_ERROR|Unclosed quotation mark|ODBC SQL Server Driver|System\.Data\.SqlClient|syntax error at or near'
  links=$(tr "'" '"' <"$ROOT_BODY" | grep -aoiE 'href="[^"#]*\?[^"#]*"' | sed -E 's/^href="//I; s/"$//; s/&amp;/\&/g' | sort -u | head -40)
  local -a urls=()
  while IFS= read -r l; do
    [[ -n $l ]] || continue
    case $l in
      http://*|https://*) [[ $l == "$SCAN_BASE"/* ]] || continue; url=$l ;;
      //*) continue ;;
      /*) url="$SCAN_BASE$l" ;;
      *) url="$SCAN_BASE/${l#./}" ;;
    esac
    urls+=("$url"); (( ${#urls[@]} >= 15 )) && break
  done <<<"$links"
  if (( ${#urls[@]} == 0 )); then MODULE_DETAIL="no same-host links with query parameters on the home page"; return 0; fi
  local -a kv
  for url in "${urls[@]}"; do
    base=${url%%\?*}; q=${url#*\?}
    IFS='&' read -ra kv <<<"$q"
    http_fetch "$url" pbase; body_base="$TMPD/pbase.keep"; cp "$FETCH_BODY" "$body_base"
    for i in "${!kv[@]}"; do
      key=${kv[i]%%=*}; [[ -n $key ]] || continue
      tested=$((tested + 1))
      canary="doxa${RANDOM}x"; payload="${canary}%22%27%3Cdx%3E"
      newq=""; for j in "${!kv[@]}"; do
        if (( j == i )); then newq+="${key}=${payload}&"; else newq+="${kv[j]}&"; fi
      done
      nurl="$base?${newq%&}"
      http_fetch "$nurl" pxss
      if grep -qaF "${canary}\"'<dx>" "$FETCH_BODY"; then
        found=$((found + 1))
        add_finding "Reflected input without encoding (possible XSS) in parameter '$key'" "$base" "Cross-Site Scripting indicators" MEDIUM "Potential vulnerability" \
          "A marker containing quote and angle-bracket characters was reflected unencoded in the response. This indicates possible reflected XSS but no script was executed." \
          "Parameter: $key; marker reflected raw in HTTP $FETCH_CODE response" "doxa-params" Medium \
          "Contextually encode all untrusted output and add a restrictive Content-Security-Policy." \
          "Reflection may be inside a non-executable context (comment, text/plain). Confirm manually in a browser."
      fi
      newq=""; for j in "${!kv[@]}"; do
        if (( j == i )); then newq+="${key}=${kv[j]#*=}%27&"; else newq+="${kv[j]}&"; fi
      done
      nurl="$base?${newq%&}"
      http_fetch "$nurl" psql
      if grep -qaE "$sqlerr" "$FETCH_BODY" && ! grep -qaE "$sqlerr" "$body_base"; then
        found=$((found + 1))
        add_finding "Database error message triggered by input (possible SQL injection) in parameter '$key'" "$base" "SQL injection indicators" HIGH "Potential vulnerability" \
          "Adding a single quote to the parameter produced a database error signature that was absent from the normal response." \
          "Parameter: $key; matched: $(grep -aoE "$sqlerr" "$FETCH_BODY" | head -1)" "doxa-params" Medium \
          "Use parameterised queries/prepared statements and suppress verbose database errors." \
          "Error text may come from input-validation layers. DOXA did not attempt exploitation; verify manually in a controlled setting."
      fi
    done
  done
  MODULE_DETAIL="$tested parameter(s) probed across ${#urls[@]} URL(s), $found indicator(s)"
  LIMITS+=("Parameter probing covered only links found on the home page; path traversal, LFI and SSRF were not actively probed (only Nuclei templates and passive indicators).")
  return 0
}
