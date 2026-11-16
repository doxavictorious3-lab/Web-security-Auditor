# shellcheck shell=bash
# DOXA module: nuclei - template-based detection. Intrusive, DoS, fuzzing, brute-force and
# default-login templates are excluded unless explicitly approved.
shopt -u patsub_replacement 2>/dev/null || true

nuclei_ingest() { # jsonl-file -> adds findings
  local name url cat sev status desc ev conf rem n=0
  while IFS=$'\037' read -r name url cat sev status desc ev conf rem; do
    [[ -n $name ]] || continue
    add_finding "Nuclei: $name" "$url" "$cat" "$sev" "$status" "$desc" "$ev" "nuclei" "$conf" "$rem" \
      "Template-based match. Version-based CVE detections can be false positives when vendors back-port patches. Verify manually."
    n=$((n + 1))
  done < <(jq -r '
    def sev: ((.info.severity // "info") | ascii_upcase | if . == "INFO" or . == "UNKNOWN" then "INFORMATIONAL" else . end);
    (.info.tags // []) as $t | (if ($t|type)=="array" then ($t|join(",")) else ($t|tostring) end) as $tags | sev as $s
    | [ (.info.name // .["template-id"] // "unnamed"),
        (.["matched-at"] // .host // ""),
        (if ($tags|test("exposure|config")) then "Sensitive file exposure"
         elif ($tags|test("cve")) then "Known vulnerable software"
         elif ($tags|test("xss|sqli|lfi|ssrf|traversal")) then "Injection indicators"
         elif ($tags|test("misconfig")) then "Security misconfiguration"
         elif ($tags|test("tech")) then "Technology fingerprinting" else "Scanner observation" end),
        $s,
        (if $s == "INFORMATIONAL" then "Informational observation" elif ($tags|test("exposure")) then "Confirmed vulnerability" else "Potential vulnerability" end),
        ((.info.description // "Detected by Nuclei template.") | tostring),
        ("Template: " + (.["template-id"] // "n/a") + " | Matched at: " + (.["matched-at"] // "n/a")
          + (if .["matcher-name"] then " | Matcher: " + .["matcher-name"] else "" end)
          + (if ((.["extracted-results"] // []) | length) > 0 then " | Extracted: " + (.["extracted-results"] | join(", ")) else "" end)),
        (if ($tags|test("exposure")) then "High" else "Medium" end),
        ((.info.remediation // "Review the template advisory and apply vendor patches or configuration hardening.") | tostring) ]
    | map(tostring | gsub("[\r\n\t\u001f]";" ")) | join("\u001f")' "$1" 2>>"$LOG_DIR/nuclei.parse.err")
  NUCLEI_ITEMS=$((${NUCLEI_ITEMS:-0} + n))
}

# nuclei_json_flag: -jsonl on current nuclei, -json on old releases. The help text is captured first;
# "nuclei -h | grep -q" would be killed by SIGPIPE and fail under "set -o pipefail" (v2.0.0 bug).
nuclei_json_flag() {
  local h
  h=$(nuclei -h 2>&1 </dev/null)
  if [[ $h == *-jsonl* ]]; then printf '%s' "-jsonl"; else printf '%s' "-json"; fi
}

run_nuclei() {
  local out="$OUTDIR/nuclei/nuclei.jsonl" rc=0 jflag="-jsonl"
  NUCLEI_ITEMS=0
  scope_assert_url "$SCAN_URL/" || return 1
  have jq || { MODULE_DETAIL="jq is required to parse nuclei output"; return 1; }
  jflag=$(nuclei_json_flag)
  local etags="dos,intrusive,fuzz,dast,bruteforce,brute-force,destructive,default-login"
  local -a cmd=(nuclei -u "$SCAN_URL" -silent -nc -duc -timeout 10 -retries 1 -rl "$RATE" -c "$THREADS" "$jflag" -o "$out" -etags "$etags")
  (( ${USE_OAST:-0} )) || cmd+=(-ni)
  [[ $MODE == standard ]] && cmd+=(-tags "tech,exposure,misconfig,cve,cms,xss,sqli,lfi,traversal,ssrf,takeover,wordpress,joomla,drupal")
  run_tool nuclei "$TOOL_TIMEOUT" "$LOG_DIR/nuclei.log" "${cmd[@]}" || rc=$?
  [[ -s $out ]] && nuclei_ingest "$out"
  if (( rc != 0 )) && [[ ! -s $out ]]; then
    MODULE_DETAIL="nuclei exit $rc, no results: $(tail -n 3 "$LOG_DIR/nuclei.log" 2>/dev/null | tr '\n\t' '  ' | cut -c1-220) (templates installed? run: nuclei -update-templates)"
    return "$rc"
  fi
  if [[ $MODE == full ]]; then
    local out2="$OUTDIR/nuclei/nuclei_default_login.jsonl"
    if require_approval "Nuclei default-login templates (attempts logins with vendor default credentials against detected products)"; then
      local -a c2=(nuclei -u "$SCAN_URL" -silent -nc -duc -timeout 10 -retries 1 -rl "$RATE" -c "$THREADS" "$jflag" -o "$out2" -tags default-login -ni)
      run_tool nuclei-default-login "$TOOL_TIMEOUT" "$LOG_DIR/nuclei_default_login.log" "${c2[@]}" || true
      [[ -s $out2 ]] && nuclei_ingest "$out2"
    else
      LIMITS+=("Nuclei default-login checks were not run (manual approval not granted).")
    fi
  fi
  (( ${USE_OAST:-0} )) || LIMITS+=("Nuclei out-of-band (OAST) templates were disabled; blind SSRF/injection checks that need a callback server were not run (use --oast to enable).")
  MODULE_DETAIL="${NUCLEI_ITEMS:-0} nuclei finding(s)"
  return "$rc"
}
