# shellcheck shell=bash
# DOXA module: js - JavaScript security analysis (passive: fetches only scripts the page itself loads).
#
#  * discovers in-scope script files from the analysed page (cross-origin scripts are listed, never fetched)
#  * extracts API endpoints and interesting routes (feeds the api module via logs/js_endpoints.txt)
#  * flags potentially exposed secrets and tokens - VALUES ARE NEVER STORED OR PRINTED
#    (evidence is type, location, length and a short hash only)
#  * flags insecure http:// references, missing Subresource Integrity and exposed source maps
#  * flags dangerous patterns (eval, innerHTML, ...) for MANUAL verification, skipping known library bundles
shopt -u patsub_replacement 2>/dev/null || true

JS_MAX_FILES=25
JS_LIB_RE='(^|/)(jquery|react|react-dom|angular|vue|bootstrap|lodash|underscore|moment|polyfills?|vendor|runtime|core-js|zone|d3|three|axios|popper|chart)[A-Za-z0-9._-]*\.js$'
JS_SOURCES_RE='location\.(hash|search|href)|document\.(URL|referrer|location)|window\.name'

JS_SECRET_NAMES=("AWS access key ID" "Google API key" "GitHub token" "Slack token" "Stripe live secret key" "Private key block" "JSON Web Token" "Hard-coded credential assignment")
JS_SECRET_RE=(
  'AKIA[0-9A-Z]{16}'
  'AIza[0-9A-Za-z_-]{35}'
  'gh[pousr]_[A-Za-z0-9]{36,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
  'sk_live_[0-9A-Za-z]{16,}'
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  "(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|passwd|password)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"'[:space:]]{8,}[\"']"
)
JS_SECRET_SEV=(HIGH LOW HIGH HIGH HIGH HIGH LOW MEDIUM)
JS_SECRET_CONF=(Medium Medium High Medium High High Low Low)

JS_DANGER_NAMES=("eval()" "new Function()" "document.write()" "innerHTML/outerHTML assignment" "insertAdjacentHTML()" "dangerouslySetInnerHTML" "setTimeout/setInterval with a string")
JS_DANGER_RE=(
  '[^A-Za-z0-9_.]eval[[:space:]]*\('
  'new[[:space:]]+Function[[:space:]]*\('
  'document\.write(ln)?[[:space:]]*\('
  '\.(inner|outer)HTML[[:space:]]*=[^=]'
  'insertAdjacentHTML[[:space:]]*\('
  'dangerouslySetInnerHTML'
  'set(Timeout|Interval)[[:space:]]*\([[:space:]]*["'"'"']'
)

# js_resolve BASE HREF -> absolute URL (or non-zero for javascript:/data: etc.)
js_resolve() {
  local base=$1 href=$2 origin q="" dir path
  href=${href%%#*}
  [[ -n $href ]] || return 1
  case $href in
    http://*|https://*) printf '%s' "$href"; return 0 ;;
    //*) printf '%s:%s' "${base%%:*}" "$href"; return 0 ;;
    javascript:*|data:*|mailto:*|blob:*|about:*) return 1 ;;
  esac
  parse_url_generic "$base" || return 1
  origin="$P_SCHEME://$P_AUTHORITY"
  if [[ $href == *\?* ]]; then q="?${href#*\?}"; href=${href%%\?*}; fi
  if [[ $href == /* ]]; then path=$href; else dir=${P_PATH%/*}; path="$dir/$href"; fi
  path=$(printf '%s' "$path" | awk '{ n=split($0,a,"/"); m=0
      for (i=1;i<=n;i++) { if (a[i]=="."||a[i]=="") continue; if (a[i]=="..") { if (m>0) m--; continue } s[++m]=a[i] }
      out=""; for (i=1;i<=m;i++) out=out "/" s[i]; if (out=="") out="/"; print out }')
  printf '%s%s%s' "$origin" "$path" "$q"
}

# js_extract_scripts HTML-FILE -> "src<TAB>has_integrity" lines
js_extract_scripts() {
  local tag src integ
  while IFS= read -r tag; do
    src=$(sed -nE 's/.*[[:space:]]src[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/Ip' <<<"$tag")
    [[ -n $src ]] || continue
    integ=0; grep -qiE '[[:space:]]integrity[[:space:]]*=' <<<"$tag" && integ=1
    printf '%s\t%s\n' "$src" "$integ"
  done < <(tr "'" '"' <"$1" | tr '\n\r\t' '   ' | grep -aoiE '<script[^>]*>')
}

# js_scan_secrets FILE LABEL URL
js_scan_secrets() {
  local file=$1 label=$2 url=$3 i line off v len h evidence n seen
  for i in "${!JS_SECRET_NAMES[@]}"; do
    evidence=""; n=0; seen=" "
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      off=${line%%:*}; v=${line#*:}
      if [[ ${JS_SECRET_NAMES[$i]} == "Hard-coded credential assignment" ]] && grep -qiE 'example|your|xxxx|changeme|placeholder|dummy|sample|test|\*\*\*|<|\$\{|process\.env' <<<"$v"; then continue; fi
      h=$(printf '%s' "$v" | sha256sum | cut -c1-8)
      [[ $seen == *" $h "* ]] && continue
      seen+="$h "; n=$((n + 1)); len=${#v}
      evidence+="${JS_SECRET_NAMES[$i]} at byte offset $off in $label: ${len} characters, sha256 prefix $h (value redacted)"$'\n'
      v=""
    done < <(grep -aboE "${JS_SECRET_RE[$i]}" "$file" 2>/dev/null | head -10)
    (( n > 0 )) || continue
    add_finding "Possible ${JS_SECRET_NAMES[$i]} in client-side code ($label)" "$url" "JavaScript secrets" "${JS_SECRET_SEV[$i]}" "Potential vulnerability" \
      "$n value(s) matching the pattern for ${JS_SECRET_NAMES[$i]} are present in JavaScript delivered to every visitor. DOXA did not use or validate the value." \
      "$evidence" "doxa-js" "${JS_SECRET_CONF[$i]}" \
      "Remove secrets from client-side code, rotate any value that was real, and keep credentials on the server side. For public client keys, restrict them (referrer, scope, quota)." \
      "Placeholders, public client-side identifiers (analytics or maps keys) and test fixtures often match these patterns. Verify manually whether the value is live and what it protects."
  done
}

# js_scan_endpoints FILE -> appends API endpoints to logs/js_endpoints.txt
js_scan_endpoints() {
  local file=$1 q=$'"\'`' host_re=${HOST//./\\.}
  {
    grep -aoE "[$q](/(api|rest|v[0-9]+|graphql|gql|auth|oauth|admin|user|users|account|accounts|login|logout|register|token|ws|socket\.io|internal|private|upload|download|search|config|health|status|metrics)[A-Za-z0-9_./{}:@%?=&-]*)[$q]" "$file" 2>/dev/null | sed -E 's/^.//; s/.$//'
    grep -aoE "(fetch|get|post|put|delete|patch|open|request)\([^)]{0,60}[$q](/[A-Za-z0-9_./{}:@%?=&-]+)[$q]" "$file" 2>/dev/null | sed -E "s/.*[$q](\/[^$q]*)[$q]\$/\1/"
    grep -aoE "https?://${host_re}(:[0-9]+)?/[A-Za-z0-9_./{}:@%?=&-]*" "$file" 2>/dev/null | sed -E 's#^https?://[^/]+##'
  } | grep -vE '\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|html?)(\?|$)' | grep -E '^/.{2,}' >>"$LOG_DIR/js_endpoints.txt"
}

# js_scan_patterns FILE LABEL URL IS_LIB
js_scan_patterns() {
  local file=$1 label=$2 url=$3 is_lib=$4 i c offs evidence="" total=0 srcs
  (( is_lib )) && return 0
  for i in "${!JS_DANGER_NAMES[@]}"; do
    c=$(grep -aoE "${JS_DANGER_RE[$i]}" "$file" 2>/dev/null | wc -l | tr -d ' ')
    (( c > 0 )) || continue
    total=$((total + c))
    offs=$(grep -aboE "${JS_DANGER_RE[$i]}" "$file" 2>/dev/null | head -3 | cut -d: -f1 | tr '\n' ' ')
    evidence+="${JS_DANGER_NAMES[$i]}: ${c} occurrence(s), first byte offsets: ${offs}"$'\n'
  done
  (( total > 0 )) || return 0
  srcs=$(grep -aoE "$JS_SOURCES_RE" "$file" 2>/dev/null | sort -u | head -5 | tr '\n' ' ')
  if [[ -n $srcs ]]; then
    add_finding "Potential DOM-based XSS pattern: user-controllable sources and unsafe sinks ($label)" "$url" "JavaScript dangerous patterns" MEDIUM "Potential vulnerability" \
      "The script reads user-controllable values (${srcs}) and also uses unsafe DOM or code-evaluation sinks. DOXA did not trace the data flow, so this is an indicator only." \
      "${evidence}Sources present: ${srcs}" "doxa-js" Low \
      "Review the flagged locations. Avoid innerHTML/document.write/eval with untrusted data; use textContent or a sanitiser and add a Content-Security-Policy." \
      "Sources and sinks in one file are often unrelated. Confirm that attacker-controlled data actually reaches the sink."
  else
    add_finding "Potentially dangerous JavaScript patterns ($label)" "$url" "JavaScript dangerous patterns" LOW "Potential vulnerability" \
      "The script uses unsafe DOM or code-evaluation constructs. These are only risky when untrusted data reaches them." \
      "$evidence" "doxa-js" Low \
      "Review the flagged locations and prefer safe APIs (textContent, DOM construction, sanitisation)." \
      "Frameworks and bundled libraries use these constructs legitimately. Manual verification is required."
  fi
}

# js_scan_http_refs FILE LABEL URL
js_scan_http_refs() {
  local file=$1 label=$2 url=$3 hosts
  hosts=$(grep -aoE 'http://[A-Za-z0-9.-]+' "$file" 2>/dev/null | sed 's#http://##' | sort -u \
          | grep -vEi '^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.)|(^|\.)(w3\.org|xmlns\.com|schema\.org|ietf\.org|apache\.org|sun\.com)$' | head -15)
  [[ -n $hosts ]] || return 0
  if [[ $SCAN_BASE == https://* ]]; then
    add_finding "Insecure http:// references in JavaScript ($label)" "$url" "Mixed content" MEDIUM "Potential vulnerability" \
      "The script references resources over plain HTTP. If they are loaded at run time on this HTTPS site, browsers may block them or expose users to tampering." \
      "Hosts referenced over http://: $(tr '\n' ' ' <<<"$hosts")" "doxa-js" Medium \
      "Use https:// for all resources and add a Content-Security-Policy with upgrade-insecure-requests." \
      "Some references are namespace identifiers or links that are never fetched."
  else
    add_finding "http:// references in JavaScript ($label)" "$url" "Mixed content" INFORMATIONAL "Informational observation" \
      "The script references resources over plain HTTP. The site itself is served over HTTP, so this is recorded for context." \
      "Hosts referenced over http://: $(tr '\n' ' ' <<<"$hosts")" "doxa-js" Medium "Serve the site and all resources over HTTPS." ""
  fi
}

# js_check_sourcemap FILE URL: only when the file itself announces a source map
js_check_sourcemap() {
  local file=$1 url=$2 ref abs
  ref=$(tail -c 400 "$file" 2>/dev/null | grep -aoE 'sourceMappingURL=[^[:space:]*]+' | tail -1 | sed 's/sourceMappingURL=//')
  [[ -n $ref && $ref != data:* ]] || return 0
  abs=$(js_resolve "$url" "$ref") || return 0
  http_fetch "$abs" jsmap -r 0-255
  case $FETCH_CODE in 200|206) ;; *) return 0 ;; esac
  grep -aq '"version"' "$FETCH_BODY" && grep -aqE '^[[:space:]]*\{' "$FETCH_BODY" || return 0
  add_finding "JavaScript source map publicly accessible" "$abs" "Information disclosure" LOW "Confirmed vulnerability" \
    "A source map is downloadable, allowing the original (unminified) application source to be reconstructed." \
    "GET ${abs#"$SCAN_BASE"} -> HTTP $FETCH_CODE; JSON source map header present" "curl" High \
    "Do not deploy source maps to production, or restrict them to authenticated developers." \
    "Intentional for open-source front ends." "" "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" \
    "Source map readable without authentication; the sensitivity of the embedded source was not assessed, so confidentiality impact is scored Low."
}

run_js() {
  local base=${ROOT_URL:-$SCAN_BASE/} src integ abs n_scan=0 n_ext=0 label is_lib size
  local -a ext_hosts=() ext_nosri=() ext_http=()
  : >"$LOG_DIR/js_endpoints.txt"; : >"$LOG_DIR/js_files.txt"
  # inline scripts and the page itself
  js_scan_secrets "$ROOT_BODY" "inline/page" "$base"
  js_scan_endpoints "$ROOT_BODY"
  local scripts; scripts=$(js_extract_scripts "$ROOT_BODY")
  if [[ -z $scripts ]]; then
    sort -u "$LOG_DIR/js_endpoints.txt" -o "$LOG_DIR/js_endpoints.txt"
    MODULE_DETAIL="no external script references on the analysed page (inline content was scanned)"
    return 0
  fi
  while IFS=$'\t' read -r src integ; do
    abs=$(js_resolve "$base" "$src") || continue
    if ! scope_check_url "$abs"; then
      n_ext=$((n_ext + 1)); parse_url_generic "$abs" && ext_hosts+=("$P_HOST")
      (( integ )) || ext_nosri+=("${abs%%\?*}")
      [[ $abs == http://* && $SCAN_BASE == https://* ]] && ext_http+=("${abs%%\?*}")
      continue
    fi
    if [[ $abs == http://* && $SCAN_BASE == https://* ]]; then ext_http+=("${abs%%\?*}"); fi
    (( n_scan >= JS_MAX_FILES )) && { LIMITS+=("JavaScript analysis stopped at $JS_MAX_FILES files."); break; }
    http_fetch "$abs" jsfile
    [[ $FETCH_CODE == 200 && -s $FETCH_BODY ]] || continue
    n_scan=$((n_scan + 1)); label=${abs##*/}; label=${label%%\?*}; [[ -n $label ]] || label=$abs
    size=$(wc -c <"$FETCH_BODY" | tr -d ' ')
    is_lib=0; [[ ${abs%%\?*} =~ $JS_LIB_RE ]] && is_lib=1
    printf '%s\t%s\t%s bytes%s\n' "$abs" "HTTP 200" "$size" "$( ((is_lib)) && echo ', library bundle (pattern checks skipped)' )" >>"$LOG_DIR/js_files.txt"
    js_scan_secrets "$FETCH_BODY" "$label" "$abs"
    js_scan_endpoints "$FETCH_BODY"
    js_scan_patterns "$FETCH_BODY" "$label" "$abs" "$is_lib"
    js_scan_http_refs "$FETCH_BODY" "$label" "$abs"
    js_check_sourcemap "$FETCH_BODY" "$abs"
  done <<<"$scripts"
  sort -u "$LOG_DIR/js_endpoints.txt" | head -300 >"$TMPD/ep.sorted"; cp "$TMPD/ep.sorted" "$LOG_DIR/js_endpoints.txt"
  local n_ep; n_ep=$(wc -l <"$LOG_DIR/js_endpoints.txt" | tr -d ' ')
  if (( n_ep > 0 )); then
    add_finding "API endpoints and routes referenced in JavaScript ($n_ep)" "$base" "JavaScript security" INFORMATIONAL "Informational observation" \
      "Client-side code references $n_ep endpoint or route string(s). They widen the known attack surface and are used by the api module." \
      "$(head -40 "$LOG_DIR/js_endpoints.txt")" "doxa-js" Medium "Ensure every referenced endpoint enforces authentication and authorization on the server side." \
      "Strings may be dead code, examples or paths that do not exist."
  fi
  if (( ${#ext_http[@]} )); then
    add_finding "Script loaded over insecure HTTP on an HTTPS page" "$base" "Mixed content" MEDIUM "Confirmed vulnerability" \
      "The page loads script over plain HTTP, which a network attacker can modify (active mixed content)." \
      "$(printf '%s\n' "${ext_http[@]}" | sort -u | head -10)" "doxa-js" High "Load all scripts over HTTPS." ""
  fi
  if (( ${#ext_nosri[@]} )); then
    add_finding "Third-party scripts loaded without Subresource Integrity" "$base" "JavaScript integrity" LOW "Confirmed vulnerability" \
      "Cross-origin script tags have no integrity attribute, so a compromised host could change the code your visitors run." \
      "$(printf '%s\n' "${ext_nosri[@]}" | sort -u | head -15)" "doxa-js" High \
      "Add integrity and crossorigin attributes to third-party script tags, or self-host the files." \
      "SRI is impractical for scripts that legitimately change often (tag managers)."
  fi
  if (( n_ext > 0 )); then
    add_finding "Third-party script hosts referenced (not analysed: outside approved scope)" "$base" "JavaScript security" INFORMATIONAL "Informational observation" \
      "$n_ext script reference(s) point to other origins. DOXA did not request them because they are outside the approved scope." \
      "$(printf '%s\n' "${ext_hosts[@]}" | sort -u | head -15)" "doxa-js" High \
      "Inventory third-party scripts and review them separately (add --scope-host only with authorization)." ""
    LIMITS+=("Third-party JavaScript ($n_ext reference(s)) was not fetched or analysed because it is outside the approved scope.")
  fi
  MODULE_DETAIL="$n_scan script file(s) analysed, $n_ext external not fetched, $n_ep endpoint string(s)"
  return 0
}
