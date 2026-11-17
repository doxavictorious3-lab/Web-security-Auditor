# shellcheck shell=bash
# DOXA module: api - API discovery and non-destructive assessment. ACTIVE module (probes paths).
#
# Only GET requests without credentials are sent: nothing is created, changed or deleted, and no
# authentication is attempted. Object-level authorization (IDOR/BOLA) cannot be assessed without
# credentials and is listed as a limitation.
shopt -u patsub_replacement 2>/dev/null || true

API_MAX_PROBES=60
API_COMMON=(/api /api/ /api/v1 /api/v2 /rest /rest/ /graphql /swagger.json /swagger/v1/swagger.json /openapi.json /openapi.yaml
  /v2/api-docs /v3/api-docs /api-docs /swagger-ui.html /swagger-ui/ /redoc /api/docs /docs/api /.well-known/openid-configuration
  /api/health /health /status)
API_SENSITIVE_RE='(users?|admins?|accounts?|customers?|orders?|tokens?|keys?|secrets?|config|settings|debug|internal|backup|payments?|cards?)'
API_STACK_RE='(at [A-Za-z0-9_.<>$ -]+ \(?[^ )]+\.(js|ts|py|java|rb|php|go):[0-9]+)|Traceback \(most recent call|Exception in thread|java\.lang\.[A-Za-z]+Exception|node_modules/|System\.[A-Za-z]+Exception|<b>Fatal error</b>'

declare -A API_SEEN=()
API_OK=() API_PROT=() API_DOCS=()
API_LAST_CODE="" API_LAST_CTYPE="" API_LAST_SIZE=""

# api_is_json FILE CONTENT-TYPE
api_is_json() {
  [[ ${2,,} == *json* ]] && return 0
  grep -qE '^[[:space:]]*[\{\[]' < <(head -c 200 "$1")
}

# api_fields FILE -> top-level style field NAMES only (never values)
api_fields() {
  grep -aoE '"[A-Za-z0-9_]{1,40}"[[:space:]]*:' "$1" 2>/dev/null | tr -d ' ":' | sort -u | head -15 | tr '\n' ' '
}

# api_probe PATH [origin] -> records results; returns 0 when a response was obtained
api_probe() {
  local p=$1 ctype size code
  [[ -n ${API_SEEN[$p]:-} ]] && return 1
  (( ${#API_SEEN[@]} >= API_MAX_PROBES )) && return 1
  API_SEEN[$p]=1
  http_fetch "$SCAN_BASE$p" api
  code=$FETCH_CODE
  [[ $code == 000 ]] && return 1
  ctype=$(hget "$FETCH_HDR" content-type); size=$(wc -c <"$FETCH_BODY" | tr -d ' ')
  API_LAST_CODE=$code; API_LAST_CTYPE=$ctype; API_LAST_SIZE=$size
  case $code in
    200)
      if api_is_json "$FETCH_BODY" "$ctype"; then
        API_OK+=("$p"); printf '%s\t%s\t%s\t%s\n' "$code" "$p" "${ctype%%;*}" "$size" >>"$LOG_DIR/api_endpoints.txt"
        # documentation?
        if grep -qE '"(openapi|swagger)"[[:space:]]*:' "$FETCH_BODY" && grep -q '"paths"' "$FETCH_BODY"; then API_DOCS+=("$p"); api_handle_docs "$p"; fi
        return 0
      elif grep -qiE 'swagger-ui|redoc|<title>[^<]*(api|swagger)' "$FETCH_BODY"; then
        API_DOCS+=("$p"); api_doc_finding "$p" "interactive API documentation page"; return 0
      fi ;;
    401|403)
      API_PROT+=("$p"); printf '%s\t%s\t%s\t%s\n' "$code" "$p" "${ctype%%;*}" "$size" >>"$LOG_DIR/api_endpoints.txt"
      local wa; wa=$(hget "$FETCH_HDR" www-authenticate)
      if [[ ${wa,,} == basic* && $SCAN_BASE == http://* ]]; then
        add_finding "HTTP Basic authentication offered over unencrypted HTTP" "$SCAN_BASE$p" "API authentication" MEDIUM "Confirmed vulnerability" \
          "The endpoint challenges with HTTP Basic authentication on a cleartext HTTP connection, so credentials would be sent unencrypted." \
          "GET $p -> HTTP $code, WWW-Authenticate: ${wa%% *}" "curl" High \
          "Serve the API over HTTPS only and prefer token-based authentication." "Acceptable only on isolated lab networks."
      fi
      return 0 ;;
    405) printf '%s\t%s\t%s\t%s\n' "$code" "$p" "${ctype%%;*}" "$size" >>"$LOG_DIR/api_endpoints.txt"; return 0 ;;
  esac
  return 1
}

api_doc_finding() { # path kind
  finding_exists "API documentation publicly exposed" "$SCAN_BASE$1" "Sensitive file exposure" && return 0
  add_finding "API documentation publicly accessible" "$SCAN_BASE$1" "API security" LOW "Confirmed vulnerability" \
    "A $2 is reachable without authentication, giving attackers a complete map of the API." \
    "GET $1 -> HTTP 200" "curl" High \
    "Restrict API documentation to authenticated or internal users in production." "Public APIs often publish documentation deliberately."
}

# api_handle_docs PATH: the response body (FETCH_BODY) is an OpenAPI/Swagger document
api_handle_docs() {
  local p=$1 n paths
  paths=$(grep -aoE '"/[A-Za-z0-9_./{}:-]*"[[:space:]]*:[[:space:]]*\{' "$FETCH_BODY" | sed -E 's/^"([^"]*)".*/\1/' | sort -u | head -200)
  n=$(grep -c . <<<"$paths")
  api_doc_finding "$p" "OpenAPI/Swagger document listing $n path(s)"
  printf '%s\n' "$paths" >>"$TMPD/api_doc_paths.txt"
  if ! grep -qE '"(securitySchemes|securityDefinitions)"' "$FETCH_BODY" && ! grep -qE '"security"[[:space:]]*:' "$FETCH_BODY"; then
    add_finding "OpenAPI document declares no authentication scheme" "$SCAN_BASE$p" "API authentication" LOW "Potential vulnerability" \
      "The API description contains no security scheme, which may indicate that endpoints are intended to be open or that authentication is undocumented." \
      "$n documented path(s); no securitySchemes/securityDefinitions/security entries found" "doxa-api" Low \
      "Document and enforce authentication for every non-public operation." \
      "Authentication may be enforced by a gateway without being described in the document."
  fi
}

api_check_graphql() {
  http_fetch "$SCAN_BASE/graphql?query=%7B__typename%7D" gql
  grep -q '"__typename"' "$FETCH_BODY" || return 0
  add_finding "GraphQL endpoint reachable without authentication" "$SCAN_BASE/graphql" "API security" INFORMATIONAL "Informational observation" \
    "A GraphQL endpoint answers an unauthenticated read-only query." "GET /graphql?query={__typename} -> HTTP $FETCH_CODE" "curl" High \
    "Require authentication for the GraphQL endpoint unless it is intentionally public." ""
  http_fetch "$SCAN_BASE/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D" gql2
  if grep -q '"__schema"' "$FETCH_BODY"; then
    add_finding "GraphQL introspection enabled" "$SCAN_BASE/graphql" "API security" LOW "Confirmed vulnerability" \
      "Introspection returns the full schema to unauthenticated clients, revealing types, fields and operations." \
      "Introspection query answered with HTTP $FETCH_CODE (schema data not stored)" "curl" High \
      "Disable introspection in production or restrict it to authenticated developers." "Intentional for public GraphQL APIs."
  fi
}

run_api() {
  local p n0 n1 pass ep q
  n0=$(count_findings); API_SEEN=(); API_OK=(); API_PROT=(); API_DOCS=()
  : >"$LOG_DIR/api_endpoints.txt"; : >"$TMPD/api_doc_paths.txt"
  for p in "${API_COMMON[@]}"; do api_probe "$p" || :; done
  # candidates from JavaScript and from API documentation (GET-able, non-templated, same origin)
  for pass in 1 2; do
    local -a cand=()
    if (( pass == 1 )); then
      [[ -s $LOG_DIR/js_endpoints.txt ]] && mapfile -t cand < <(head -80 "$LOG_DIR/js_endpoints.txt")
    else
      [[ -s $TMPD/api_doc_paths.txt ]] && mapfile -t cand < <(head -80 "$TMPD/api_doc_paths.txt")
    fi
    for ep in "${cand[@]}"; do
      q=${ep%%\?*}
      [[ $q == *"{"* || $q == *":"* || $q == *"\${"* || ${#q} -lt 3 ]] && continue
      api_probe "$q" || :
    done
  done
  # GraphQL
  [[ -n ${API_SEEN[/graphql]:-} ]] && api_check_graphql
  local total=$(( ${#API_OK[@]} + ${#API_PROT[@]} ))
  if (( total == 0 )); then
    MODULE_DETAIL="no API endpoints found among ${#API_SEEN[@]} probed path(s)"
    return 0
  fi
  # CORS on the first reachable endpoint
  local first=${API_OK[0]:-}
  if [[ -n $first ]]; then
    local origin="https://doxa-cors-test.invalid" acao acac
    http_fetch "$SCAN_BASE$first" apicors -H "Origin: $origin"
    acao=$(hget "$FETCH_HDR" access-control-allow-origin); acac=$(hget "$FETCH_HDR" access-control-allow-credentials)
    if [[ $acao == "$origin" && ${acac,,} == true ]]; then
      add_finding "API CORS reflects arbitrary origin with credentials" "$SCAN_BASE$first" "CORS misconfiguration" HIGH "Potential vulnerability" \
        "The API reflects an untrusted Origin and allows credentials, so a malicious site could read authenticated API responses in a victim browser." \
        "Origin: $origin -> Access-Control-Allow-Origin: $acao; Access-Control-Allow-Credentials: $acac" "curl" Medium \
        "Validate Origin against an explicit allow-list; never combine reflected origins with credentials." \
        "Impact depends on whether the endpoint returns authenticated, sensitive data."
    elif [[ $acao == "*" ]]; then
      add_finding "API CORS allows any origin (wildcard)" "$SCAN_BASE$first" "CORS misconfiguration" LOW "Informational observation" \
        "Access-Control-Allow-Origin: * lets any website read unauthenticated API responses." "ACAO: *" "curl" High \
        "Restrict to trusted origins unless the API is intentionally public." "Normal for public read-only APIs."
    fi
    # response headers of a JSON API response
    http_fetch "$SCAN_BASE$first" apihdr
    if [[ -z $(hget "$FETCH_HDR" x-content-type-options) ]]; then
      add_finding "API responses lack X-Content-Type-Options" "$SCAN_BASE$first" "API security" LOW "Confirmed vulnerability" \
        "JSON responses are served without nosniff, allowing content-type sniffing in some browsers." "GET $first -> no X-Content-Type-Options header" "curl" High \
        "Send X-Content-Type-Options: nosniff on all API responses." "Low risk when Content-Type is correct and responses are not rendered."
    fi
  fi
  # sensitive-looking endpoints reachable without credentials
  local shown=0 fields
  for p in "${API_OK[@]}"; do
    [[ ${p,,} =~ $API_SENSITIVE_RE ]] || continue
    (( shown >= 10 )) && break
    shown=$((shown + 1))
    http_fetch "$SCAN_BASE$p" apisens
    fields=$(api_fields "$FETCH_BODY")
    add_finding "Potentially sensitive API endpoint reachable without authentication: $p" "$SCAN_BASE$p" "API access control indicators" MEDIUM "Potential vulnerability" \
      "An endpoint whose name suggests sensitive data returned a JSON response to an unauthenticated GET request. DOXA recorded field names only and did not store any data." \
      "GET $p -> HTTP $FETCH_CODE, $(hget "$FETCH_HDR" content-type), $(wc -c <"$FETCH_BODY" | tr -d ' ') bytes; field names: ${fields:-none}" "doxa-api" Low \
      "Require authentication and enforce object-level authorization on the server for every non-public endpoint." \
      "The data may be intentionally public (catalogues, status pages). Verify what the endpoint returns and who should see it."
  done
  # verbose error handling on up to three API bases
  local -A bases=(); local b
  for p in "${API_OK[@]}" "${API_PROT[@]}"; do
    b=/${p#/}; b=/${b#/}; b=/$(cut -d/ -f2 <<<"$b")
    [[ $b == /api || $b == /rest || $b =~ ^/v[0-9]+$ ]] && bases[$b]=1
  done
  local n_err=0
  for b in "${!bases[@]}"; do
    (( n_err >= 3 )) && break
    n_err=$((n_err + 1))
    http_fetch "$SCAN_BASE$b/doxa-nonexistent-$RANDOM" apierr
    if [[ $FETCH_CODE =~ ^[45] ]] && grep -aqE "$API_STACK_RE" "$FETCH_BODY"; then
      add_finding "Verbose error or stack trace disclosed by API ($b)" "$SCAN_BASE$b/" "Information disclosure" MEDIUM "Confirmed vulnerability" \
        "A request for a non-existent resource returned an error that contains stack-trace or framework internals." \
        "GET $b/<random> -> HTTP $FETCH_CODE; stack-trace signature matched ($(grep -aoE "$API_STACK_RE" "$FETCH_BODY" | head -1 | cut -c1-40 | tr -d '\n')...)" "curl" High \
        "Return generic error messages in production and log details server-side." \
        "Development builds commonly enable verbose errors." "" \
        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" "Internal paths and framework details confirmed in an unauthenticated error response; no data records were exposed."
    fi
  done
  add_finding "API endpoints discovered (${#API_OK[@]} reachable without credentials, ${#API_PROT[@]} protected)" "$SCAN_BASE" "API security" INFORMATIONAL "Informational observation" \
    "GET probes of common, JavaScript-referenced and documented API paths. Details are listed in logs/api_endpoints.txt." \
    "$(cut -f1-3 "$LOG_DIR/api_endpoints.txt" | head -40)" "doxa-api" Medium \
    "Confirm that every reachable endpoint is meant to be public." "Only GET requests without credentials were sent."
  LIMITS+=("API assessment used unauthenticated GET requests only; authorization (IDOR/BOLA), business logic and write operations were not tested.")
  n1=$(count_findings)
  MODULE_DETAIL="${#API_SEEN[@]} path(s) probed: ${#API_OK[@]} open, ${#API_PROT[@]} protected, $((n1 - n0)) finding(s)"
  return 0
}
