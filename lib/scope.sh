# shellcheck shell=bash
# DOXA scope control: approved hosts/ports, redirect validation, global rate limiter,
# and the single HTTP client (http_fetch) every module must use.
shopt -u patsub_replacement 2>/dev/null || true

SCOPE_HOSTS=()
SCOPE_PORTS=()
SCOPE_OOS_COUNT=0
SCOPE_REASON=""
INSECURE_TLS=0          # set only by --insecure-tls-diagnostic
CA_CERT=""              # optional --ca-cert FILE for lab CAs
TLS_VERIFY_FAILED=0
RATE=${RATE:-30}
MAX_REDIRECTS=${MAX_REDIRECTS:-5}
CURL_TIMEOUT=${CURL_TIMEOUT:-15}
NEXT_SLOT_US=0
FETCH_CODE="" FETCH_HDR="" FETCH_BODY="" FETCH_RC=0 FETCH_ERR=""
CHAIN_FINAL_URL="" CHAIN_FINAL_CODE="" CHAIN_BLOCKED="" CHAIN_DOWNGRADE=0
UA="${UA:-DOXA-Web-Security-Auditor/2.0 (authorized security assessment)}"
CURL_BASE=()

scope_add_host() {
  validate_scope_host "$1" || return 1
  local h=${1,,} x
  for x in "${SCOPE_HOSTS[@]}"; do [[ $x == "$h" ]] && return 0; done
  SCOPE_HOSTS+=("$h")
}

scope_add_port() {
  is_port "$1" || { VALIDATION_ERROR="invalid scope port '$1'"; return 1; }
  local p=$((10#$1)) x
  for x in "${SCOPE_PORTS[@]}"; do [[ $x == "$p" ]] && return 0; done
  SCOPE_PORTS+=("$p")
}

# scope_init: call after validate_target. Defaults: target host; explicit port or 80+443.
scope_init() {
  scope_add_host "$HOST"
  if (( ${#SCOPE_PORTS[@]} == 0 )); then
    SCOPE_PORTS_DEFAULTED=1
    if [[ -n $PORT ]]; then scope_add_port "$PORT"; else scope_add_port 80; scope_add_port 443; fi
  else
    SCOPE_PORTS_DEFAULTED=0
  fi
}

scope_host_ok() {
  local h=${1,,} x
  for x in "${SCOPE_HOSTS[@]}"; do
    if [[ $x == \*.* ]]; then
      [[ $h == *"${x#\*}" && $h != "${x#\*.}" ]] && return 0
    elif [[ $x == "$h" ]]; then
      return 0
    fi
  done
  return 1
}

scope_port_ok() {
  local x
  for x in "${SCOPE_PORTS[@]}"; do [[ $x == "$1" ]] && return 0; done
  return 1
}

# scope_check_url URL -> 0 in scope, 1 out of scope (SCOPE_REASON explains)
scope_check_url() {
  SCOPE_REASON=""
  if ! parse_url_generic "$1"; then SCOPE_REASON="invalid URL: $VALIDATION_ERROR"; return 1; fi
  if ! scope_host_ok "$P_HOST"; then SCOPE_REASON="host '$P_HOST' is not approved"; return 1; fi
  if ! scope_port_ok "$P_EPORT"; then SCOPE_REASON="port $P_EPORT is not approved"; return 1; fi
  return 0
}

scope_note_oos() { # url reason
  SCOPE_OOS_COUNT=$((SCOPE_OOS_COUNT + 1))
  printf '%s\t%s\t%s\n' "$(now_iso)" "$1" "$2" >>"${LOG_DIR:-/dev/null}/out_of_scope.log" 2>/dev/null || true
  log SCOPE "blocked out-of-scope request: $1 ($2)"
}

# scope_assert_url URL: for external tools; blocks and records when out of scope
scope_assert_url() {
  if scope_check_url "$1"; then return 0; fi
  scope_note_oos "$1" "$SCOPE_REASON"
  MODULE_DETAIL="blocked: $1 is out of scope ($SCOPE_REASON)"
  warn "Blocked out-of-scope target: $1 ($SCOPE_REASON)"
  return 1
}

# scope_assert_host HOST: external port/DNS tools
scope_assert_host() {
  if scope_host_ok "$1"; then return 0; fi
  scope_note_oos "host:$1" "host is not approved"
  MODULE_DETAIL="blocked: host $1 is not approved"
  warn "Blocked out-of-scope host: $1"
  return 1
}

# ---------------------------------------------------------------------------
# Global rate limiter: one shared budget for every request DOXA itself makes.
# External tools receive the same RATE value and run strictly one after another,
# so the aggregate never exceeds RATE requests per second.
# ---------------------------------------------------------------------------
rate_wait() {
  local now interval wait_us
  (( RATE > 0 )) || return 0
  interval=$(( 1000000 / RATE ))
  now=${EPOCHREALTIME/./}
  if (( now < NEXT_SLOT_US )); then
    wait_us=$(( NEXT_SLOT_US - now ))
    printf -v wait_us '%d.%06d' $((wait_us / 1000000)) $((wait_us % 1000000))
    sleep "$wait_us"
    now=${EPOCHREALTIME/./}
  fi
  NEXT_SLOT_US=$(( now + interval ))
}

# ---------------------------------------------------------------------------
# HTTP client. TLS certificates are VERIFIED by default.
# ---------------------------------------------------------------------------
build_curl_base() {
  CURL_BASE=(-s -g --max-time "$CURL_TIMEOUT" --connect-timeout 8 -A "$UA" --max-redirs 0
             --max-filesize 3000000 --proto '=http,https' --proto-redir '=http,https')
  [[ -n $CA_CERT ]] && CURL_BASE+=(--cacert "$CA_CERT")
  (( INSECURE_TLS )) && CURL_BASE+=(-k)
  return 0
}

# http_fetch URL NAME [extra curl args]  -> FETCH_CODE FETCH_HDR FETCH_BODY FETCH_RC FETCH_ERR
http_fetch() {
  local url=$1 name=$2; shift 2
  local rc=0
  FETCH_HDR="$TMPD/$name.hdr"; FETCH_BODY="$TMPD/$name.body"; FETCH_ERR=""; FETCH_RC=0
  : >"$FETCH_HDR"; : >"$FETCH_BODY"
  if ! scope_check_url "$url"; then
    FETCH_CODE=000; FETCH_ERR="out-of-scope: $SCOPE_REASON"; FETCH_RC=-1
    scope_note_oos "$url" "$SCOPE_REASON"
    return 0
  fi
  rate_wait
  FETCH_CODE=$(curl "${CURL_BASE[@]}" -D "$FETCH_HDR" -o "$FETCH_BODY" -w '%{http_code}' "$@" "$url" 2>>"${LOG_DIR:-/dev/null}/curl.err") || rc=$?
  FETCH_RC=$rc
  [[ $FETCH_CODE =~ ^[0-9]{3}$ ]] || FETCH_CODE=000
  case $rc in
    0|63) ;;
    60|51|58|59|77|83) FETCH_ERR="tls-verification-failed"; TLS_VERIFY_FAILED=1 ;;
    28) FETCH_ERR="timeout" ;;
    6)  FETCH_ERR="dns-failure" ;;
    7)  FETCH_ERR="connection-refused" ;;
    *)  FETCH_ERR="curl-exit-$rc" ;;
  esac
  return 0
}

# follow_chain URL: manual redirect following; every hop is scope-checked.
# Prints the chain; sets CHAIN_FINAL_URL/CODE, CHAIN_BLOCKED (reason) and CHAIN_DOWNGRADE.
follow_chain() {
  local url=$1 i loc origin hop_scheme prev_scheme=""
  local -a seen=()
  CHAIN_BLOCKED=""; CHAIN_DOWNGRADE=0
  for ((i = 1; i <= MAX_REDIRECTS + 1; i++)); do
    http_fetch "$url" chain
    printf '  [%d] %s -> HTTP %s%s\n' "$i" "$url" "$FETCH_CODE" "${FETCH_ERR:+ ($FETCH_ERR)}"
    CHAIN_FINAL_URL=$url; CHAIN_FINAL_CODE=$FETCH_CODE
    if [[ -n ${CHAIN_ALL_HDR:-} ]]; then cat "$FETCH_HDR" >>"$CHAIN_ALL_HDR"; fi
    case $FETCH_CODE in 301|302|303|307|308) ;; *) return 0 ;; esac
    (( i > MAX_REDIRECTS )) && { CHAIN_BLOCKED="redirect limit ($MAX_REDIRECTS) exceeded"; printf '      %s\n' "$CHAIN_BLOCKED"; return 0; }
    loc=$(hget "$FETCH_HDR" location)
    [[ -n $loc ]] || return 0
    parse_url_generic "$url" || return 0
    origin="$P_SCHEME://$P_AUTHORITY"; prev_scheme=$P_SCHEME
    if [[ $loc == //* ]]; then loc="$P_SCHEME:$loc"
    elif [[ $loc == /* ]]; then loc="$origin$loc"
    elif [[ $loc != http://* && $loc != https://* ]]; then
      if [[ $loc == *://* ]]; then CHAIN_BLOCKED="redirect to unsupported scheme"; printf '      %s\n' "$CHAIN_BLOCKED"; scope_note_oos "$loc" "$CHAIN_BLOCKED"; return 0; fi
      loc="$origin${P_PATH%/*}/$loc"
    fi
    if ! scope_check_url "$loc"; then
      CHAIN_BLOCKED="redirect target not followed: $SCOPE_REASON"
      printf '      %s (%s)\n' "$CHAIN_BLOCKED" "$loc"
      scope_note_oos "$loc" "$SCOPE_REASON"
      return 0
    fi
    hop_scheme=$P_SCHEME
    [[ $prev_scheme == https && $hop_scheme == http ]] && CHAIN_DOWNGRADE=1
    local s; for s in "${seen[@]}"; do
      if [[ $s == "$loc" ]]; then CHAIN_BLOCKED="redirect loop"; printf '      %s\n' "$CHAIN_BLOCKED"; return 0; fi
    done
    seen+=("$url")
    url=$loc
  done
  return 0
}

# ---------------------------------------------------------------------------
# Header helpers (used with FETCH_HDR files)
# ---------------------------------------------------------------------------
hget() { # hget headers-file name -> first value
  tr -d '\r' <"$1" | awk -v n="${2,,}" '{ k=$0; sub(/:.*/, "", k); if (tolower(k)==n) { sub(/^[^:]*:[ \t]*/, ""); print; exit } }'
}
hget_all() { # all values (e.g. Set-Cookie)
  tr -d '\r' <"$1" | awk -v n="${2,,}" '{ k=$0; sub(/:.*/, "", k); if (tolower(k)==n) { sub(/^[^:]*:[ \t]*/, ""); print } }'
}

hdr_excerpt() { redact_headers <"$ROOT_HDR" | head -25; }
