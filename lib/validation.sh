# shellcheck shell=bash
# DOXA input validation: IPv4, IPv6, hostnames, ports, URLs and CLI values.
shopt -u patsub_replacement 2>/dev/null || true

VALIDATION_ERROR=""

is_ipv4() {
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
  return 0
}

# is_ipv6: plain IPv6 text (no brackets, no zone id, no embedded IPv4 tail)
is_ipv6() {
  local a=$1 g n=0 dbl=0 rest
  local -a groups
  [[ $a =~ ^[0-9A-Fa-f:]+$ ]] || return 1
  [[ $a == *:::* ]] && return 1
  if [[ $a == *::* ]]; then
    rest=${a#*::}
    [[ $rest == *::* ]] && return 1
    dbl=1
  fi
  [[ $a == :* && $a != ::* ]] && return 1
  [[ $a == *: && $a != *:: ]] && return 1
  IFS=: read -ra groups <<<"$a"
  for g in "${groups[@]}"; do
    [[ -z $g ]] && continue
    (( ${#g} <= 4 )) || return 1
    n=$((n + 1))
  done
  if (( dbl )); then (( n <= 7 )) || return 1; else (( n == 8 )) || return 1; fi
  return 0
}

is_hostname() {
  local h=$1 label
  local -a labels
  (( ${#h} >= 1 && ${#h} <= 253 )) || return 1
  [[ $h != .* && $h != *. && $h != *..* ]] || return 1
  IFS=. read -ra labels <<<"$h"
  for label in "${labels[@]}"; do
    (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
    [[ $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
  return 0
}

is_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# parse_url_generic URL -> P_SCHEME P_HOST P_PORT(explicit or "") P_EPORT(effective) P_PATH P_HOSTTYPE P_AUTHORITY
# Returns 1 and sets VALIDATION_ERROR on any problem. Never executes or expands input.
parse_url_generic() {
  local url=$1 rest authority scheme host="" port="" pathq pre
  P_SCHEME=""; P_HOST=""; P_PORT=""; P_EPORT=""; P_PATH=""; P_HOSTTYPE=""; P_AUTHORITY=""
  VALIDATION_ERROR=""
  [[ -n $url ]] || { VALIDATION_ERROR="empty URL"; return 1; }
  (( ${#url} <= 2048 )) || { VALIDATION_ERROR="URL too long"; return 1; }
  if [[ $url == *[[:space:]]* || $url == *[[:cntrl:]]* || $url == *\\* ]]; then
    VALIDATION_ERROR="URL contains whitespace, control characters or backslashes"; return 1
  fi
  [[ $url == *://* ]] || { VALIDATION_ERROR="missing scheme (use http:// or https://)"; return 1; }
  pre=${url%%://*}; scheme=${pre,,}
  [[ $scheme == http || $scheme == https ]] || { VALIDATION_ERROR="unsupported scheme '$scheme'"; return 1; }
  rest=${url#*://}
  authority=${rest%%[/?#]*}
  pathq=${rest#"$authority"}
  [[ -n $authority ]] || { VALIDATION_ERROR="missing host"; return 1; }
  [[ $authority != *@* ]] || { VALIDATION_ERROR="credentials (user@host) in URL are not allowed"; return 1; }
  if [[ $authority == \[* ]]; then
    [[ $authority =~ ^\[([0-9A-Fa-f:]+)\](:([0-9]+))?$ ]] || { VALIDATION_ERROR="malformed IPv6 authority"; return 1; }
    host=${BASH_REMATCH[1]}; port=${BASH_REMATCH[3]:-}
    is_ipv6 "$host" || { VALIDATION_ERROR="invalid IPv6 address"; return 1; }
    P_HOSTTYPE=ipv6
  else
    if [[ $authority == *:* ]]; then
      host=${authority%%:*}; port=${authority#*:}
      [[ $port != *:* ]] || { VALIDATION_ERROR="multiple colons: wrap IPv6 addresses in [brackets]"; return 1; }
      [[ -n $port ]] || { VALIDATION_ERROR="empty port"; return 1; }
    else
      host=$authority
    fi
    host=${host,,}
    if is_ipv4 "$host"; then P_HOSTTYPE=ipv4
    elif [[ $host =~ ^[0-9.]+$ ]]; then VALIDATION_ERROR="invalid IPv4 address"; return 1
    elif is_hostname "$host"; then P_HOSTTYPE=domain
    else VALIDATION_ERROR="invalid hostname"; return 1; fi
  fi
  if [[ -n $port ]]; then
    is_port "$port" || { VALIDATION_ERROR="invalid port '$port'"; return 1; }
    port=$((10#$port))
  fi
  P_PATH=${pathq%%[?#]*}
  if [[ -n $P_PATH ]]; then
    [[ $P_PATH =~ ^/[A-Za-z0-9._~/%+=\&@:,-]*$ ]] || { VALIDATION_ERROR="unsupported characters in path"; return 1; }
    [[ $P_PATH != */../* && $P_PATH != */.. ]] || { VALIDATION_ERROR="path traversal segments are not allowed"; return 1; }
  fi
  P_SCHEME=$scheme; P_HOST=${host,,}; P_PORT=$port; P_AUTHORITY=$authority
  if [[ -n $port ]]; then P_EPORT=$port; elif [[ $scheme == https ]]; then P_EPORT=443; else P_EPORT=80; fi
  return 0
}

# validate_target URL -> sets the global target variables used by all modules
validate_target() {
  parse_url_generic "$1" || return 1
  SCHEME=$P_SCHEME; HOST=$P_HOST; PORT=$P_PORT; PATH_PREFIX=${P_PATH%/}
  IS_IP=0; IS_IPV6=0; HOST_URL=$HOST
  [[ $P_HOSTTYPE == ipv4 || $P_HOSTTYPE == ipv6 ]] && IS_IP=1
  if [[ $P_HOSTTYPE == ipv6 ]]; then IS_IPV6=1; HOST_URL="[$HOST]"; fi
  if [[ ( $SCHEME == http && $PORT == 80 ) || ( $SCHEME == https && $PORT == 443 ) ]]; then PORT=""; fi
  if [[ -n $PORT ]]; then BASE_URL="$SCHEME://$HOST_URL:$PORT"; else BASE_URL="$SCHEME://$HOST_URL"; fi
  TARGET_URL="$BASE_URL$PATH_PREFIX"
  HTTP_BASE=""; HTTPS_BASE=""; HTTPS_PORT=443
  if [[ -n $PORT ]]; then
    if [[ $SCHEME == https ]]; then HTTPS_BASE=$BASE_URL; HTTPS_PORT=$PORT; else HTTP_BASE=$BASE_URL; fi
  else
    HTTP_BASE="http://$HOST_URL"; HTTPS_BASE="https://$HOST_URL"
  fi
  return 0
}

validate_int() { # validate_int NAME VALUE MIN MAX
  if [[ $2 =~ ^[0-9]+$ ]] && (( 10#$2 >= $3 && 10#$2 <= $4 )); then return 0; fi
  VALIDATION_ERROR="$1 must be an integer between $3 and $4"; return 1
}

# validate_output_dir: reject option-like or control-character paths
validate_output_dir() {
  [[ -n $1 && $1 != -* && $1 != *[[:cntrl:]]* ]] || { VALIDATION_ERROR="unsafe output directory"; return 1; }
  return 0
}

# validate_scope_host: exact host, IPv4, IPv6 or *.wildcard.domain
validate_scope_host() {
  local h=${1,,}
  if [[ $h == \*.* ]]; then is_hostname "${h#*.}" && return 0; fi
  is_ipv4 "$h" && return 0
  is_ipv6 "$h" && return 0
  is_hostname "$h" && return 0
  VALIDATION_ERROR="invalid scope host '$1'"; return 1
}
