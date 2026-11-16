# shellcheck shell=bash
# Safe config loading: whitelisted KEY=VALUE parsing, never "source"d.
shopt -u patsub_replacement 2>/dev/null || true

load_settings() { # file
  local f=$1 k v
  [[ -r $f ]] || return 0
  while IFS='=' read -r k v; do
    [[ $k =~ ^[A-Z_]+$ ]] || continue
    [[ $v =~ ^[A-Za-z0-9_./,:@+-]*$ ]] || { warn "ignored unsafe value for $k in $f"; continue; }
    case $k in
      DEFAULT_THREADS) DEFAULT_THREADS=$v ;;
      DEFAULT_RATE) DEFAULT_RATE=$v ;;
      TOOL_TIMEOUT) [[ -n $v ]] && TOOL_TIMEOUT=$v ;;
      CURL_TIMEOUT) [[ -n $v ]] && CURL_TIMEOUT=$v ;;
      MAX_REDIRECTS) [[ -n $v ]] && MAX_REDIRECTS=$v ;;
      OUTPUT_ROOT) [[ -n $v ]] && OUTPUT_ROOT=$v ;;
      WORDLIST) [[ -n $v ]] && WORDLIST=$v ;;
    esac
  done < <(grep -vE '^[[:space:]]*(#|$)' "$f")
}

# load_profile NAME FILE -> PROFILE_MODULES PROFILE_THREADS PROFILE_RATE PROFILE_DESC
load_profile() {
  local want=$1 f=$2 line sect="" found=0
  PROFILE_MODULES="" PROFILE_THREADS="" PROFILE_RATE="" PROFILE_DESC=""
  [[ -r $f ]] || return 1
  while IFS= read -r line; do
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ $line =~ ^\[([a-z]+)\]$ ]]; then sect=${BASH_REMATCH[1]}; [[ $sect == "$want" ]] && found=1; continue; fi
    [[ $sect == "$want" ]] || continue
    case $line in
      modules=*) PROFILE_MODULES=${line#modules=} ;;
      threads=*) PROFILE_THREADS=${line#threads=} ;;
      rate=*) PROFILE_RATE=${line#rate=} ;;
      description=*) PROFILE_DESC=${line#description=} ;;
    esac
  done <"$f"
  (( found ))
}
