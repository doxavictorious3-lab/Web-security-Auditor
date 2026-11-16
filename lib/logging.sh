# shellcheck shell=bash
# DOXA logging and terminal helpers (cyan / Matrix-green theme)
shopt -u patsub_replacement 2>/dev/null || true

MAIN_LOG="${MAIN_LOG:-/dev/null}"
OPT_NO_COLOR="${OPT_NO_COLOR:-0}"

setup_colors() {
  if [[ -t 1 && $OPT_NO_COLOR -eq 0 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
    C_CYAN=$'\e[96m'; C_GREEN=$'\e[38;5;46m'; C_RED=$'\e[91m'
    C_ORANGE=$'\e[38;5;208m'; C_YELLOW=$'\e[93m'; C_BLUE=$'\e[94m'; C_GREY=$'\e[90m'
  else
    C_RESET="" C_BOLD="" C_DIM="" C_CYAN="" C_GREEN="" C_RED="" C_ORANGE="" C_YELLOW="" C_BLUE="" C_GREY=""
  fi
}
setup_colors

log() { printf '[%s] [%s] %s\n' "$(date '+%F %T')" "$1" "${*:2}" >>"$MAIN_LOG" 2>/dev/null || true; }
info() { printf '%s[*]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; log INFO "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; log OK "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; log WARN "$*"; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; log ERROR "$*"; }
die()  { local code=$1; shift; err "$*"; exit "$code"; }

sev_color() {
  case $1 in
    CRITICAL) printf '%s' "$C_RED$C_BOLD" ;;
    HIGH) printf '%s' "$C_ORANGE" ;;
    MEDIUM) printf '%s' "$C_YELLOW" ;;
    LOW) printf '%s' "$C_BLUE" ;;
    *) printf '%s' "$C_GREY" ;;
  esac
}
sev_tag() { printf '%s[%-13s]%s' "$(sev_color "$1")" "$1" "$C_RESET"; }

progress_bar() { # cur total
  local cur=$1 tot=$2 w=24 filled i bar=""
  (( tot > 0 )) || tot=1
  filled=$(( cur * w / tot ))
  for ((i = 0; i < w; i++)); do
    if (( i < filled )); then bar+="#"; else bar+="-"; fi
  done
  printf '%s[%s]%s %3d%%' "$C_GREEN" "$bar" "$C_RESET" $(( cur * 100 / tot ))
}
