# shellcheck shell=bash
# DOXA common helpers: text sanitising, escaping, redaction, tool runner, approvals.
shopt -u patsub_replacement 2>/dev/null || true

have() { command -v "$1" >/dev/null 2>&1; }
now_iso() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
fmt_dur() { local s=$1; printf '%dm %02ds' $((s / 60)) $((s % 60)); }
clean() { printf '%s' "$1" | LC_ALL=C tr -cd '\11\12\40-\176'; }

ver_lt() { # ver_lt A B -> true when A < B
  [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1) == "$1" ]]
}

html_escape() {
  local s=$1
  s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; s=${s//\"/&quot;}; s=${s//\'/&#39;}
  printf '%s' "$s"
}

# json_str TEXT -> a quoted, escaped JSON string (ASCII-only output)
json_str() {
  local s
  s=$(printf '%s' "$1" | LC_ALL=C tr -cd '\11\12\15\40-\176')
  s=${s//\\/\\\\}; s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '"%s"' "$s"
}

# csv_field TEXT -> RFC 4180 field, neutralising spreadsheet formula injection
csv_field() {
  local s=$1
  s=${s//$'\036'/ }; s=${s//$'\n'/ }; s=${s//$'\r'/ }; s=${s//$'\t'/ }
  case $s in [=+@-]*) s="'$s" ;; esac
  s=${s//\"/\"\"}
  printf '"%s"' "$s"
}

# redact_text: stdin -> stdout, masks credentials, tokens and key material
redact_text() {
  sed -E \
    -e 's/((authorization|proxy-authorization|x-api-key|api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|token|passwd|password|pwd)["'"'"']?[[:space:]]*[:=][[:space:]]*)((Bearer|Basic)[[:space:]]+)?["'"'"']?[^[:space:]"'"'"',;\&<>]{4,}/\1<redacted>/Ig' \
    -e 's/[Bb]earer[[:space:]]+[A-Za-z0-9._~+\/=-]{10,}/Bearer <redacted>/g' \
    -e 's/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/<jwt-redacted>/g' \
    -e 's/AKIA[0-9A-Z]{16}/AKIA<redacted>/g' \
    -e 's/AIza[0-9A-Za-z_-]{35}/AIza<redacted>/g' \
    -e 's/(gh[pousr]_)[A-Za-z0-9]{20,}/\1<redacted>/g' \
    -e 's/xox[baprs]-[A-Za-z0-9-]{10,}/xox<redacted>/g' \
    -e 's/(sk_live_)[0-9A-Za-z]{16,}/\1<redacted>/g' \
    -e '/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/c\<private key material redacted>' \
    -e 's/^([Ss]et-[Cc]ookie:[[:space:]]*[^=]*=)[^;]*/\1<redacted>/' \
    -e 's/^([Cc]ookie:[[:space:]]*).*/\1<redacted>/'
}

redact_headers() { tr -d '\r' | redact_text; }

# Safe temporary directory (private, removed on exit by cleanup)
make_tmpdir() {
  TMPD=$(mktemp -d "${TMPDIR:-/tmp}/doxa.XXXXXX") || return 1
  chmod 700 "$TMPD"
}
cleanup() { [[ -n ${TMPD:-} && -d ${TMPD:-} && $TMPD == */doxa.* ]] && rm -rf -- "$TMPD"; return 0; }

# run_tool LABEL TIMEOUT LOGFILE CMD...   (spinner, timeout, logged, interruptible)
run_tool() {
  local label=$1 tmo=$2 logf=$3; shift 3
  local start=$SECONDS rc=0 cmdline="$*" i=0 sp='|/-\'
  log CMD "$label: $cmdline"
  (( ${VERBOSE:-0} )) && printf '    %s$ %s%s\n' "$C_DIM" "$cmdline" "$C_RESET"
  timeout --kill-after=10 "$tmo" "$@" >"$logf" 2>&1 </dev/null &
  CHILD_PID=$!
  if [[ -t 1 ]]; then
    while kill -0 "$CHILD_PID" 2>/dev/null; do
      printf '\r    %s%s%s %s running... %ds ' "$C_GREEN" "${sp:$((i % 4)):1}" "$C_RESET" "$label" $((SECONDS - start))
      i=$((i + 1)); sleep 0.2
    done
    printf '\r\033[K'
  fi
  wait "$CHILD_PID"; rc=$?
  CHILD_PID=""
  printf '%s\t%s\t%s\t%s\t%s\n' "$label" "${cmdline//$'\t'/ }" "$rc" "$((SECONDS - start))" "${logf#"${OUTDIR:-}"/}" >>"${TOOLS_TSV:-/dev/null}"
  return "$rc"
}

# require_approval "description": risky checks need explicit approval
require_approval() {
  if (( ${ALLOW_DANGEROUS:-0} )); then log APPROVE "pre-approved: $1"; return 0; fi
  [[ -t 0 && -t 1 ]] || return 1
  printf '\n%s[?] MANUAL APPROVAL REQUIRED%s\n    %s\n' "$C_YELLOW" "$C_RESET" "$1"
  local a; read -r -p "    Approve? [y/N] " a
  if [[ ${a,,} == y || ${a,,} == yes ]]; then log APPROVE "approved: $1"; return 0; fi
  log APPROVE "denied: $1"; return 1
}
