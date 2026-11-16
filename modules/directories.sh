# shellcheck shell=bash
# DOXA module: directories (ported from v1.0.0, hardened for v2.0)
shopt -u patsub_replacement 2>/dev/null || true

find_wordlist() {
  local c
  if [[ -n $WORDLIST ]]; then [[ -r $WORDLIST ]] && { printf '%s' "$WORDLIST"; return 0; }; return 1; fi
  local -a cands
  if [[ $MODE == full ]]; then
    cands=(/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt /usr/share/wordlists/dirb/common.txt /usr/share/seclists/Discovery/Web-Content/common.txt)
  else
    cands=(/usr/share/wordlists/dirb/common.txt /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt)
  fi
  for c in "${cands[@]}"; do [[ -r $c ]] && { printf '%s' "$c"; return 0; }; done
  return 1
}

run_gobuster() {
  local wl out="$OUTDIR/gobuster/gobuster_dir.txt" res="$OUTDIR/gobuster/results_filtered.txt" rc=0 delay_ms src
  wl=$(find_wordlist) || { MODULE_DETAIL="no readable wordlist (install dirb/seclists or use --wordlist)"; return 1; }
  scope_assert_url "$SCAN_URL/" || return 1
  delay_ms=$(( 1000 * THREADS / RATE ))
  local -a cmd=(gobuster dir -u "$SCAN_URL" -w "$wl" -t "$THREADS" -s "200,204,301,302,307,401,403" -b "" -q --no-error -a "$UA" --timeout 10s -o "$out")
  (( INSECURE_TLS )) && cmd+=(-k)
  (( delay_ms > 0 )) && cmd+=(--delay "${delay_ms}ms")
  [[ $MODE == full ]] && cmd+=(-x php,html,txt,bak,old,zip,json)
  run_tool gobuster "$TOOL_TIMEOUT" "$LOG_DIR/gobuster.log" "${cmd[@]}" || rc=$?
  if (( rc != 0 )) && grep -qiE 'non existing urls|wildcard' "$LOG_DIR/gobuster.log"; then
    warn "gobuster detected wildcard responses; retrying with --wildcard and filtering results"
    : >"$out"; cmd+=(--wildcard); rc=0
    run_tool gobuster-wildcard "$TOOL_TIMEOUT" "$LOG_DIR/gobuster.log" "${cmd[@]}" || rc=$?
  fi
  src=$out; [[ -s $src ]] || src="$LOG_DIR/gobuster.log"
  awk -v bc="$B404_CODE" -v bl="$B404_LEN" '
    match($0, /\(Status: [0-9]+\)/) {
      st = substr($0, RSTART + 9, RLENGTH - 10); sz = 0
      if (match($0, /\[Size: [0-9]+\]/)) sz = substr($0, RSTART + 7, RLENGTH - 8)
      p = $1; if (p !~ /^\//) p = "/" p
      if (bc != "404" && st == bc && sz == bl) next
      print p, st, sz
    }' "$src" 2>/dev/null | sort -u >"$res"
  local total dom cnt s1 s2 noise=""
  total=$(wc -l <"$res" | tr -d ' ')
  if (( total > 30 )); then
    dom=$(awk '{print $2, $3}' "$res" | sort | uniq -c | sort -rn | head -1)
    read -r cnt s1 s2 <<<"$dom"
    if (( cnt * 2 > total )); then
      awk -v s="$s1" -v z="$s2" '!($2 == s && $3 == z)' "$res" >"$res.tmp" && mv "$res.tmp" "$res"
      noise=" (dropped $cnt wildcard-like results)"
      total=$(wc -l <"$res" | tr -d ' ')
    fi
  fi
  if (( total == 0 )); then
    MODULE_DETAIL="no accessible paths found$noise"
    (( rc == 0 )) || MODULE_DETAIL="gobuster exit $rc, no results; see logs/gobuster.log"
    return "$rc"
  fi
  add_finding "Discovered accessible paths ($total)" "$SCAN_URL" "Directory and file enumeration" INFORMATIONAL "Informational observation" \
    "Gobuster found $total path(s) returning interesting status codes using wordlist $(basename "$wl").$noise" "$(head -40 "$res")" "gobuster" Medium \
    "Review discovered paths and remove or protect anything not meant to be public." \
    "Status 403/401 only proves existence. Verify each path manually; wildcard filtering is heuristic."
  local path st sz base nfind=0
  local -a dirs=()
  while read -r path st sz; do
    base=${path##*/}
    if [[ $st == 200 && ${path,,} =~ \.(bak|old|zip|sql|tar\.gz|conf|config|log|swp|ini|yml|yaml|cfg|inc|env)$ ]] && (( nfind < 25 )); then
      nfind=$((nfind + 1))
      add_finding "Potentially sensitive file discovered: $path" "$SCAN_BASE$path" "Sensitive file exposure" MEDIUM "Potential vulnerability" \
        "A backup/config/log style file returned HTTP 200. Content was not inspected." "$path (Status: $st, Size: $sz)" "gobuster" Low \
        "Verify the file contents; remove or restrict it if it should not be public." "A 200 response may be a generic page. Content not validated."
    elif [[ ${path,,} =~ (^|/)(admin|administrator|phpmyadmin|manager|console|wp-admin|cpanel|login)(/|$) ]] && [[ $st =~ ^(200|301|302|401|403)$ ]] && (( nfind < 25 )); then
      nfind=$((nfind + 1))
      add_finding "Administrative interface discovered: $path" "$SCAN_BASE$path" "Attack surface" LOW "Potential vulnerability" \
        "A path that looks like an administrative or login interface responded." "$path (Status: $st)" "gobuster" Low \
        "Restrict admin interfaces by network or VPN and enforce MFA and strong authentication." "The path may be a decoy or require authentication."
    fi
    if [[ $st =~ ^(200|301|302|403)$ && $base != *.* ]] && (( ${#dirs[@]} < 25 )); then dirs+=("${path%/}/"); fi
  done <"$res"
  (( ${#dirs[@]} )) && check_dir_listing "${dirs[@]}"
  MODULE_DETAIL="$total path(s)$noise"
  return "$rc"
}
