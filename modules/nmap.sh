# shellcheck shell=bash
# DOXA module: nmap (ported from v1.0.0, hardened for v2.0)
shopt -u patsub_replacement 2>/dev/null || true

run_nmap() {
  local out="$OUTDIR/nmap/nmap" scripts rc=0 ports line svc
  scripts="http-title,http-server-header,http-methods,http-headers,http-robots.txt,ssl-cert,banner"
  local -a cmd=(nmap -Pn -sV --script "$scripts" --max-retries 2 --host-timeout "${TOOL_TIMEOUT}s" -oA "$out")
  if (( ! ${SCOPE_PORTS_DEFAULTED:-1} )); then
    cmd+=(-p "$(IFS=,; printf '%s' "${SCOPE_PORTS[*]}")" -T3 --version-intensity 2)
  elif [[ $MODE == full ]]; then
    cmd+=(--top-ports 1000 -T4 --version-intensity 5)
  else
    cmd+=(-p 21,22,23,25,53,80,110,143,443,445,465,587,993,995,1433,2375,3000,3306,3389,5000,5432,5900,6379,8000,8008,8080,8081,8088,8443,8888,9000,9200,27017 -T3 --version-intensity 2)
  fi
  scope_assert_host "$HOST" || return 1
  cmd+=(--max-rate "$RATE")
  (( IS_IPV6 )) && cmd+=(-6)
  cmd+=("$HOST")
  run_tool nmap "$TOOL_TIMEOUT" "$LOG_DIR/nmap.log" "${cmd[@]}" || rc=$?
  [[ -s $out.gnmap ]] || { MODULE_DETAIL="no nmap output (exit $rc); see logs/nmap.log"; return "${rc/#0/1}"; }

  local list="$TMPD/open_ports.txt"
  grep -E '^Host:.*Ports:' "$out.gnmap" | sed -E 's/^.*Ports: //; s/\tIgnored.*$//' | tr ',' '\n' | sed 's/^ *//' \
    | awk -F/ '$2=="open"{v=$7; for(i=8;i<NF;i++) v=v"/"$i; printf "%s/%s %s %s\n",$1,$3,$5,v}' >"$list"
  local n; n=$(wc -l <"$list" | tr -d ' ')
  cp "$list" "$LOG_DIR/open_ports.txt"
  if (( n > 0 )); then
    add_finding "Open TCP ports and services" "tcp://$HOST" "Port and service assessment" INFORMATIONAL \
      "Informational observation" "Nmap identified $n open port(s) among the scanned set." "$(cat "$list")" "nmap" High \
      "Close or firewall services that do not need to be reachable; keep only required ports exposed." \
      "Reachability depends on the scanning vantage point and any rate-limiting or IDS."
    while read -r pp svc _rest; do
      local pn=${pp%%/*} sev="" title="" desc=""
      case $pn in
        21)  sev=LOW;    title="FTP service exposed (cleartext protocol)";  desc="FTP transmits credentials and data unencrypted." ;;
        23)  sev=HIGH;   title="Telnet service exposed";                    desc="Telnet is an unencrypted remote administration protocol." ;;
        445) sev=MEDIUM; title="SMB service exposed";                       desc="SMB reachable from the testing vantage point increases attack surface." ;;
        3389) sev=MEDIUM; title="RDP service exposed";                      desc="Remote Desktop exposed to the network is a frequent attack target." ;;
        5900) sev=MEDIUM; title="VNC service exposed";                      desc="VNC is often weakly authenticated and unencrypted." ;;
        2375) sev=HIGH;  title="Docker remote API port exposed";            desc="An unauthenticated Docker API grants host-level control." ;;
        1433|3306|5432|6379|9200|27017) sev=MEDIUM; title="Database/datastore service exposed ($svc)"; desc="Data stores should not be reachable from untrusted networks." ;;
      esac
      if [[ -n $sev ]]; then
        add_finding "$title" "tcp://$HOST:$pn" "Exposed network service" "$sev" "Potential vulnerability" "$desc" \
          "$pp $svc" "nmap" Medium "Restrict the service with firewall rules or bind it to localhost/internal networks; require strong authentication and encryption." \
          "The exposure may be intentional for this host (e.g. a lab). Confirm business need."
      fi
    done <"$list"
    awk '{print $2}' "$list" | sort -u | sed 's/^/Service: /' >>"$TECH_FILE"
  fi
  MODULE_DETAIL="$n open port(s)"
  return "$rc"
}
