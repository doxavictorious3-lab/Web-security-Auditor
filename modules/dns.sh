# shellcheck shell=bash
# DOXA module: dns - DNS inspection, subdomain discovery and takeover INDICATORS.
#
#  * record inspection and basic configuration checks (SPF, DMARC, CAA, nameservers) are passive lookups
#  * subdomain enumeration (built-in wordlist) is an ACTIVE step and is skipped in passive mode; it only
#    queries names under the approved host, never the discovered hosts' web servers unless they are in scope
#  * takeover findings are always INDICATORS ("Potential vulnerability"); DOXA never tries to claim a resource
#  * zone-transfer (AXFR) attempts contact the authoritative nameservers and therefore need manual approval
shopt -u patsub_replacement 2>/dev/null || true

DNS_PASSIVE_SOURCES=${DNS_PASSIVE_SOURCES:-0}
DNS_PROV="" DNS_SIG=""

dns_q() { # name type -> values, one per line
  rate_wait
  dig +short +time=2 +tries=1 "$1" "$2" 2>>"${LOG_DIR:-/dev/null}/dns.err" | tr -d '\r' | grep -v '^;' | grep -v '^$'
}
dns_status() { # name -> NOERROR / NXDOMAIN / SERVFAIL ...
  rate_wait
  dig +noall +comments +time=2 +tries=1 "$1" A 2>/dev/null | sed -nE 's/.*status: ([A-Z]+).*/\1/p' | head -1
}
dns_name_ok() { scope_host_ok "$1" || [[ $1 == *".$HOST" ]]; }

# dns_provider TARGET -> DNS_PROV DNS_SIG (provider name and an error-page signature, when known)
dns_provider() {
  DNS_PROV=""; DNS_SIG=""
  case ${1,,} in
    *.github.io) DNS_PROV="GitHub Pages"; DNS_SIG="There isn't a GitHub Pages site here" ;;
    *.herokuapp.com|*.herokudns.com) DNS_PROV="Heroku"; DNS_SIG="No such app" ;;
    *.s3.amazonaws.com|*.s3-website*.amazonaws.com) DNS_PROV="Amazon S3"; DNS_SIG="NoSuchBucket|The specified bucket does not exist" ;;
    *.azurewebsites.net|*.cloudapp.net|*.trafficmanager.net|*.blob.core.windows.net) DNS_PROV="Microsoft Azure" ;;
    *.cloudfront.net) DNS_PROV="Amazon CloudFront" ;;
    *.ghost.io) DNS_PROV="Ghost"; DNS_SIG="The thing you were looking for is no longer here" ;;
    *.surge.sh) DNS_PROV="Surge"; DNS_SIG="project not found" ;;
    *.netlify.app|*.netlify.com) DNS_PROV="Netlify"; DNS_SIG="Not Found - Request ID" ;;
    *.readme.io) DNS_PROV="Readme"; DNS_SIG="Project doesnt exist" ;;
    *.zendesk.com) DNS_PROV="Zendesk"; DNS_SIG="Help Center Closed" ;;
    *.pantheonsite.io) DNS_PROV="Pantheon"; DNS_SIG="404 error unknown site" ;;
    *.bitbucket.io) DNS_PROV="Bitbucket"; DNS_SIG="Repository not found" ;;
    *.myshopify.com) DNS_PROV="Shopify"; DNS_SIG="Sorry, this shop is currently unavailable" ;;
  esac
}

dns_takeover_report() { # sub cname-target dangling(0|1)
  local sub=$1 tgt=${2%.} dangling=$3 scheme
  dns_provider "$tgt"
  if (( dangling )); then
    if [[ -n $DNS_PROV ]]; then
      add_finding "Subdomain takeover indicator: $sub -> $tgt ($DNS_PROV)" "dns://$sub" "Subdomain takeover indicators" MEDIUM "Potential vulnerability" \
        "$sub is a CNAME to a $DNS_PROV resource that does not resolve (NXDOMAIN). If the resource name is unclaimed, a third party may be able to register it and serve content on your domain. DOXA did not attempt to claim it." \
        "$sub CNAME $tgt; DNS status of the target: NXDOMAIN" "doxa-dns" Medium \
        "Remove the dangling DNS record, or re-create the resource at the provider." \
        "Some providers reserve names or require domain verification, which prevents takeover. Verify with the provider documentation."
    else
      add_finding "Dangling CNAME record: $sub -> $tgt" "dns://$sub" "Subdomain takeover indicators" LOW "Potential vulnerability" \
        "$sub is a CNAME to a name that does not resolve (NXDOMAIN). Dangling records are a prerequisite for subdomain takeover." \
        "$sub CNAME $tgt; DNS status of the target: NXDOMAIN" "doxa-dns" Low \
        "Remove DNS records that point at decommissioned names." \
        "Takeover is only possible when the target namespace can be registered by a third party."
    fi
  elif [[ -n $DNS_PROV && -n $DNS_SIG ]] && scope_host_ok "$sub"; then
    for scheme in https http; do
      http_fetch "$scheme://$sub/" takeover
      [[ $FETCH_CODE == 000 ]] && continue
      if grep -aqE "$DNS_SIG" "$FETCH_BODY"; then
        add_finding "Subdomain takeover indicator: $DNS_PROV error page on $sub" "$scheme://$sub/" "Subdomain takeover indicators" MEDIUM "Potential vulnerability" \
          "$sub points at $DNS_PROV and the provider returns its 'unclaimed resource' page. This is a strong indicator that the resource can be claimed. DOXA did not attempt to claim it." \
          "$sub CNAME $tgt; provider unclaimed-resource signature observed (HTTP $FETCH_CODE)" "doxa-dns" High \
          "Remove the DNS record or re-create the resource at the provider." \
          "Error pages can be shown for legitimately configured but empty sites. Confirm in the provider console."
        return 0
      fi
    done
  fi
}

dns_check_mail() { # HOST MX-values TXT-values
  local has_mx=0 spf all dm
  [[ -n $2 ]] && has_mx=1
  spf=$(grep -i 'v=spf1' <<<"$3" | head -1)
  if [[ -n $spf ]]; then
    all=$(grep -oiE '[+?~-]?all' <<<"$spf" | tail -1)
    case ${all,,} in
      +all|all) add_finding "SPF record allows any sender (+all)" "dns://$HOST" "DNS configuration" MEDIUM "Confirmed vulnerability" \
        "The SPF record ends with +all, authorising every server on the internet to send mail as this domain." "TXT: ${spf}" "doxa-dns" High \
        "Use -all or ~all with an explicit list of authorised senders." "" ;;
      '?all') add_finding "SPF record uses neutral qualifier (?all)" "dns://$HOST" "DNS configuration" LOW "Confirmed vulnerability" \
        "A neutral SPF policy gives receivers no instruction about unauthorised senders." "TXT: ${spf}" "doxa-dns" High "Use ~all or -all." "" ;;
    esac
  elif (( has_mx )); then
    add_finding "Mail-enabled host without SPF record" "dns://$HOST" "DNS configuration" LOW "Potential vulnerability" \
      "The host publishes MX records but no SPF record, making sender spoofing easier." "MX: $(tr '\n' ' ' <<<"$2")" "doxa-dns" Medium \
      "Publish an SPF record listing the authorised senders." "Only relevant if the host is used to send mail."
  fi
  dm=$(dns_q "_dmarc.$HOST" TXT | grep -i 'v=DMARC1' | head -1)
  if (( has_mx )) && [[ -z $dm ]]; then
    add_finding "Mail-enabled host without DMARC record" "dns://_dmarc.$HOST" "DNS configuration" LOW "Potential vulnerability" \
      "No DMARC policy is published, so receivers cannot be told how to treat spoofed mail." "no TXT record at _dmarc.$HOST" "doxa-dns" Medium \
      "Publish a DMARC record (start with p=none and reporting, then move to quarantine/reject)." "DMARC may be published at the organisational domain instead."
  elif [[ ${dm,,} == *"p=none"* ]]; then
    add_finding "DMARC policy is monitoring only (p=none)" "dns://_dmarc.$HOST" "DNS configuration" INFORMATIONAL "Informational observation" \
      "DMARC is published with p=none, so spoofed mail is reported but not blocked." "TXT: $dm" "doxa-dns" High \
      "Move to p=quarantine or p=reject once legitimate senders are aligned." ""
  fi
}

run_dns() {
  if (( IS_IP )); then MODULE_STATUS=SKIPPED; MODULE_DETAIL="target is an IP address (no DNS names to inspect)"; return 0; fi
  scope_assert_host "$HOST" || return 1
  local rec="$LOG_DIR/dns_records.txt" sub="$LOG_DIR/subdomains.txt" t vals n0 n1 ns_n
  local -A R=() FOUND=() WC=()
  : >"$rec"; : >"$sub"; n0=$(count_findings)
  for t in A AAAA CNAME NS MX TXT CAA SOA; do
    vals=$(dns_q "$HOST" "$t"); R[$t]=$vals
    { printf '== %s %s ==\n' "$HOST" "$t"; printf '%s\n\n' "${vals:-(none)}"; } >>"$rec"
  done
  if [[ -z ${R[A]}${R[AAAA]}${R[CNAME]} ]]; then
    MODULE_DETAIL="no A, AAAA or CNAME records returned for $HOST (resolver problem or name does not exist)"; return 1
  fi
  ns_n=$(grep -c . <<<"${R[NS]}")
  if (( ns_n == 1 )); then
    add_finding "Only one authoritative nameserver" "dns://$HOST" "DNS configuration" LOW "Potential vulnerability" \
      "A single nameserver is a resilience risk: if it fails, the domain stops resolving." "NS: ${R[NS]}" "doxa-dns" Medium \
      "Publish at least two nameservers on separate networks." "Managed DNS providers may present one name that is internally redundant."
  fi
  if [[ -z ${R[CAA]} && -z ${R[CNAME]} && $ns_n -gt 0 ]]; then
    add_finding "No CAA record published" "dns://$HOST" "DNS configuration" INFORMATIONAL "Informational observation" \
      "Without CAA records any certificate authority may issue certificates for this name." "no CAA records for $HOST" "doxa-dns" Medium \
      "Publish CAA records for the certificate authorities you use." ""
  fi
  dns_check_mail "$HOST" "${R[MX]}" "${R[TXT]}"
  # wildcard DNS
  local wc_vals; wc_vals=$(dns_q "doxa-wc-$RANDOM$RANDOM.$HOST" A)
  if [[ -n $wc_vals ]]; then
    while IFS= read -r t; do WC[$t]=1; done <<<"$wc_vals"
    add_finding "Wildcard DNS record detected" "dns://$HOST" "DNS configuration" INFORMATIONAL "Informational observation" \
      "Random non-existent labels resolve, so every subdomain appears to exist. Subdomain results matching the wildcard are filtered out." \
      "doxa-wc-<random>.$HOST -> $(tr '\n' ' ' <<<"$wc_vals")" "doxa-dns" High "No action required unless unintended." ""
  fi
  # dangling CNAME on the target itself
  if [[ -n ${R[CNAME]} ]]; then
    local tgt=${R[CNAME]%%$'\n'*}
    [[ $(dns_status "${tgt%.}") == NXDOMAIN ]] && dns_takeover_report "$HOST" "$tgt" 1 || dns_takeover_report "$HOST" "$tgt" 0
  fi
  # names disclosed in the TLS certificate (passive)
  local hs="$LOG_DIR/tls_handshake.txt" san="" s
  if [[ -s $hs ]] && have openssl; then
    san=$(openssl x509 -noout -ext subjectAltName <"$hs" 2>/dev/null | grep -oE 'DNS:[^, ]+' | sed 's/DNS://' | sort -u)
  fi
  if [[ -n $san ]]; then
    add_finding "Hostnames disclosed in the TLS certificate ($(grep -c . <<<"$san"))" "$SCAN_BASE" "Information disclosure" INFORMATIONAL "Informational observation" \
      "The certificate lists these names. Related hosts are useful reconnaissance leads." "$(head -30 <<<"$san")" "openssl" High \
      "Avoid placing internal or staging host names on public certificates." ""
    while IFS= read -r s; do
      [[ -n $s && $s != \** ]] && dns_name_ok "$s" && [[ $s != "$HOST" ]] && FOUND[$s]="certificate"
    done <<<"$san"
  fi
  # active subdomain enumeration (not in passive mode)
  local wl="$DOXA_HOME/config/subdomains.txt" w name av words=0 hits=0
  if [[ $MODE != passive && -r $wl ]]; then
    local limit=60; [[ $MODE == full ]] && limit=1000
    while IFS= read -r w; do
      [[ $w =~ ^[a-z0-9-]+$ ]] || continue
      words=$((words + 1)); (( words > limit )) && break
      name="$w.$HOST"
      av=$(dns_q "$name" A); [[ -n $av ]] || continue
      if (( ${#WC[@]} )); then
        local only_wc=1; while IFS= read -r t; do [[ -n ${WC[$t]:-} ]] || only_wc=0; done <<<"$av"
        (( only_wc )) && continue
      fi
      FOUND[$name]="wordlist"; hits=$((hits + 1))
    done <"$wl"
  elif [[ $MODE == passive ]]; then
    LIMITS+=("Passive mode: subdomain enumeration by wordlist was not performed (only certificate names were used).")
  fi
  # optional third-party passive sources (sends the domain name to external services; explicit opt-in)
  if (( DNS_PASSIVE_SOURCES )); then
    if have subfinder; then
      run_tool subfinder 180 "$LOG_DIR/subfinder.log" subfinder -d "$HOST" -silent -passive || true
      while IFS= read -r s; do
        s=${s,,}; [[ $s =~ ^[a-z0-9.-]+$ ]] && dns_name_ok "$s" && [[ -n $(dns_q "$s" A) ]] && FOUND[$s]=${FOUND[$s]:-subfinder}
      done <"$LOG_DIR/subfinder.log"
    else
      LIMITS+=("--dns-passive-sources was requested but subfinder is not installed.")
    fi
  else
    LIMITS+=("Subdomain discovery did not use third-party passive data sources (enable with --dns-passive-sources; the domain name is sent to external services).")
  fi
  # resolve, record, check takeover indicators for every discovered name
  local name_list cn status
  name_list=$(printf '%s\n' "${!FOUND[@]}" | sort)
  while IFS= read -r name; do
    [[ -n $name ]] || continue
    av=$(dns_q "$name" A | tr '\n' ' ')
    printf '%s\t%s\t%s\n' "$name" "${FOUND[$name]}" "${av:-(no A record)}" >>"$sub"
    cn=$(dns_q "$name" CNAME | head -1)
    if [[ -n $cn ]]; then
      status=$(dns_status "${cn%.}")
      if [[ $status == NXDOMAIN ]]; then dns_takeover_report "$name" "$cn" 1; else dns_takeover_report "$name" "$cn" 0; fi
    fi
  done <<<"$name_list"
  local n_sub; n_sub=$(grep -c . "$sub")
  if (( n_sub > 0 )); then
    add_finding "Subdomains discovered ($n_sub)" "dns://$HOST" "Reconnaissance" INFORMATIONAL "Informational observation" \
      "Names found under the approved host by certificate names and DNS resolution. They were resolved but not scanned unless explicitly approved with --scope-host." \
      "$(cut -f1,2 "$sub" | head -40)" "doxa-dns" Medium \
      "Maintain an inventory of subdomains and remove records that are no longer needed." "Wordlist hits only prove the name resolves."
  fi
  # zone transfer: contacts nameservers outside the web scope, so it needs approval
  if [[ $MODE == full && -n ${R[NS]} ]]; then
    if require_approval "DNS zone transfer attempt (AXFR): sends a standard AXFR query for $HOST to its authoritative nameservers, which are outside the approved web scope. No data is stored."; then
      local ns out recs
      while IFS= read -r ns; do
        [[ -n $ns ]] || continue
        rate_wait
        out=$(timeout 20 dig +time=3 +tries=1 "@${ns%.}" "$HOST" AXFR 2>&1)
        recs=$(grep -cvE '^(;|$)' <<<"$out")
        if (( recs >= 3 )) && ! grep -qiE 'transfer failed|refused|timed out|no servers|connection' <<<"$out"; then
          add_finding "DNS zone transfer (AXFR) permitted by ${ns%.}" "dns://$HOST" "DNS configuration" HIGH "Confirmed vulnerability" \
            "The nameserver returned the zone to an unauthenticated client, disclosing every host name in it." \
            "AXFR $HOST @${ns%.}: $recs record(s) returned (content not stored)" "dig" High \
            "Restrict zone transfers to authorised secondary servers (allow-transfer / TSIG)." "" "" \
            "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" "Complete zone contents were returned to an unauthenticated client; no credentials or user data were involved, so impact is scored Low."
        fi
      done <<<"${R[NS]}"
    else
      LIMITS+=("DNS zone-transfer (AXFR) check was not run (manual approval not granted).")
    fi
  fi
  n1=$(count_findings)
  MODULE_DETAIL="${#R[@]} record types inspected, $n_sub subdomain(s), $((n1 - n0)) finding(s)"
  return 0
}
