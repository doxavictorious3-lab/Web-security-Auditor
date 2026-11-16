# shellcheck shell=bash
# DOXA module: tls (ported from v1.0.0, hardened for v2.0)
shopt -u patsub_replacement 2>/dev/null || true

openssl_proto() { # tls1|tls1_1|tls1_2|tls1_3|ssl3 -> 0 supported, 1 rejected, 2 untestable
  local out; local -a extra=()
  case $1 in tls1|tls1_1|ssl3) extra=(-cipher 'ALL:@SECLEVEL=0') ;; esac
  out=$(timeout 15 openssl s_client -connect "$HOST_URL:$HTTPS_PORT" "${SNI_ARGS[@]}" "-$1" "${extra[@]}" </dev/null 2>&1)
  grep -qiE 'unknown option|unsupported protocol|no protocols available|invalid command|unrecognized option' <<<"$out" && return 2
  grep -qE 'New, [^(]*, Cipher is [A-Za-z0-9_-]+' <<<"$out" && return 0
  return 1
}

check_tls() {
  local hs="$OUTDIR/logs/tls_handshake.txt" leaf="$TMPD/leaf.pem" url="https://$HOST_URL:$HTTPS_PORT"
  if (( ! HTTPS_OK && ! HTTPS_PRESENT )); then MODULE_STATUS=SKIPPED; MODULE_DETAIL="target does not serve HTTPS"; return 0; fi
  scope_assert_url "$url/" || return 1
  SNI_ARGS=(); (( IS_IP )) || SNI_ARGS=(-servername "$HOST")
  TLS_CA_ARGS=(); [[ -n ${CA_CERT:-} ]] && TLS_CA_ARGS=(-CAfile "$CA_CERT")
  timeout 25 openssl s_client -connect "$HOST_URL:$HTTPS_PORT" "${SNI_ARGS[@]}" "${TLS_CA_ARGS[@]}" -showcerts </dev/null >"$hs" 2>&1
  if ! grep -q 'BEGIN CERTIFICATE' "$hs"; then MODULE_DETAIL="TLS handshake failed; see logs/tls_handshake.txt"; return 1; fi
  openssl x509 <"$hs" >"$leaf" 2>/dev/null
  local subject issuer nb na exp_epoch days="" vr vcode vmsg
  subject=$(openssl x509 -in "$leaf" -noout -subject 2>/dev/null | sed 's/^subject= *//')
  issuer=$(openssl x509 -in "$leaf" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
  nb=$(openssl x509 -in "$leaf" -noout -startdate 2>/dev/null | cut -d= -f2)
  na=$(openssl x509 -in "$leaf" -noout -enddate 2>/dev/null | cut -d= -f2)
  exp_epoch=$(date -d "$na" +%s 2>/dev/null) && days=$(( (exp_epoch - $(date +%s)) / 86400 ))
  vr=$(grep -m1 'Verify return code:' "$hs")
  vcode=$(sed -nE 's/.*code: ([0-9]+).*/\1/p' <<<"$vr"); vmsg=$(sed -nE 's/.*\((.*)\).*/\1/p' <<<"$vr")
  local proto cipher
  proto=$(grep -m1 -E '^ *Protocol *:' "$hs" | sed 's/.*: *//'); cipher=$(grep -m1 -E '^ *Cipher *:' "$hs" | sed 's/.*: *//')
  local certinfo="Subject: $subject
Issuer: $issuer
Valid from: $nb
Valid until: $na (${days:-?} days remaining)
Negotiated: ${proto:-?} / ${cipher:-?}
Verification: ${vr:-n/a}"
  add_finding "TLS certificate information" "$url" "TLS configuration" INFORMATIONAL "Informational observation" \
    "Certificate and negotiated parameters of the HTTPS service." "$certinfo" "openssl" High "No action required." ""

  if ! openssl x509 -in "$leaf" -noout -checkend 0 >/dev/null 2>&1; then
    add_finding "TLS certificate has expired" "$url" "TLS configuration" HIGH "Confirmed vulnerability" \
      "The certificate expired on $na. Browsers show security errors and users may be trained to ignore warnings." "$certinfo" "openssl" High \
      "Renew and deploy a valid certificate; automate renewal (e.g. ACME)." ""
  elif [[ -n $days ]] && (( days <= 14 )); then
    add_finding "TLS certificate expires within 14 days" "$url" "TLS configuration" MEDIUM "Confirmed vulnerability" \
      "The certificate expires in $days day(s)." "Valid until: $na" "openssl" High "Renew the certificate and automate renewal." ""
  elif [[ -n $days ]] && (( days <= 30 )); then
    add_finding "TLS certificate expires within 30 days" "$url" "TLS configuration" LOW "Confirmed vulnerability" \
      "The certificate expires in $days day(s)." "Valid until: $na" "openssl" High "Renew the certificate and automate renewal." ""
  fi
  if [[ -n $vcode && $vcode != 0 && $vcode != 10 ]]; then
    add_finding "TLS certificate is not trusted ($vmsg)" "$url" "TLS configuration" MEDIUM "Confirmed vulnerability" \
      "Certificate validation against the system trust store failed: $vmsg." "$vr" "openssl" High \
      "Install a certificate issued by a trusted CA with the full chain." "Expected for lab targets using self-signed or internal CAs that are not in Kali's trust store."
  fi
  local ch
  if (( IS_IP )); then ch=$(openssl x509 -in "$leaf" -noout -checkip "$HOST" 2>&1); else ch=$(openssl x509 -in "$leaf" -noout -checkhost "$HOST" 2>&1); fi
  if grep -qi 'does NOT match' <<<"$ch"; then
    add_finding "TLS certificate does not match hostname" "$url" "TLS configuration" MEDIUM "Confirmed vulnerability" \
      "The certificate is not valid for $HOST, so clients will reject it or warn." "$ch" "openssl" High "Issue a certificate whose SAN covers $HOST." ""
  fi
  local sig keyinfo bits
  sig=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null | grep -m1 'Signature Algorithm' | sed 's/^ *//')
  if grep -qiE 'sha1With|md5With|md2With' <<<"$sig"; then
    add_finding "Certificate uses a weak signature algorithm" "$url" "TLS configuration" MEDIUM "Confirmed vulnerability" \
      "The certificate is signed with a deprecated hash algorithm." "$sig" "openssl" High "Reissue the certificate with SHA-256 or stronger." ""
  fi
  keyinfo=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null | grep -m1 -E 'Public-Key:')
  bits=$(sed -nE 's/.*\(([0-9]+) bit\).*/\1/p' <<<"$keyinfo")
  if [[ -n $bits ]] && [[ $(openssl x509 -in "$leaf" -noout -text 2>/dev/null) == *rsaEncryption* ]] && (( bits < 2048 )); then
    add_finding "Certificate uses a short RSA key ($bits bits)" "$url" "TLS configuration" MEDIUM "Confirmed vulnerability" \
      "RSA keys below 2048 bits are considered weak." "$keyinfo" "openssl" High "Reissue with an RSA key of at least 2048 bits (or ECDSA P-256)." ""
  fi

  # Protocol support: sslyze > nmap > openssl
  local -a legacy=(); local method="" untested=""
  if have sslyze; then
    run_tool sslyze "$TOOL_TIMEOUT" "$LOG_DIR/sslyze.log" sslyze --json_out="$OUTDIR/logs/sslyze.json" "$HOST_URL:$HTTPS_PORT" || true
    if [[ -s $OUTDIR/logs/sslyze.json ]] && jq -e '.server_scan_results[0].scan_result | has("tls_1_2_cipher_suites")' "$OUTDIR/logs/sslyze.json" >/dev/null 2>&1; then
      method=sslyze
      mapfile -t legacy < <(jq -r '.server_scan_results[0].scan_result | to_entries[]
        | select(.key | test("^(ssl_2_0|ssl_3_0|tls_1_0|tls_1_1)_cipher_suites$"))
        | select((.value.result.accepted_cipher_suites | length) > 0) | .key
        | sub("_cipher_suites";"") | sub("ssl_2_0";"SSLv2") | sub("ssl_3_0";"SSLv3") | sub("tls_1_0";"TLSv1.0") | sub("tls_1_1";"TLSv1.1")' "$OUTDIR/logs/sslyze.json")
    fi
  fi
  if [[ -z $method ]] && have nmap; then
    run_tool nmap-tls "$TOOL_TIMEOUT" "$LOG_DIR/nmap_tls.log" nmap -Pn $( ((IS_IPV6)) && echo -6 ) --max-rate "$RATE" -p "$HTTPS_PORT" --script ssl-enum-ciphers -oN "$OUTDIR/nmap/nmap_ssl_enum.txt" "$HOST" || true
    if grep -q 'ssl-enum-ciphers' "$OUTDIR/nmap/nmap_ssl_enum.txt" 2>/dev/null; then
      method=nmap
      mapfile -t legacy < <(grep -oE '^\|   (SSLv3|TLSv1\.0|TLSv1\.1):' "$OUTDIR/nmap/nmap_ssl_enum.txt" | tr -d '| :')
      local weak; weak=$(grep -iE 'vulnerable to|weak|broken|least strength: [CDEF]' "$OUTDIR/nmap/nmap_ssl_enum.txt" | sed 's/^| *//' | sort -u | head -8)
      if [[ -n $weak ]]; then
        add_finding "Weak TLS cipher suites or grades reported" "$url" "TLS configuration" MEDIUM "Potential vulnerability" \
          "Nmap ssl-enum-ciphers reported weak ciphers or low strength grades." "$weak" "nmap" Medium \
          "Disable weak ciphers (3DES, RC4, export, NULL) and prefer AEAD suites with forward secrecy." "Grades depend on nmap's ruleset; verify with a dedicated TLS scanner."
      fi
    fi
  fi
  if [[ -z $method ]]; then
    method=openssl; local pr
    for pr in ssl3:SSLv3 tls1:TLSv1.0 tls1_1:TLSv1.1; do
      openssl_proto "${pr%%:*}"; case $? in 0) legacy+=("${pr##*:}") ;; 2) untested+="${pr##*:} " ;; esac
    done
    [[ -n $untested ]] && LIMITS+=("Legacy TLS protocols ($untested) could not be tested with the local OpenSSL client; install sslyze or nmap for full protocol coverage.")
  fi
  local lp
  for lp in "${legacy[@]}"; do
    case $lp in
      SSLv2|SSLv3) add_finding "Insecure protocol supported: $lp" "$url" "TLS configuration" HIGH "Confirmed vulnerability" \
        "The server accepts $lp, which is cryptographically broken." "Accepted protocol: $lp (via $method)" "$method" High \
        "Disable SSLv2/SSLv3 and allow only TLS 1.2 and TLS 1.3." "" ;;
      *) add_finding "Deprecated protocol supported: $lp" "$url" "TLS configuration" MEDIUM "Confirmed vulnerability" \
        "The server accepts $lp, which is deprecated (RFC 8996) and weakens transport security." "Accepted protocol: $lp (via $method)" "$method" High \
        "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and TLS 1.3." "Some legacy clients may break when disabled." ;;
    esac
  done
  local s12=1 s13=1
  openssl_proto tls1_2; s12=$?; openssl_proto tls1_3; s13=$?
  if [[ $s12 -eq 1 && $s13 -eq 1 ]]; then
    add_finding "Server does not support TLS 1.2 or 1.3" "$url" "TLS configuration" HIGH "Potential vulnerability" \
      "Neither TLS 1.2 nor TLS 1.3 negotiation succeeded in testing." "Protocol probes failed for TLS 1.2 and 1.3" "openssl" Low \
      "Enable TLS 1.2 and 1.3." "Probe may fail because of network filtering or client-side limitations; verify with sslyze."
  fi
  MODULE_DETAIL="protocols checked via $method; ${#legacy[@]} legacy protocol(s) accepted; ${days:-?} days to expiry"
  return 0
}
