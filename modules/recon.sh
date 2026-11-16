# shellcheck shell=bash
# DOXA module: recon (ported from v1.0.0, hardened for v2.0)
shopt -u patsub_replacement 2>/dev/null || true

collect_recon() {
  local f=$RECON_FILE u t code title
  {
    printf 'DOXA Web Security Auditor - Reconnaissance\n'
    printf 'Generated : %s\nTarget    : %s\nHost      : %s\nResolved  : %s\n\n' "$(date -u '+%F %T UTC')" "$TARGET_URL" "$HOST" "${IPS[*]}"
    echo "== DNS records =="
    if (( IS_IP )); then
      echo "(target is an IP address; forward DNS skipped)"
      if have dig; then echo "-- PTR"; dig +short +time=3 +tries=1 -x "$HOST" 2>&1; fi
    elif have dig; then
      for t in A AAAA CNAME NS MX TXT CAA SOA; do echo "-- $t"; dig +short +time=3 +tries=1 "$HOST" "$t" 2>&1; done
    else
      echo "(dig not installed; resolver output only)"; getent ahosts "$HOST"
    fi
    echo; echo "== HTTP/HTTPS service detection =="
  } >>"$f"

  local -a cands=()
  [[ -n $HTTP_BASE ]] && cands+=("$HTTP_BASE")
  [[ -n $HTTPS_BASE ]] && cands+=("$HTTPS_BASE")
  HTTP_OK=0; HTTPS_OK=0; HTTPS_PRESENT=0
  for u in "${cands[@]}"; do
    http_fetch "$u/" probe
    printf '%-34s HTTP %s%s\n' "$u" "$FETCH_CODE" "${FETCH_ERR:+  ($FETCH_ERR)}" >>"$f"
    if [[ $FETCH_ERR == tls-verification-failed && $u == https://* ]]; then HTTPS_PRESENT=1; fi
    if [[ $FETCH_CODE != 000 ]]; then
      redact_headers <"$FETCH_HDR" >"$LOG_DIR/headers_${u%%:*}.txt"
      if [[ $u == https://* ]]; then HTTPS_OK=1; else HTTP_OK=1; fi
      case $FETCH_CODE in 301|302|303|307|308)
        follow_chain "$u/" >>"$f"
        if (( CHAIN_DOWNGRADE )); then
          add_finding "HTTPS redirects to unencrypted HTTP" "$u/" "Transport security" MEDIUM "Confirmed vulnerability" \
            "A redirect chain starting on HTTPS leads to an http:// URL, downgrading the connection." "$(sed -n '1,12p' "$f" | tail -6)" "curl" High \
            "Redirect only to HTTPS URLs and enable HSTS." "" ;
        fi
        if [[ -n $CHAIN_BLOCKED ]]; then
          add_finding "Redirect was not followed: $CHAIN_BLOCKED" "$u/" "Reconnaissance" INFORMATIONAL "Informational observation" \
            "DOXA stopped at a redirect that leaves the approved scope (or exceeded the redirect policy). Nothing outside the scope was requested." \
            "$CHAIN_BLOCKED" "doxa-scope" High "To assess the redirect destination, add it explicitly with --scope-host after confirming authorization." "" ;
        fi ;;
      esac
    fi
  done

  if [[ $SCHEME == https && $HTTPS_OK -eq 1 ]]; then SCAN_BASE=$HTTPS_BASE
  elif [[ $SCHEME == http && $HTTP_OK -eq 1 ]]; then SCAN_BASE=$HTTP_BASE
  elif (( HTTPS_OK )); then SCAN_BASE=$HTTPS_BASE
  elif (( HTTP_OK )); then SCAN_BASE=$HTTP_BASE
  else SCAN_BASE=""; fi

  if [[ -z $SCAN_BASE ]]; then
    MODULE_DETAIL="no HTTP(S) response from $HOST (check URL, port, firewall)"
    if (( HTTPS_PRESENT )); then
      MODULE_DETAIL="HTTPS certificate validation failed; web modules skipped. Use --ca-cert FILE for a lab CA, or --insecure-tls-diagnostic (authorized diagnostics only)"
      add_finding "TLS certificate validation failed" "$HTTPS_BASE/" "TLS configuration" MEDIUM "Confirmed vulnerability" \
        "The HTTPS endpoint presented a certificate that could not be validated against the trust store, so DOXA refused to send web requests over it." \
        "curl exit code $FETCH_RC (tls-verification-failed)" "curl" High \
        "Install a certificate from a trusted CA with a complete chain that matches the hostname." \
        "Expected for lab targets that use self-signed certificates; supply --ca-cert for those."
    fi
    echo "RESULT: no web service responded" >>"$f"
    return 1
  fi
  WEB_OK=1; SCAN_URL="$SCAN_BASE$PATH_PREFIX"
  http_fetch "$SCAN_BASE/" root
  ROOT_HDR=$FETCH_HDR; ROOT_BODY=$FETCH_BODY; ROOT_URL="$SCAN_BASE/"; COOKIE_HDR=$ROOT_HDR; ROOT_CODE=$FETCH_CODE
  case $FETCH_CODE in
    301|302|303|307|308)
      # Security headers on a bare redirect say little: analyse the final in-scope page, and keep
      # Set-Cookie headers from every hop (sessions are usually created on the first response).
      CHAIN_ALL_HDR="$TMPD/chain_all.hdr"; : >"$CHAIN_ALL_HDR"
      { echo; echo "== Root redirect chain (scope-checked hops) =="; follow_chain "$SCAN_BASE/"; } >>"$f"
      CHAIN_ALL_HDR=""
      COOKIE_HDR="$TMPD/chain_all.hdr"
      if [[ $CHAIN_FINAL_CODE == 2* ]]; then
        cp "$FETCH_HDR" "$TMPD/rootfinal.hdr"; cp "$FETCH_BODY" "$TMPD/rootfinal.body"
        ROOT_HDR="$TMPD/rootfinal.hdr"; ROOT_BODY="$TMPD/rootfinal.body"; ROOT_URL=$CHAIN_FINAL_URL; ROOT_CODE=$CHAIN_FINAL_CODE
      fi ;;
  esac
  SERVER_HDR=$(hget "$ROOT_HDR" server)
  PAGE_TITLE=$(grep -aoiE '<title[^>]*>[^<]{0,200}' "$ROOT_BODY" | head -1 | sed -E 's/<[^>]*>//')
  {
    echo; echo "== Analysed page: ${ROOT_URL} (HTTP ${ROOT_CODE}) =="
    echo "Server header : ${SERVER_HDR:-<none>}"
    echo "X-Powered-By  : $(hget "$ROOT_HDR" x-powered-by)"
    echo "Content-Type  : $(hget "$ROOT_HDR" content-type)"
    echo "Page title    : ${PAGE_TITLE:-<none>}"
    echo; echo "-- Response headers (cookie values redacted)"; redact_headers <"$ROOT_HDR"
  } >>"$f"
  [[ -n $SERVER_HDR ]] && echo "Server: $SERVER_HDR" >>"$TECH_FILE"
  local xp gen
  xp=$(hget "$ROOT_HDR" x-powered-by); [[ -n $xp ]] && echo "X-Powered-By: $xp" >>"$TECH_FILE"
  gen=$(grep -aoiE '<meta[^>]+name=.generator.[^>]*>' "$ROOT_BODY" | head -1 | sed -E 's/.*content="?([^">]*).*/\1/I')
  [[ -n $gen ]] && echo "Generator: $gen" >>"$TECH_FILE"

  # Soft-404 baseline used to cut false positives
  http_fetch "$SCAN_BASE/doxa-${RANDOM}${RANDOM}-nonexistent" b404
  B404_CODE=$FETCH_CODE
  B404_LEN=$(wc -c <"$FETCH_BODY" | tr -d ' ')
  B404_MD5=$(md5sum <"$FETCH_BODY" | cut -d' ' -f1)
  echo "Soft-404 baseline: HTTP $B404_CODE, $B404_LEN bytes" >>"$f"
  if [[ $B404_CODE == 200 ]]; then
    add_finding "Server returns HTTP 200 for non-existent pages (soft-404)" "$SCAN_BASE" "Reconnaissance" INFORMATIONAL \
      "Informational observation" "Requests for random non-existent paths return HTTP 200, which inflates directory-brute-force and scanner false positives." \
      "GET /doxa-random-nonexistent -> HTTP 200 ($B404_LEN bytes)" "curl" High \
      "No action required; consider returning proper 404 status codes." \
      "DOXA filters results matching this baseline, but manual verification of discovered paths is still advised."
  fi

  # robots.txt
  http_fetch "$SCAN_BASE/robots.txt" robots
  if [[ $FETCH_CODE == 200 ]] && grep -qiE '^(user-agent|disallow|allow|sitemap):' "$FETCH_BODY"; then
    local dis sens
    dis=$(tr -d '\r' <"$FETCH_BODY" | grep -iE '^disallow:' | sort -u | head -30)
    { echo; echo "== robots.txt (accessible) =="; tr -d '\r' <"$FETCH_BODY" | head -60; } >>"$f"
    sens=$(grep -iE 'admin|backup|private|secret|config|login|internal|staging|sql|\.git|dump' <<<"$dis" | head -10)
    if [[ -n $sens ]]; then
      add_finding "robots.txt references sensitive-looking paths" "$SCAN_BASE/robots.txt" "Information disclosure" LOW \
        "Potential vulnerability" "robots.txt is public and lists paths that suggest administrative, backup or internal content, which helps attackers prioritise targets." \
        "$sens" "curl" Medium "Do not rely on robots.txt to hide content; protect sensitive paths with authentication and remove revealing entries." \
        "Paths may be harmless or decoys. Verify whether the listed resources are actually reachable."
    else
      add_finding "robots.txt is publicly accessible" "$SCAN_BASE/robots.txt" "Reconnaissance" INFORMATIONAL \
        "Informational observation" "robots.txt exists and lists crawler directives." "$dis" "curl" High \
        "No action required." ""
    fi
  else
    echo; echo "robots.txt: not found (HTTP $FETCH_CODE)" >>"$f"
  fi

  # sitemap.xml
  http_fetch "$SCAN_BASE/sitemap.xml" sitemap
  if [[ $FETCH_CODE == 200 ]] && grep -qiE '<urlset|<sitemapindex' "$FETCH_BODY"; then
    local n; n=$(grep -aoiE '<loc>' "$FETCH_BODY" | wc -l | tr -d ' ')
    { echo; echo "== sitemap.xml (accessible, $n entries) =="; grep -aoiE '<loc>[^<]+' "$FETCH_BODY" | sed 's/<loc>//I' | head -25; } >>"$f"
    add_finding "sitemap.xml is publicly accessible" "$SCAN_BASE/sitemap.xml" "Reconnaissance" INFORMATIONAL \
      "Informational observation" "A sitemap with $n entries is published." "$(grep -aoiE '<loc>[^<]+' "$FETCH_BODY" | sed 's/<loc>//I' | head -10)" \
      "curl" High "No action required unless the sitemap exposes non-public URLs." ""
  else
    echo "sitemap.xml: not found (HTTP $FETCH_CODE)" >>"$f"
  fi

  add_finding "Web service identified" "$SCAN_BASE" "Reconnaissance" INFORMATIONAL "Informational observation" \
    "HTTP(S) service reachable. Server: ${SERVER_HDR:-unknown}. HTTP available: $HTTP_OK, HTTPS available: $HTTPS_OK." \
    "Title: ${PAGE_TITLE:-n/a}; Resolved IPs: ${IPS[*]}" "curl" High "No action required." ""
  MODULE_DETAIL="HTTP=$HTTP_OK HTTPS=$HTTPS_OK server=${SERVER_HDR:-unknown}"
  return 0
}
