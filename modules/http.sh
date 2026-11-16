# shellcheck shell=bash
# DOXA module: http (ported from v1.0.0, hardened for v2.0)
shopt -u patsub_replacement 2>/dev/null || true

HEADER_SPECS=(
  "content-security-policy|Missing Content-Security-Policy header|LOW|No CSP is set, so the browser has no policy limiting where scripts and other resources may load from, reducing defence against XSS.|Define a restrictive Content-Security-Policy (avoid unsafe-inline/unsafe-eval)."
  "x-content-type-options|Missing X-Content-Type-Options header|LOW|Without nosniff, browsers may MIME-sniff responses, enabling content-type confusion attacks.|Send X-Content-Type-Options: nosniff on all responses."
  "x-frame-options|Missing clickjacking protection (X-Frame-Options / frame-ancestors)|LOW|The page can be embedded in third-party frames, enabling clickjacking.|Send X-Frame-Options: DENY (or SAMEORIGIN) or a CSP frame-ancestors directive."
  "referrer-policy|Missing Referrer-Policy header|INFORMATIONAL|Full URLs may leak to other sites via the Referer header.|Send Referrer-Policy: strict-origin-when-cross-origin or stricter."
  "permissions-policy|Missing Permissions-Policy header|INFORMATIONAL|Browser features (camera, geolocation, etc.) are not explicitly restricted.|Send a Permissions-Policy header disabling unused features."
)

check_security_headers() {
  local ev v csp spec name title sev desc rem maxage
  ev=$(hdr_excerpt)
  csp=$(hget "$ROOT_HDR" content-security-policy)
  if [[ $SCAN_BASE == https://* ]]; then
    v=$(hget "$ROOT_HDR" strict-transport-security)
    if [[ -z $v ]]; then
      add_finding "Missing HTTP Strict-Transport-Security (HSTS) header" "${ROOT_URL:-$SCAN_BASE}" "Security headers" MEDIUM "Confirmed vulnerability" \
        "The HTTPS site does not send HSTS, so browsers may be downgraded to HTTP by a network attacker (SSL stripping)." "$ev" "curl" High \
        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS is fully deployed." \
        "Informational only if the site is never reachable over HTTP and is preloaded."
    else
      maxage=$(sed -nE 's/.*max-age=([0-9]+).*/\1/Ip' <<<"$v")
      if [[ -n $maxage ]] && (( maxage < 15552000 )); then
        add_finding "Weak HSTS max-age" "${ROOT_URL:-$SCAN_BASE}" "Security headers" LOW "Confirmed vulnerability" \
          "HSTS max-age is $maxage seconds (< 180 days), limiting its protection." "Strict-Transport-Security: $v" "curl" High \
          "Use max-age of at least 31536000 seconds." ""
      fi
    fi
  fi
  if [[ -n $csp ]] && grep -qiE "unsafe-inline|unsafe-eval|script-src[^;]*\*" <<<"$csp"; then
    add_finding "Weak Content-Security-Policy" "${ROOT_URL:-$SCAN_BASE}" "Security headers" LOW "Potential vulnerability" \
      "The CSP allows unsafe-inline/unsafe-eval or wildcard script sources, weakening XSS protection." "Content-Security-Policy: $csp" "curl" Medium \
      "Remove unsafe directives; use nonces or hashes and explicit source lists." "Some legacy applications cannot drop unsafe-inline immediately."
  fi
  for spec in "${HEADER_SPECS[@]}"; do
    IFS='|' read -r name title sev desc rem <<<"$spec"
    [[ -n $(hget "$ROOT_HDR" "$name") ]] && continue
    [[ $name == x-frame-options && $csp == *frame-ancestors* ]] && continue
    add_finding "$title" "${ROOT_URL:-$SCAN_BASE}" "Security headers" "$sev" "Confirmed vulnerability" "$desc" "$ev" "curl" High "$rem" \
      "Severity is context dependent; static or non-sensitive sites may accept this risk."
  done
  # Information disclosure headers
  local h val
  for h in server x-powered-by x-aspnet-version x-aspnetmvc-version x-generator x-runtime; do
    val=$(hget "$ROOT_HDR" "$h")
    [[ -n $val ]] || continue
    if [[ $val =~ [0-9]+\.[0-9]+ ]]; then
      add_finding "Version information disclosed in $h header" "${ROOT_URL:-$SCAN_BASE}" "Information disclosure" LOW "Confirmed vulnerability" \
        "The $h header discloses software and version details that help attackers select exploits." "$(tr -d '\r' <"$ROOT_HDR" | grep -i -m1 "^$h:")" "curl" High \
        "Remove or genericise version banners (e.g. ServerTokens Prod, server_tokens off, expose_php=Off)." \
        "Disclosure alone is not exploitable; it only reduces attacker effort."
    elif [[ $h == server ]]; then
      add_finding "Server header discloses technology" "${ROOT_URL:-$SCAN_BASE}" "Information disclosure" INFORMATIONAL "Informational observation" \
        "The Server header names the web server software." "$(tr -d '\r' <"$ROOT_HDR" | grep -i -m1 "^$h:")" "curl" High "Consider removing or genericising the Server header." ""
    fi
  done
}

check_cookies() {
  local line c name lc nohttp="" nosec="" nosame="" sess_http=0 sess_sec=0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    c=$line; name=${c%%=*}; lc=${c,,}
    local sess=0; [[ ${name,,} =~ (sess|sid|auth|token|jwt|login|phpsessid|jsessionid) ]] && sess=1
    if [[ $lc != *httponly* ]]; then [[ " $nohttp " == *" $name "* ]] || nohttp+="$name "; (( sess )) && sess_http=1; fi
    if [[ $SCAN_BASE == https://* && $lc != *secure* ]]; then [[ " $nosec " == *" $name "* ]] || nosec+="$name "; (( sess )) && sess_sec=1; fi
    [[ $lc == *samesite* ]] || [[ " $nosame " == *" $name "* ]] || nosame+="$name "
  done < <(hget_all "${COOKIE_HDR:-$ROOT_HDR}" set-cookie)
  local sev
  if [[ -n $nohttp ]]; then
    sev=LOW; (( sess_http )) && sev=MEDIUM
    add_finding "Cookie without HttpOnly attribute" "${ROOT_URL:-$SCAN_BASE}" "Session management" "$sev" "Confirmed vulnerability" \
      "Cookies without HttpOnly can be read by JavaScript and stolen through XSS." "Cookie names (values not stored): $nohttp" "curl" High \
      "Set the HttpOnly attribute on cookies that JavaScript does not need." "Cookies used only for client-side preferences may legitimately omit HttpOnly."
  fi
  if [[ -n $nosec ]]; then
    sev=LOW; (( sess_sec )) && sev=MEDIUM
    add_finding "Cookie without Secure attribute" "${ROOT_URL:-$SCAN_BASE}" "Session management" "$sev" "Confirmed vulnerability" \
      "Cookies without Secure may be sent over unencrypted HTTP connections." "Cookie names (values not stored): $nosec" "curl" High \
      "Set the Secure attribute on all cookies served over HTTPS." ""
  fi
  if [[ -n $nosame ]]; then
    add_finding "Cookie without SameSite attribute" "${ROOT_URL:-$SCAN_BASE}" "Session management" LOW "Confirmed vulnerability" \
      "Without SameSite, cookies are sent on cross-site requests in older browsers, aiding CSRF." "Cookie names (values not stored): $nosame" "curl" High \
      "Set SameSite=Lax or Strict (None only with Secure when required)." "Modern browsers default to Lax, reducing the practical risk."
  fi
}

check_redirect() {
  [[ -n $HTTP_BASE ]] || return 0
  (( HTTP_OK )) || return 0
  local loc
  http_fetch "$HTTP_BASE/" redir
  case $FETCH_CODE in
    301|302|303|307|308)
      loc=$(hget "$FETCH_HDR" location)
      if [[ ${loc,,} != https://* ]] && (( HTTPS_OK )); then
        add_finding "HTTP does not redirect to HTTPS" "$HTTP_BASE/" "Transport security" MEDIUM "Confirmed vulnerability" \
          "HTTP requests are redirected, but not to an HTTPS URL, leaving users on cleartext HTTP." "HTTP $FETCH_CODE Location: $loc" "curl" High \
          "Redirect all HTTP requests to the HTTPS version of the same host with a 301." "" 
      fi ;;
    000) ;;
    *)
      if (( HTTPS_OK )); then
        add_finding "HTTP content served without redirect to HTTPS" "$HTTP_BASE/" "Transport security" MEDIUM "Confirmed vulnerability" \
          "The site answers on HTTP (status $FETCH_CODE) instead of redirecting to HTTPS, exposing traffic to interception." "GET $HTTP_BASE/ -> HTTP $FETCH_CODE" "curl" High \
          "Redirect HTTP to HTTPS and enable HSTS." "Acceptable only for explicitly public, non-sensitive content."
      else
        local sev=MEDIUM t="Site served only over unencrypted HTTP"
        if grep -qiE "type=.?password" "$FETCH_BODY"; then sev=HIGH; t="Login form served over unencrypted HTTP"; fi
        add_finding "$t" "$HTTP_BASE/" "Transport security" "$sev" "Confirmed vulnerability" \
          "No HTTPS service was found; all traffic, including any credentials, is sent in cleartext." "GET $HTTP_BASE/ -> HTTP $FETCH_CODE" "curl" High \
          "Deploy a valid TLS certificate, enable HTTPS and redirect HTTP to HTTPS." "Local lab targets commonly use plain HTTP."
      fi ;;
  esac
}

check_cors() {
  local origin="https://doxa-cors-test.invalid" acao acac
  http_fetch "$SCAN_BASE/" cors -H "Origin: $origin"
  acao=$(hget "$FETCH_HDR" access-control-allow-origin); acac=$(hget "$FETCH_HDR" access-control-allow-credentials)
  [[ -n $acao ]] || return 0
  if [[ $acao == "$origin" && ${acac,,} == true ]]; then
    add_finding "CORS reflects arbitrary origin with credentials" "$SCAN_BASE" "CORS misconfiguration" HIGH "Potential vulnerability" \
      "The server reflects an untrusted Origin and allows credentials, which can let malicious sites read authenticated responses." \
      "Origin: $origin -> Access-Control-Allow-Origin: $acao; Access-Control-Allow-Credentials: $acac" "curl" Medium \
      "Validate Origin against a strict allow-list; never reflect arbitrary origins with credentials." "Impact depends on whether the endpoint returns sensitive, authenticated data."
  elif [[ $acao == "$origin" ]]; then
    add_finding "CORS reflects arbitrary origin" "$SCAN_BASE" "CORS misconfiguration" MEDIUM "Potential vulnerability" \
      "The server reflects an untrusted Origin in Access-Control-Allow-Origin." "Origin: $origin -> ACAO: $acao" "curl" Medium \
      "Use a strict allow-list of trusted origins." "Low impact if the resource is public and credentials are not allowed."
  elif [[ $acao == "*" ]]; then
    add_finding "CORS allows any origin (wildcard)" "$SCAN_BASE" "CORS misconfiguration" LOW "Informational observation" \
      "Access-Control-Allow-Origin: * lets any website read this response (without credentials)." "ACAO: *" "curl" High \
      "Restrict to trusted origins if the content is not intentionally public." "Wildcard is normal for public APIs and static assets."
  fi
}

check_http_methods() {
  local allow
  http_fetch "$SCAN_BASE/" opts -X OPTIONS
  allow=$(hget "$FETCH_HDR" allow)
  if [[ ${allow^^} =~ (PUT|DELETE|PATCH) ]]; then
    add_finding "Potentially dangerous HTTP methods advertised" "$SCAN_BASE" "Security misconfiguration" LOW "Potential vulnerability" \
      "The Allow header lists state-changing methods. DOXA did not test them (would modify data)." "Allow: $allow" "curl" Low \
      "Disable unused HTTP methods and require authentication for write methods." "Advertised methods may still require authentication."
  fi
  http_fetch "$SCAN_BASE/" trace -X TRACE -H "X-Doxa-Probe: doxa-trace-probe"
  if [[ $FETCH_CODE == 200 ]] && grep -qa "doxa-trace-probe" "$FETCH_BODY"; then
    add_finding "HTTP TRACE method enabled" "$SCAN_BASE" "Security misconfiguration" LOW "Confirmed vulnerability" \
      "TRACE echoes requests back, which can aid cross-site tracing attacks." "TRACE / -> HTTP 200 and the probe header was echoed" "curl" High \
      "Disable TRACE (e.g. TraceEnable off)." ""
  fi
}

EXPOSURE_PATHS=(/.git/HEAD /.git/config /.env /.svn/wc.db /.DS_Store /phpinfo.php /info.php /server-status /server-info
  /wp-config.php.bak /wp-config.php~ /wp-config.old /config.php.bak /config.php~ /config.inc.php.bak /configuration.php.bak
  /web.config /web.config.bak /.htpasswd /.htaccess /backup.zip /backup.tar.gz /backup.sql /db.sql /dump.sql /database.sql
  /site.zip /www.zip /composer.json /composer.lock /package.json /actuator/env /actuator /swagger.json /openapi.json /v2/api-docs
  /phpmyadmin/ /.idea/workspace.xml /id_rsa /.ssh/id_rsa /error_log /debug.log /application.log /storage/logs/laravel.log /.npmrc)

DIRLIST_PATHS=(/ /images/ /img/ /uploads/ /files/ /backup/ /backups/ /admin/ /assets/ /static/ /css/ /js/ /includes/ /tmp/ /logs/ /data/ /old/ /test/)

exposure_rule() { # sets R_* for a path; returns 1 if unknown
  R_HTML=0; R_REDACT=0; R_GREP=(-a -q -E)
  R_REM="Remove the file from the web root, deny access in the web-server configuration and rotate any credentials it contained."
  case $1 in
    /.git/HEAD|/.git/config) R_SEV=HIGH; R_TITLE="Exposed Git repository metadata"; R_RE='^ref: refs/|^\[core\]'
      R_DESC="The .git directory is downloadable, allowing source code and history to be reconstructed." ;;
    /.env) R_SEV=HIGH; R_TITLE="Exposed environment file (.env)"; R_RE='^[A-Za-z_][A-Za-z0-9_]*='; R_REDACT=1
      R_DESC="The .env file is publicly readable and typically holds credentials and API keys." ;;
    /.svn/wc.db) R_SEV=MEDIUM; R_TITLE="Exposed Subversion metadata"; R_RE='^SQLite format 3'; R_DESC="Subversion metadata exposes file paths and potentially source code." ;;
    /.DS_Store) R_SEV=LOW; R_TITLE="Exposed .DS_Store file"; R_RE='Bud1'; R_DESC="macOS directory metadata reveals file and folder names." ;;
    /phpinfo.php|/info.php) R_SEV=MEDIUM; R_TITLE="phpinfo() page exposed"; R_RE='phpinfo\(\)|PHP Version'; R_HTML=1
      R_DESC="phpinfo output discloses configuration, paths and environment details." ;;
    /server-status) R_SEV=MEDIUM; R_TITLE="Apache server-status exposed"; R_RE='Apache Server Status'; R_HTML=1
      R_DESC="server-status reveals live requests, client IPs and internal URLs." ;;
    /server-info) R_SEV=MEDIUM; R_TITLE="Apache server-info exposed"; R_RE='Apache Server Information'; R_HTML=1
      R_DESC="server-info discloses full server configuration." ;;
    /wp-config.php.bak|/wp-config.php~|/wp-config.old|/config.php.bak|/config.php~|/config.inc.php.bak|/configuration.php.bak)
      R_SEV=HIGH; R_TITLE="Exposed configuration backup file"; R_RE='<\?php|DB_PASSWORD|DB_USER'; R_REDACT=1
      R_DESC="A backup copy of an application configuration file is served as plain text and may contain database credentials." ;;
    /web.config|/web.config.bak) R_SEV=MEDIUM; R_TITLE="web.config readable over HTTP"; R_RE='<configuration'; R_REDACT=1
      R_DESC="The IIS/ASP.NET configuration file is downloadable." ;;
    /.htpasswd) R_SEV=HIGH; R_TITLE="Exposed .htpasswd file"; R_RE='^[^:[:space:]]+:.{8,}'; R_REDACT=1
      R_DESC="Password hashes for HTTP authentication are publicly downloadable." ;;
    /.htaccess) R_SEV=LOW; R_TITLE="Exposed .htaccess file"; R_RE='RewriteEngine|AuthType|Require |Options '; R_DESC="Server rules are readable, revealing hidden paths and logic." ;;
    /backup.zip|/site.zip|/www.zip) R_SEV=HIGH; R_TITLE="Downloadable site backup archive"; R_RE='^PK'; R_GREP=(-a -q -E)
      R_DESC="A ZIP archive (likely a site backup) is publicly downloadable and may contain source code and secrets." ;;
    /backup.tar.gz) R_SEV=HIGH; R_TITLE="Downloadable site backup archive"; R_RE='^\x1f\x8b'; R_GREP=(-a -q -P)
      R_DESC="A gzip archive (likely a backup) is publicly downloadable." ;;
    /backup.sql|/db.sql|/dump.sql|/database.sql) R_SEV=HIGH; R_TITLE="Exposed database dump"; R_RE='CREATE TABLE|INSERT INTO|DROP TABLE|mysqldump|MySQL dump'
      R_DESC="A SQL dump is downloadable and may expose all application data." ;;
    /composer.json|/composer.lock) R_SEV=LOW; R_TITLE="Dependency manifest exposed ($1)"; R_RE='"(require|packages)"'
      R_DESC="Dependency manifests reveal library versions, aiding vulnerability matching." ;;
    /package.json) R_SEV=LOW; R_TITLE="Dependency manifest exposed (package.json)"; R_RE='"(dependencies|name|version)"'
      R_DESC="Dependency manifests reveal library versions, aiding vulnerability matching." ;;
    /actuator/env) R_SEV=HIGH; R_TITLE="Spring Boot actuator env endpoint exposed"; R_RE='propertySources|activeProfiles'
      R_DESC="The actuator env endpoint can expose configuration properties and secrets." ;;
    /actuator) R_SEV=MEDIUM; R_TITLE="Spring Boot actuator exposed"; R_RE='"_links"'; R_DESC="Actuator endpoints can disclose internals and operational data." ;;
    /swagger.json|/openapi.json|/v2/api-docs) R_SEV=LOW; R_TITLE="API documentation publicly exposed"; R_RE='"(swagger|openapi)"'
      R_DESC="Full API specification is public, mapping the attack surface."; R_REM="Restrict API documentation to authenticated or internal users where appropriate." ;;
    /phpmyadmin/) R_SEV=MEDIUM; R_TITLE="phpMyAdmin interface exposed"; R_RE='phpMyAdmin'; R_HTML=1
      R_DESC="A database administration interface is reachable from the internet."; R_REM="Restrict phpMyAdmin by IP/VPN and enforce strong authentication, or remove it." ;;
    /.idea/workspace.xml) R_SEV=LOW; R_TITLE="IDE project file exposed"; R_RE='<project'; R_DESC="IDE metadata reveals project structure and paths." ;;
    /id_rsa|/.ssh/id_rsa) R_SEV=CRITICAL; R_TITLE="Private SSH key exposed"; R_RE='BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY'; R_REDACT=2
      R_DESC="A private key file is publicly downloadable, enabling server compromise."; R_REM="Remove the key immediately, treat it as compromised and rotate it everywhere it was authorised." ;;
    /error_log|/debug.log|/application.log|/storage/logs/laravel.log) R_SEV=MEDIUM; R_TITLE="Application log file exposed"
      R_RE='PHP (Warning|Notice|Fatal)|Stack trace|^\[[0-9]{4}-[0-9]{2}-[0-9]{2}|\[(error|debug|info)\]'
      R_DESC="Log files can leak internal paths, queries, tokens and user data." ;;
    /.npmrc) R_SEV=HIGH; R_TITLE="Exposed .npmrc file"; R_RE='_authToken|registry='; R_REDACT=1; R_DESC="npm configuration may contain registry authentication tokens." ;;
    *) return 1 ;;
  esac
  return 0
}

# exposure_cvss PATH EVIDENCE -> R_CVSS R_CVSSJ. Scores only what the evidence directly supports.
exposure_cvss() {
  local base="AV:N/AC:L/PR:N/UI:N/S:U" ;
  R_CVSS=""; R_CVSSJ=""
  case $1 in
    /.git/HEAD|/.git/config) R_CVSS="$base/C:L/I:N/A:N"; R_CVSSJ="Repository metadata was confirmed readable without authentication; full source retrieval was not attempted, so confidentiality impact is scored Low." ;;
    /.env|/.npmrc) if grep -qiE '(pass|secret|key|token|database_url|_authToken)' <<<"$2"; then
        R_CVSS="$base/C:H/I:N/A:N"; R_CVSSJ="Readable configuration file whose variable names indicate credentials or keys (values redacted and not used)."
      else R_CVSS="$base/C:L/I:N/A:N"; R_CVSSJ="Readable configuration file; no credential-like variable names were observed, so impact is scored Low."; fi ;;
    /id_rsa|/.ssh/id_rsa) R_CVSS="$base/C:H/I:N/A:N"; R_CVSSJ="Private key header confirmed in a public file. Whether the key grants access to any system was not tested." ;;
    /wp-config.php.bak|/wp-config.php~|/wp-config.old|/config.php.bak|/config.php~|/config.inc.php.bak|/configuration.php.bak)
      if LC_ALL=C grep -aqE 'DB_PASSWORD|password' "$FETCH_BODY"; then R_CVSS="$base/C:H/I:N/A:N"; R_CVSSJ="Application configuration source is served as text and references credentials (values redacted)."
      else R_CVSS="$base/C:L/I:N/A:N"; R_CVSSJ="Application source is disclosed; no credential references were observed in the sampled bytes."; fi ;;
    /backup.sql|/db.sql|/dump.sql|/database.sql)
      if LC_ALL=C grep -aq 'INSERT INTO' "$FETCH_BODY"; then R_CVSS="$base/C:H/I:N/A:N"; R_CVSSJ="SQL dump containing INSERT statements (data rows) is publicly downloadable."
      else R_CVSS="$base/C:L/I:N/A:N"; R_CVSSJ="SQL dump signature confirmed; data rows were not observed in the sampled bytes."; fi ;;
    /backup.zip|/backup.tar.gz|/site.zip|/www.zip) R_CVSS="$base/C:L/I:N/A:N"; R_CVSSJ="Archive signature confirmed; archive contents were not inspected, so impact is scored Low." ;;
    /phpinfo.php|/info.php|/server-status|/server-info|/actuator|/actuator/env|/.htpasswd|/.htaccess|/web.config|/web.config.bak)
      R_CVSS="$base/C:L/I:N/A:N"; R_CVSSJ="Configuration or runtime information confirmed readable without authentication." ;;
  esac
}

check_exposed_files() {
  local p ev found=0
  for p in "${EXPOSURE_PATHS[@]}"; do
    exposure_rule "$p" || continue
    http_fetch "$SCAN_BASE$p" exp -r 0-511
    case $FETCH_CODE in 200|206) ;; *) continue ;; esac
    if (( ! R_HTML )) && grep -aqiE '<(!doctype|html|head|body)' < <(head -c 400 "$FETCH_BODY"); then continue; fi
    LC_ALL=C grep "${R_GREP[@]}" -e "$R_RE" "$FETCH_BODY" || continue
    case $R_REDACT in
      2) ev="Private key header detected (content intentionally not stored)." ;;
      1) ev=$(LC_ALL=C grep -aE -e "$R_RE" "$FETCH_BODY" | head -6 | sed -E 's/([=:]).*/\1<redacted>/' | cut -c1-80) ;;
      *) ev=$(head -c 300 "$FETCH_BODY" | tr -c '[:print:]\n' '.') ;;
    esac
    found=$((found + 1))
    exposure_cvss "$p" "$ev"
    add_finding "$R_TITLE" "$SCAN_BASE$p" "Sensitive file exposure" "$R_SEV" "Confirmed vulnerability" "$R_DESC" \
      "GET $p -> HTTP $FETCH_CODE; content signature matched. ${ev}" "curl" High "$R_REM" \
      "Signature matched file content. Confirm manually that this is not an intentional public file or a honeypot." "" "$R_CVSS" "$R_CVSSJ"
  done
  return 0
}

check_dir_listing() { # paths...
  local p
  for p in "$@"; do
    http_fetch "$SCAN_BASE$p" dl
    [[ $FETCH_CODE == 200 ]] || continue
    if grep -qaiE '<title>Index of /|<h1>Index of /|Directory listing for /|<title>Directory Listing|\[To Parent Directory\]|Parent Directory</a>' "$FETCH_BODY"; then
      add_finding "Directory listing enabled" "$SCAN_BASE$p" "Information disclosure" MEDIUM "Confirmed vulnerability" \
        "The web server lists directory contents, exposing file names and potentially sensitive files." \
        "GET $p -> HTTP 200; auto-index page detected: $(grep -aoiE '<title>[^<]*' "$FETCH_BODY" | head -1 | sed 's/<title>//I')" "curl" High \
        "Disable directory indexing (Options -Indexes, autoindex off) and review exposed files." "Intentional public file mirrors may be listed on purpose." "" \
        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" "Directory index confirmed readable without authentication; sensitivity of the listed files was not assessed, so confidentiality impact is scored Low."
    fi
  done
}

check_http_headers() {
  local n0 n1; n0=$(count_findings)
  check_security_headers; check_cookies; check_redirect
  if [[ $MODE != passive ]]; then
    check_cors; check_http_methods; check_exposed_files; check_dir_listing "${DIRLIST_PATHS[@]}"
  else
    LIMITS+=("Passive mode: exposed-file probing, CORS/TRACE probes and directory-listing checks were not performed.")
  fi
  n1=$(count_findings)
  MODULE_DETAIL="$((n1 - n0)) findings"
  return 0
}
