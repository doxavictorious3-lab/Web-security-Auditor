#!/usr/bin/env bash
# DOXA test suite. Needs: bash, curl, openssl, python3. Uses ONLY a local lab server on 127.0.0.1.
# Usage: tests/run_tests.sh [-v]
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERBOSE=0; [[ ${1:-} == -v ]] && VERBOSE=1
PASS=0; FAIL=0; SKIPPED=0
W="$(mktemp -d /tmp/doxa-tests.XXXXXX)"
SRV_PID=""

pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [[ -n ${2:-} ]] && printf '       %s\n' "$2"; }
note() { SKIPPED=$((SKIPPED + 1)); printf '  \033[33mSKIP\033[0m %s\n' "$1"; }
section() { printf '\n== %s ==\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "expected [$3] got [$2]"; fi; }
assert_true() { local d=$1; shift; if "$@"; then pass "$d"; else fail "$d" "command failed: $*"; fi; }
assert_false() { local d=$1; shift; if "$@"; then fail "$d" "expected failure: $*"; else pass "$d"; fi; }

cleanup_tests() { [[ -n $SRV_PID ]] && kill "$SRV_PID" 2>/dev/null; [[ -n ${SRV2_PID:-} ]] && kill "$SRV2_PID" 2>/dev/null; rm -rf "$W"; }
trap cleanup_tests EXIT

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }

# ---- lab ----------------------------------------------------------------------------
HP=$(free_port); SP=$(free_port)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -days 2 >/dev/null 2>&1
python3 "$HERE/lab_server.py" --http-port "$HP" --https-port "$SP" --cert "$W/cert.pem" --key "$W/key.pem" --request-log "$W/req.log" >"$W/server.log" 2>&1 &
SRV_PID=$!
RP=$(free_port)
python3 "$HERE/lab_server.py" --http-port "$RP" --root-redirect >"$W/server2.log" 2>&1 &
SRV2_PID=$!
for _ in $(seq 1 30); do grep -q ready "$W/server.log" 2>/dev/null && break; sleep 0.2; done
grep -q ready "$W/server.log" || { echo "lab server failed to start"; cat "$W/server.log"; exit 2; }
echo "Lab: http://127.0.0.1:$HP  https://127.0.0.1:$SP (self-signed)"

# ---- source DOXA (no main) --------------------------------------------------------------
DOXA_SOURCE_ONLY=1
# shellcheck source=../doxa.sh
source "$ROOT/doxa.sh"
unset DOXA_SOURCE_ONLY
set +e
OPT_NO_COLOR=1; setup_colors

reset_env() { # fresh unit-test environment
  rm -rf "$W/unit"; mkdir -p "$W/unit/logs"
  OUTDIR="$W/unit"; LOG_DIR="$OUTDIR/logs"; TMPD="$W/unit/tmp"; mkdir -p "$TMPD"
  MAIN_LOG="$LOG_DIR/doxa.log"; FINDINGS_TSV="$LOG_DIR/findings.raw.tsv"; : >"$FINDINGS_TSV"
  MODULES_TSV="$LOG_DIR/modules.tsv"; : >"$MODULES_TSV"; TOOLS_TSV="$LOG_DIR/tools.tsv"; : >"$TOOLS_TSV"
  TECH_FILE="$LOG_DIR/technologies.txt"; : >"$TECH_FILE"
  SCOPE_HOSTS=(); SCOPE_PORTS=(); SCOPE_OOS_COUNT=0; INSECURE_TLS=0; CA_CERT=""; TLS_VERIFY_FAILED=0
  FIND_SEEN=(); FIND_DUP=0; FIND_COUNT=0; LIMITS=(); MODULE_PROBLEMS=0; MODULE_IDX=0; MODULE_TOTAL=1
  RATE=1000; NEXT_SLOT_US=0; CURL_TIMEOUT=8; MAX_REDIRECTS=5
  CURRENT_MODULE=""; MODE=standard; SELECTED_MODULES=""
  build_curl_base
}

# =============================================================================================
section "Invalid target input and URL parsing"
for u in "" "example.com" "ftp://x.com" "http://" "http://user@x.com" "http://x.com:0" "http://x.com:65536" "http://x.com:80:80" \
         "http://999.1.1.1" "http://1.2.3" "http://a..b" "http://-bad.com" "http://bad-.com" "http://[::1" "http://[::1::2]" \
         "http://[12345::1]" "http://x.com/a b" "http://x.com/\$(id)" "http://x.com/;rm" "http://x.com/../etc" 'http://x.com/a\b' \
         "http://exa mple.com" "https://x.com:abc"; do
  assert_false "rejects '${u//$'\n'/ }'" validate_target "$u"
done
validate_target "https://Example.COM:443/app/?x=1#frag"
assert_eq "normalises host/port/path" "$HOST|$PORT|$PATH_PREFIX|$BASE_URL" "example.com||/app|https://example.com"
validate_target "http://10.0.0.5:8080"; assert_eq "IPv4 with port" "$HOST|$PORT|$IS_IP|$IS_IPV6" "10.0.0.5|8080|1|0"
validate_target "https://[2001:db8::1]:8443/x"; assert_eq "IPv6 with brackets and port" "$HOST|$HOST_URL|$PORT|$IS_IPV6" "2001:db8::1|[2001:db8::1]|8443|1"
validate_target "http://[::1]"; assert_eq "IPv6 loopback default port" "$BASE_URL|$HTTPS_BASE" "http://[::1]|https://[::1]"
validate_target "http://localhost:3000"; assert_eq "single-label hostname" "$HOST|$HTTP_BASE|$HTTPS_BASE" "localhost|http://localhost:3000|"
assert_true "valid ports accepted" is_port 65535
assert_false "port 0 rejected" is_port 0
assert_false "validate_int bounds" validate_int x 101 1 100
assert_false "unsafe output dir rejected" validate_output_dir "--evil"

# =============================================================================================
section "Scope enforcement"
reset_env
validate_target "https://app.example.com"; scope_init
assert_eq "default hosts" "${SCOPE_HOSTS[*]}" "app.example.com"
assert_eq "default ports (no explicit port)" "${SCOPE_PORTS[*]}" "80 443"
assert_true "in-scope URL allowed" scope_check_url "https://app.example.com/x?y=1"
assert_true "http on port 80 allowed" scope_check_url "http://app.example.com/"
assert_false "other host blocked" scope_check_url "https://evil.example.net/"
assert_false "sibling subdomain blocked by default" scope_check_url "https://api.example.com/"
assert_false "unapproved port blocked" scope_check_url "https://app.example.com:8443/"
assert_false "malformed URL blocked" scope_check_url "https://app.example.com@evil.com/"
scope_add_host "*.example.org"
assert_true "wildcard matches subdomain" scope_check_url "https://a.b.example.org/"
assert_false "wildcard does not match apex" scope_check_url "https://example.org/"
assert_false "invalid scope host rejected" scope_add_host "bad host"
scope_add_port 8443
assert_true "added port allowed" scope_check_url "https://app.example.com:8443/"
reset_env; validate_target "http://127.0.0.1:9000"; scope_init
assert_eq "explicit port is the only approved port" "${SCOPE_PORTS[*]}" "9000"
assert_false "scope_assert_url blocks and counts" scope_assert_url "http://127.0.0.1:9001/"
assert_eq "out-of-scope counter" "$SCOPE_OOS_COUNT" "1"
http_fetch "http://127.0.0.1:9001/" oos; assert_eq "http_fetch refuses out-of-scope (code 000)" "$FETCH_CODE" "000"
assert_true "out-of-scope request logged" grep -q "9001" "$LOG_DIR/out_of_scope.log"
assert_false "assert_host blocks unapproved host" scope_assert_host "10.9.9.9"

# =============================================================================================
section "Redirect handling (scope-checked at every hop)"
reset_env; validate_target "http://127.0.0.1:$HP"; scope_init
follow_chain "http://127.0.0.1:$HP/redirect-in" >"$W/chain1.txt"
assert_eq "in-scope redirect is followed" "$CHAIN_FINAL_URL|$CHAIN_FINAL_CODE" "http://127.0.0.1:$HP/|200"
follow_chain "http://127.0.0.1:$HP/redirect-out" >"$W/chain2.txt"
assert_true "off-host redirect is blocked" test -n "$CHAIN_BLOCKED"
assert_eq "blocked redirect keeps last in-scope URL" "$CHAIN_FINAL_URL" "http://127.0.0.1:$HP/redirect-out"
assert_true "blocked redirect counted" test "$SCOPE_OOS_COUNT" -ge 1
follow_chain "http://127.0.0.1:$HP/redirect-port" >"$W/chain3.txt"
assert_true "redirect to unapproved port is blocked" grep -q "not approved" "$W/chain3.txt"
follow_chain "http://127.0.0.1:$HP/redirect-loop" >"$W/chain4.txt"
assert_true "redirect loop detected" test -n "$CHAIN_BLOCKED"
MAX_REDIRECTS=3; follow_chain "http://127.0.0.1:$HP/redirect-chain" >"$W/chain5.txt"
assert_true "redirect limit enforced" grep -q "redirect limit" "$W/chain5.txt"
MAX_REDIRECTS=5

# =============================================================================================
section "TLS verification (on by default)"
reset_env; validate_target "https://127.0.0.1:$SP"; scope_init
has_k() { local x; for x in "${CURL_BASE[@]}"; do [[ $x == -k ]] && return 0; done; return 1; }
assert_false "default curl options do not contain -k" has_k
http_fetch "https://127.0.0.1:$SP/" tls1
assert_eq "self-signed certificate is rejected" "$FETCH_CODE|$FETCH_ERR" "000|tls-verification-failed"
assert_eq "TLS_VERIFY_FAILED flag set" "$TLS_VERIFY_FAILED" "1"
CA_CERT="$W/cert.pem"; build_curl_base
http_fetch "https://127.0.0.1:$SP/" tls2
assert_eq "trusted via --ca-cert" "$FETCH_CODE" "200"
CA_CERT=""; INSECURE_TLS=1; build_curl_base
http_fetch "https://127.0.0.1:$SP/" tls3
assert_eq "explicit diagnostic override connects" "$FETCH_CODE" "200"
assert_true "override adds -k only when enabled" has_k
INSECURE_TLS=0; build_curl_base

# =============================================================================================
section "Global rate limiting"
reset_env; validate_target "http://127.0.0.1:$HP"; scope_init
RATE=5; NEXT_SLOT_US=0; t0=$EPOCHREALTIME
for i in 1 2 3 4 5 6 7 8; do http_fetch "http://127.0.0.1:$HP/" rl; done
t1=$EPOCHREALTIME; el=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
assert_true "8 requests at 5 req/s take >= 1.3s (took ${el}s)" awk -v e="$el" 'BEGIN{exit !(e>=1.3)}'
assert_true "rate limiter does not over-throttle (<4s)" awk -v e="$el" 'BEGIN{exit !(e<4)}'
RATE=1000; NEXT_SLOT_US=0; t0=$EPOCHREALTIME
for i in 1 2 3 4 5 6 7 8; do http_fetch "http://127.0.0.1:$HP/" rl; done
t1=$EPOCHREALTIME; el=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
assert_true "high rate is fast (${el}s)" awk -v e="$el" 'BEGIN{exit !(e<1.5)}'

# =============================================================================================
section "Missing dependencies and module failures"
mkdir -p "$W/nocurl"
for f in /usr/bin/* /bin/*; do b=$(basename "$f"); [[ $b == curl ]] && continue; [[ -e $W/nocurl/$b ]] || ln -s "$f" "$W/nocurl/$b" 2>/dev/null; done
env PATH="$W/nocurl" /bin/bash "$ROOT/doxa.sh" --target "http://127.0.0.1:$HP" --authorized --no-color -o "$W/out_nocurl" >"$W/nocurl.log" 2>&1
assert_eq "missing required tool exits with code 2" "$?" "2"
assert_true "message names the missing tool" grep -q "curl (required)" "$W/nocurl.log"
reset_env; MODULE_TOTAL=3
MOD_FUNC[bad]=false_module; MOD_REQ[bad]=""
false_module() { MODULE_DETAIL="simulated failure"; return 1; }
timeout_module() { MODULE_DETAIL="simulated timeout"; return 124; }
MOD_FUNC[tmo]=timeout_module; MOD_REQ[tmo]=""
MOD_FUNC[needs]=false_module; MOD_REQ[needs]="definitely-not-installed-tool"
MOD_FUNC[needweb]=false_module; MOD_REQ[needweb]="@web"; WEB_OK=0
run_module bad >/dev/null; run_module tmo >/dev/null; run_module needs >/dev/null; run_module needweb >/dev/null
assert_eq "failed module recorded as FAILED" "$(awk -F'\t' '$1=="bad"{print $2}' "$MODULES_TSV")" "FAILED"
assert_eq "timed-out module recorded as TIMEOUT" "$(awk -F'\t' '$1=="tmo"{print $2}' "$MODULES_TSV")" "TIMEOUT"
assert_eq "missing tool recorded as SKIPPED with reason" "$(awk -F'\t' '$1=="needs"{print $2": "$4}' "$MODULES_TSV")" "SKIPPED: required tool not installed: definitely-not-installed-tool"
assert_eq "no web service recorded as SKIPPED" "$(awk -F'\t' '$1=="needweb"{print $2}' "$MODULES_TSV")" "SKIPPED"
assert_eq "problems counted (failed + timeout)" "$MODULE_PROBLEMS" "2"
unset 'MOD_FUNC[bad]' 'MOD_REQ[bad]' 'MOD_FUNC[tmo]' 'MOD_REQ[tmo]' 'MOD_FUNC[needs]' 'MOD_REQ[needs]' 'MOD_FUNC[needweb]' 'MOD_REQ[needweb]'

# =============================================================================================
section "Finding normalisation, redaction and deduplication"
reset_env; CURRENT_MODULE=unit
add_finding "Dup finding" "http://x/" "Security headers" LOW "Confirmed vulnerability" "d" "e" "curl" High "r" >/dev/null
add_finding "Dup finding" "http://x" "Security headers" HIGH "Confirmed vulnerability" "d" "e" "curl" High "r" >/dev/null
assert_eq "duplicates suppressed (URL trailing slash normalised)" "$FIND_COUNT|$FIND_DUP" "1|1"
add_finding "Secrets" "http://x/s" "Sensitive file exposure" HIGH "Confirmed vulnerability" "has password=hunter22" \
  $'Authorization: Bearer abcdefghij1234567\npassword=hunter22\nAKIAABCDEFGHIJKLMNOP\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk' "t" High "r" >/dev/null
assert_false "secrets are not stored in the raw store" grep -qE "hunter22|abcdefghij1234567|AKIAABCDEFGHIJKLMNOP|eyJhbGci" "$FINDINGS_TSV"
add_finding "Bad vector" "http://x/v" "Sensitive file exposure" MEDIUM "Confirmed vulnerability" "d" "e" "t" High "r" "" "" "AV:Z/AC:L" "bogus" >/dev/null
add_finding "Scored" "http://x/c" "Sensitive file exposure" MEDIUM "Confirmed vulnerability" "d" "e" "t" High "r" "" "" "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" "justified" >/dev/null
add_finding "Unscored info" "http://x/i" "Reconnaissance" INFORMATIONAL "Informational observation" "d" "e" "t" High "r" >/dev/null
add_finding "Crit" "http://x/k" "Sensitive file exposure" CRITICAL "bogus-status" "d" "e" "t" High "r" >/dev/null
IPS=(127.0.0.1); START_EPOCH=$(date +%s); report_prepare
assert_eq "severity ordering and IDs (first is CRITICAL, DOXA-001)" "$(head -1 "$FINAL_TSV" | cut -d$'\037' -f1,3)" "DOXA-001"$'\037'"CRITICAL"
assert_eq "invalid classification downgraded to unverified" "$(grep -c 'False positive or unverified result' "$FINAL_TSV")" "1"
assert_eq "invalid CVSS vector rejected (no score)" "$(awk -F'\037' '$4=="Bad vector"{print "["$13"]"}' "$FINAL_TSV")" "[]"
assert_eq "valid CVSS vector scored 7.5" "$(awk -F'\037' '$4=="Scored"{print $13}' "$FINAL_TSV")" "7.5"
assert_eq "informational finding is not scored" "$(awk -F'\037' '$4=="Unscored info"{print "["$13"]"}' "$FINAL_TSV")" "[]"
assert_eq "OWASP mapping applied" "$(awk -F'\037' '$4=="Scored"{print $12}' "$FINAL_TSV")" "A05:2021 Security Misconfiguration"
assert_eq "statistics" "$TOTAL|$CVSS_SCORED|$CNT_CRITICAL|$CNT_HIGH|$CNT_MEDIUM" "6|1|1|1|2"
assert_eq "CVSS 9.8 reference vector" "$(cvss31_score 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')" "9.8"
assert_eq "CVSS 6.1 reference vector (XSS style, scope changed)" "$(cvss31_score 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')" "6.1"
assert_eq "CVSS 5.3 reference vector" "$(cvss31_score 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N')" "5.3"
assert_false "CVSS invalid vector fails" cvss31_score "AV:X/AC:L"

# =============================================================================================
section "Report generation: JSON validity, HTML escaping, CSV injection"
reset_env; CURRENT_MODULE=unit; validate_target "http://127.0.0.1:$HP"; scope_init
IPS=(127.0.0.1); THREADS=1; RATE=5; AUTH_METHOD=test; AUTH_TIME=$(now_iso); START_ISO=$(now_iso); START_EPOCH=$(date +%s)
printf 'recon\tOK\t1\tdone\nnmap\tSKIPPED\t0\trequired tool not installed: nmap\n' >"$MODULES_TSV"
printf 'curl\tcurl -s "x\\y"\t0\t1\tlogs/x.log\n' >"$TOOLS_TSV"
add_finding '<script>alert(1)</script> "quoted" \ back\slash' "http://x/a?b=1&c=2" "Security headers" MEDIUM "Confirmed vulnerability" \
  'desc with <b>html</b> & "quotes"' $'line1\nline2 <img src=x onerror=alert(1)>\ttab' "curl" High 'rem "x"' "fp" >/dev/null
add_finding '=HYPERLINK("http://evil","x")' "http://x/b" "Security headers" LOW "Confirmed vulnerability" "d" "e" "curl" High "r" >/dev/null
add_finding $'unicode \xc3\xa9 and ctrl \x01 chars' "http://x/c" "Security headers" LOW "Confirmed vulnerability" "d" "e" "curl" High "r" >/dev/null
finalize_reports >/dev/null 2>&1
assert_true "findings.json is valid JSON" python3 -c "import json;json.load(open('$OUTDIR/findings.json'))"
assert_eq "JSON keeps tricky title intact" "$(python3 -c "import json;d=json.load(open('$OUTDIR/findings.json'));print([f['title'] for f in d['findings'] if 'script' in f['title']][0])")" '<script>alert(1)</script> "quoted" \ back\slash'
assert_eq "JSON finding count" "$(python3 -c "import json;print(len(json.load(open('$OUTDIR/findings.json'))['findings']))")" "3"
assert_eq "JSON has OWASP, CVSS object and impact on each finding" "$(python3 -c "
import json;d=json.load(open('$OUTDIR/findings.json'))
print(all(f['owasp_category'] and 'cvss' in f and f['impact'] and f['id'].startswith('DOXA-') for f in d['findings']))")" "True"
assert_true "HTML contains no raw injected script/img tags" bash -c "! grep -q '<script>alert\|<img src=x' '$OUTDIR/report.html'"
assert_true "HTML contains escaped title" grep -q '&lt;script&gt;alert(1)&lt;/script&gt;' "$OUTDIR/report.html"
assert_true "HTML has all numbered sections (>= 15)" test "$(grep -c '<h2[^>]*>[0-9]*\. ' "$OUTDIR/report.html")" -ge 15
assert_true "HTML is well formed (balanced tags)" python3 - "$OUTDIR/report.html" <<'EOF'
import sys
from html.parser import HTMLParser
class P(HTMLParser):
    def __init__(s): super().__init__(); s.st=[]; s.bad=0
    def handle_starttag(s,t,a):
        if t not in ('meta','br','img','link'): s.st.append(t)
    def handle_endtag(s,t):
        if s.st and s.st[-1]==t: s.st.pop()
        else: s.bad+=1
p=P(); p.feed(open(sys.argv[1]).read()); sys.exit(0 if not p.st and not p.bad else 1)
EOF
assert_true "CSV neutralises formula injection" bash -c "grep -q \"\\\"'=HYPERLINK\" '$OUTDIR/findings.csv'"
assert_true "CSV parses with 15 columns" python3 -c "
import csv;r=list(csv.reader(open('$OUTDIR/findings.csv',newline='')));assert all(len(x)==15 for x in r) and len(r)==4"
assert_true "TXT report generated" test -s "$OUTDIR/report.txt"
assert_true "report hashes verify" bash -c "cd '$OUTDIR' && sha256sum -c logs/reports.sha256 >/dev/null 2>&1"
assert_true "artefact hash manifest exists" test -s "$LOG_DIR/evidence.sha256"
assert_true "skipped module appears in limitations" grep -q "nmap skipped" "$OUTDIR/report.txt"

# =============================================================================================
section "End-to-end scans against the local lab"
E2E="$W/e2e"; mkdir -p "$E2E"
"$ROOT/doxa.sh" --target "http://127.0.0.1:$HP" --mode standard --authorized --no-color -o "$E2E" --rate 200 >"$W/e2e1.log" 2>&1
rc=$?
assert_eq "standard scan exits 4 (HIGH findings present)" "$rc" "4"
D=$(ls -d "$E2E"/127.0.0.1_"$HP"_* | head -1)
assert_true "report files created" bash -c "cd '$D' && test -s report.html -a -s report.txt -a -s findings.json -a -s findings.csv -a -s reconnaissance.txt"
assert_true "e2e findings.json valid" python3 -c "import json;json.load(open('$D/findings.json'))"
assert_true "exposed .env found with CVSS 7.5" python3 -c "
import json;d=json.load(open('$D/findings.json'))
f=[x for x in d['findings'] if '.env' in x['title']];assert f and f[0]['cvss']['score']==7.5 and f[0]['classification']=='Confirmed vulnerability'"
assert_true "exposed .git found" grep -q "Exposed Git repository" "$D/report.txt"
assert_true "directory listing found" grep -q "Directory listing enabled" "$D/report.txt"
assert_true "insecure cookie found" grep -q "Cookie without HttpOnly" "$D/report.txt"
assert_true "reflective CORS found" grep -q "CORS reflects arbitrary origin with credentials" "$D/report.txt"
assert_false "no secret or cookie value leaked into any output" grep -rqE "hunter2hunter2|SECRETVALUE123" "$D"
assert_true "missing tools reported as SKIPPED (never silent)" grep -qE "^nmap\s+SKIPPED" <(awk -F'\t' '{print $1" "$2}' "$D/logs/modules.tsv" | sed 's/ /\t/') || \
  assert_true "missing tools reported as SKIPPED (never silent)" grep -q "SKIPPED" "$D/logs/modules.tsv"
assert_eq "no out-of-scope requests were made" "$(python3 -c "import json;print(json.load(open('$D/findings.json'))['assessment']['scope']['out_of_scope_requests_blocked'])")" "0"
assert_true "scope and TLS recorded in JSON" python3 -c "
import json;a=json.load(open('$D/findings.json'))['assessment'];assert a['scope']['tls_verification']=='enabled' and a['scope']['approved_hosts']==['127.0.0.1']"

"$ROOT/doxa.sh" --target "http://127.0.0.1:$HP" --mode passive --authorized --no-color -o "$E2E" --rate 200 >"$W/e2e2.log" 2>&1
D2=$(ls -dt "$E2E"/127.0.0.1_"$HP"_* | head -1)
assert_false "passive mode does not probe exposed files" grep -q "Exposed environment file" "$D2/report.txt"
assert_true "passive mode records active modules as skipped" grep -q "passive" <(grep -i "nmap" "$D2/logs/modules.tsv")

"$ROOT/doxa.sh" --target "https://127.0.0.1:$SP" --mode passive --authorized --no-color -o "$E2E" --rate 200 >"$W/e2e3.log" 2>&1
D3=$(ls -dt "$E2E"/127.0.0.1_"$SP"_* | head -1)
assert_true "HTTPS with untrusted cert: validation failure reported, not bypassed" grep -q "TLS certificate validation failed" "$D3/report.txt"
assert_true "web modules skipped when verification fails" grep -qP "^http\tSKIPPED" "$D3/logs/modules.tsv"
assert_true "TLS module still analyses the certificate" grep -q "TLS certificate is not trusted" "$D3/report.txt"
"$ROOT/doxa.sh" --target "https://127.0.0.1:$SP" --mode passive --authorized --no-color -o "$E2E" --rate 200 --ca-cert "$W/cert.pem" >"$W/e2e4.log" 2>&1
D4=$(ls -dt "$E2E"/127.0.0.1_"$SP"_* | head -1)
assert_true "--ca-cert: web checks run over verified HTTPS" grep -qP "^http\tOK" "$D4/logs/modules.tsv"
"$ROOT/doxa.sh" --target "https://127.0.0.1:$SP" --mode passive --authorized --no-color -o "$E2E" --rate 200 --insecure-tls-diagnostic >"$W/e2e5.log" 2>&1
D5=$(ls -dt "$E2E"/127.0.0.1_"$SP"_* | head -1)
assert_true "diagnostic override works and is recorded in the report" grep -q "TLS certificate verification disabled for this scan" "$D5/report.txt"
assert_true "diagnostic override is flagged in JSON" python3 -c "
import json;print(json.load(open('$D5/findings.json'))['assessment']['scope']['tls_verification'])" 
assert_true "CLI rejects invalid scope host" bash -c "'$ROOT/doxa.sh' --target http://127.0.0.1:$HP --scope-host 'bad host' --authorized >/dev/null 2>&1; test \$? -eq 1"
assert_true "CLI rejects bad rate" bash -c "'$ROOT/doxa.sh' --target http://127.0.0.1:$HP --rate 0 --authorized >/dev/null 2>&1; test \$? -eq 1"
assert_true "CLI rejects unknown module" bash -c "'$ROOT/doxa.sh' --target http://127.0.0.1:$HP --skip nope --authorized >/dev/null 2>&1; test \$? -eq 1"
assert_true "non-interactive run without --authorized is refused" bash -c "'$ROOT/doxa.sh' --target http://127.0.0.1:$HP </dev/null >/dev/null 2>&1; test \$? -eq 1"

# =============================================================================================
section "Regression tests for issues found in the first real-world scan (DVWA)"
# 1. nuclei flag detection must survive pipefail/SIGPIPE: a fake nuclei prints a huge help text.
mkdir -p "$W/fakebin"
cat >"$W/fakebin/nuclei" <<'FAKE'
#!/bin/sh
if [ "$1" = "-h" ]; then i=0; while [ $i -lt 4000 ]; do echo "   -j, -jsonl   write output in JSONL(ines) format  (padding line $i xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)"; i=$((i+1)); done; fi
FAKE
chmod +x "$W/fakebin/nuclei"
assert_eq "nuclei -jsonl detected despite pipefail and large help output" "$(PATH="$W/fakebin:$PATH" nuclei_json_flag)" "-jsonl"
cat >"$W/fakebin/nuclei" <<'FAKE'
#!/bin/sh
echo "usage: only the old -json flag exists"
FAKE
assert_eq "old nuclei falls back to -json" "$(PATH="$W/fakebin:$PATH" nuclei_json_flag)" "-json"

# 2. root redirect: headers analysed on the final page, cookies collected from every hop, names deduplicated
"$ROOT/doxa.sh" --target "http://127.0.0.1:$RP" --mode passive --authorized --no-color -o "$E2E" --rate 200 >"$W/e2e6.log" 2>&1
D6=$(ls -dt "$E2E"/127.0.0.1_"$RP"_* | head -1)
assert_true "cookies set on the redirect response are analysed" grep -q "Cookie without HttpOnly" "$D6/report.txt"
assert_eq "cookie names are not repeated" "$(grep -o 'PHPSESSID' <(grep 'Cookie names' "$D6/report.txt" | head -1) | wc -l | tr -d ' ')" "1"
assert_true "header findings point at the analysed (final) page" grep -q "Affected URL   : http://127.0.0.1:$RP/home" "$D6/report.txt"
assert_true "evidence shows the final 200 response, not the 302" grep -q "HTTP/1.1 200 OK" "$D6/report.txt"
assert_true "page title taken from the final page" grep -q "Page title    : DOXA Lab" "$D6/reconnaissance.txt"
assert_false "cookie values never leak" grep -rqE "REDIRSECRET" "$D6"

# 3. TXT layout: Remediation always starts on its own line
assert_false "evidence does not run into the Remediation line" grep -qE '[^ ]  Remediation' "$D6/report.txt"
assert_true "Remediation lines are well formed" grep -qE '^  Remediation +: ' "$D6/report.txt"

# 4. nikto duplicate suppression helper
reset_env; CURRENT_MODULE=unit
add_finding "Directory listing enabled" "http://x/config/" "Information disclosure" MEDIUM "Confirmed vulnerability" "d" "e" "curl" High "r" >/dev/null
assert_true "finding_exists matches despite trailing slash" finding_exists "Directory listing enabled" "http://x/config" "Information disclosure"
assert_false "finding_exists is false for other URLs" finding_exists "Directory listing enabled" "http://x/other" "Information disclosure"

# =============================================================================================
section "Stage 2: JavaScript analysis"
JD="$W/js_out"; mkdir -p "$JD"
: >"$W/req.log"
"$ROOT/doxa.sh" --target "http://127.0.0.1:$HP" --mode custom --modules recon,js --authorized --no-color -o "$JD" --rate 500 >"$W/js1.log" 2>&1
DJ=$(ls -dt "$JD"/127.0.0.1_"$HP"_* | head -1)
for t in "AWS access key ID" "Stripe live secret key" "JSON Web Token" "Google API key" "Hard-coded credential assignment"; do
  assert_true "secret pattern flagged: $t" grep -q "Possible $t in client-side code (app.js)" "$DJ/report.txt"
done
assert_false "secret values never appear in any output file" grep -rqE "AKIAABCDEFGHIJKLMNOP|sk_live_abcdefghijklmnop1234|S3cr3tPassw0rd|eyJhbGciOiJIUzI1NiJ9|AIzaSyA1234567890" "$DJ"
assert_eq "placeholder credential (YOUR_API_KEY_HERE) is ignored" "$(grep -c 'Hard-coded credential assignment at byte offset' "$DJ/report.txt")" "1"
assert_true "evidence shows length and hash only" grep -q "characters, sha256 prefix" "$DJ/report.txt"
assert_true "API endpoints extracted from JavaScript" bash -c "grep -qx '/api/Challenges' '$DJ/logs/js_endpoints.txt' && grep -qx '/rest/user/login' '$DJ/logs/js_endpoints.txt'"
assert_false "static assets are not listed as endpoints" grep -q "logo.png" "$DJ/logs/js_endpoints.txt"
assert_true "DOM XSS indicator (source + sink) flagged for manual verification" grep -q "Potential DOM-based XSS pattern" "$DJ/report.txt"
assert_true "library bundle skipped for pattern checks" grep -q "library bundle" "$DJ/logs/js_files.txt"
assert_false "no dangerous-pattern finding for the jQuery bundle" grep -qE "dangerous JavaScript patterns \(jquery" "$DJ/report.txt"
assert_true "http:// reference on an HTTP site is informational only" grep -q "\[INFORMATIONAL\] DOXA-[0-9]*  http:// references in JavaScript" "$DJ/report.txt"
assert_true "missing Subresource Integrity reported" grep -q "Third-party scripts loaded without Subresource Integrity" "$DJ/report.txt"
assert_true "SRI evidence lists lib.js" grep -q "cdn.example.org/lib.js" "$DJ/report.txt"
assert_false "script that has an integrity attribute is not listed" grep -q "sri.js" "$DJ/report.txt"
assert_true "exposed source map found with CVSS 5.3" python3 -c "
import json;d=json.load(open('$DJ/findings.json'))
f=[x for x in d['findings'] if 'source map' in x['title']];assert f and f[0]['cvss']['score']==5.3 and f[0]['classification']=='Confirmed vulnerability'"
assert_true "third-party scripts were not fetched (scope)" python3 -c "
import json;d=json.load(open('$DJ/findings.json'));assert d['assessment']['scope']['out_of_scope_requests_blocked']==0"
assert_false "no request ever left the approved origin" grep -q "example.org" "$W/req.log"
"$ROOT/doxa.sh" --target "https://127.0.0.1:$SP" --mode custom --modules recon,js --authorized --no-color -o "$JD" --rate 500 --ca-cert "$W/cert.pem" >"$W/js2.log" 2>&1
DJ2=$(ls -dt "$JD"/127.0.0.1_"$SP"_* | head -1)
assert_true "on HTTPS, http:// references are a MEDIUM finding" grep -q "\[MEDIUM\] DOXA-[0-9]*  Insecure http:// references in JavaScript" "$DJ2/report.txt"
assert_true "on HTTPS, a script over http:// is active mixed content" grep -q "Script loaded over insecure HTTP on an HTTPS page" "$DJ2/report.txt"

# =============================================================================================
section "Stage 2: API assessment (GET-only, non-destructive)"
AD="$W/api_out"; mkdir -p "$AD"; : >"$W/req.log"
"$ROOT/doxa.sh" --target "http://127.0.0.1:$HP" --mode custom --modules recon,js,api --authorized --no-color -o "$AD" --rate 500 >"$W/api1.log" 2>&1
DA=$(ls -dt "$AD"/127.0.0.1_"$HP"_* | head -1)
assert_eq "only GET requests were sent" "$(cut -d' ' -f1 "$W/req.log" | sort -u | tr '\n' ' ')" "GET "
assert_true "OpenAPI/Swagger document found" grep -q "API documentation publicly accessible" "$DA/report.txt"
assert_true "missing authentication scheme in the API description noted" grep -q "OpenAPI document declares no authentication scheme" "$DA/report.txt"
assert_true "GraphQL introspection detected" grep -q "GraphQL introspection enabled" "$DA/report.txt"
assert_true "reflective CORS on the API (HIGH, potential)" python3 -c "
import json;d=json.load(open('$DA/findings.json'))
f=[x for x in d['findings'] if x['title'].startswith('API CORS reflects')];assert f and f[0]['severity']=='HIGH' and f[0]['classification']=='Potential vulnerability'"
assert_true "sensitive-looking unauthenticated endpoint flagged as potential only" python3 -c "
import json;d=json.load(open('$DA/findings.json'))
f=[x for x in d['findings'] if 'sensitive API endpoint' in x['title'] and '/api/users' in x['title']];assert f and f[0]['classification']=='Potential vulnerability' and f[0]['owasp_category'].startswith('A01')"
assert_true "evidence has field names only" grep -q "field names: .*email" "$DA/report.txt"
assert_false "API response values never stored" grep -rq "admin@x.test" "$DA"
assert_true "stack trace disclosure confirmed with CVSS" python3 -c "
import json;d=json.load(open('$DA/findings.json'))
f=[x for x in d['findings'] if x['title'].startswith('Verbose error')];assert f and f[0]['cvss']['score']==5.3"
assert_true "HTTP Basic over cleartext HTTP found" grep -q "HTTP Basic authentication offered over unencrypted HTTP" "$DA/report.txt"
assert_false "templated endpoints (/api/users/{id}) are not probed" grep -q "{" "$DA/logs/api_endpoints.txt"
assert_true "api endpoint inventory written" test -s "$DA/logs/api_endpoints.txt"
assert_true "authorization limitation documented" grep -q "authorization (IDOR/BOLA)" "$DA/report.txt"
assert_true "api module is skipped in passive mode" bash -c "grep -qP '^api\tSKIPPED\t0\tnot part of' '$E2E'/127.0.0.1_${HP}_*/logs/modules.tsv"

# =============================================================================================
section "Stage 2: DNS and subdomain indicators (fake dig fixture)"
mkdir -p "$W/fakedig"
cat >"$W/fakedig/dig" <<'FAKEDIG'
#!/usr/bin/env bash
data=${DNS_FIXTURE:?}; short=0; comments=0; server=""; args=()
for a in "$@"; do case $a in +short) short=1 ;; +comments) comments=1 ;; +*) ;; @*) server=${a#@} ;; *) args+=("$a") ;; esac; done
name=${args[0]:-}; type=${args[1]:-A}
echo "$name $type $server" >>"${DNS_LOG:-/dev/null}"
if [[ $type == AXFR ]]; then
  if grep -q "^axfr|$name|" "$data"; then grep "^axfr|$name|" "$data" | cut -d'|' -f3; else echo "; Transfer failed."; fi; exit 0
fi
if (( comments )); then st=$(grep "^status|$name|" "$data" | cut -d'|' -f3); echo ";; ->>HEADER<<- opcode: QUERY, status: ${st:-NOERROR}, id: 1"; exit 0; fi
out=$(grep -F "$name|$type|" "$data" | grep "^$name|$type|" | cut -d'|' -f3)
if [[ -z $out && $type == A ]]; then
  wz=$(grep '^wildcard|' "$data" | cut -d'|' -f2); wi=$(grep '^wildcard|' "$data" | cut -d'|' -f3)
  if [[ -n $wz && $name == *".$wz" ]] && ! grep -q "|CNAME|" <(grep "^$name|" "$data"); then out=$wi; fi
fi
printf '%s\n' "$out" | grep -v '^$'
exit 0
FAKEDIG
chmod +x "$W/fakedig/dig"
cat >"$W/dns.fixture" <<'FIX'
app.example.test|A|10.0.0.5
app.example.test|NS|ns1.example.test.
app.example.test|MX|10 mail.example.test.
app.example.test|TXT|"v=spf1 +all"
app.example.test|SOA|ns1.example.test. admin.example.test. 1 2 3 4 5
dev.app.example.test|A|10.0.0.6
old.app.example.test|A|abandoned.github.io.
old.app.example.test|CNAME|abandoned.github.io.
blog.app.example.test|A|zzz.unknown-provider.net.
blog.app.example.test|CNAME|zzz.unknown-provider.net.
ghost.app.example.test|A|foo.herokuapp.com.
ghost.app.example.test|CNAME|foo.herokuapp.com.
foo.herokuapp.com|A|54.1.2.3
status|abandoned.github.io|NXDOMAIN
status|zzz.unknown-provider.net|NXDOMAIN
axfr|app.example.test|app.example.test. 3600 IN SOA ns1.example.test. a.b. 1 2 3 4 5
axfr|app.example.test|www.app.example.test. 3600 IN A 10.0.0.7
axfr|app.example.test|secret.app.example.test. 3600 IN A 10.0.0.8
axfr|app.example.test|app.example.test. 3600 IN SOA ns1.example.test. a.b. 1 2 3 4 5
FIX
run_dns_case() { # MODE [wildcard]
  reset_env; CURRENT_MODULE=dns; MODE=$1; IS_IP=0; HOST=app.example.test; PORT=""; HOST_URL=$HOST; SCAN_BASE="http://$HOST"
  SCOPE_HOSTS=(app.example.test); SCOPE_PORTS=(80); RATE=1000
  cp "$W/dns.fixture" "$W/dns.case"; [[ -n ${2:-} ]] && echo "wildcard|app.example.test|10.9.9.9" >>"$W/dns.case"
  export DNS_FIXTURE="$W/dns.case" DNS_LOG="$W/dns.queries"; : >"$DNS_LOG"
  PATH="$W/fakedig:$PATH" run_dns >/dev/null 2>&1; DNS_RC=$?
  IPS=(10.0.0.5); START_EPOCH=$(date +%s); report_prepare
}
run_dns_case standard
assert_eq "run_dns completes" "$DNS_RC" "0"
assert_true "SPF +all is a confirmed finding" grep -q "SPF record allows any sender (+all)" "$FINAL_TSV"
assert_true "mail-enabled host without DMARC noted as potential" bash -c "grep -q 'without DMARC record' '$FINAL_TSV'"
assert_true "single nameserver noted" grep -q "Only one authoritative nameserver" "$FINAL_TSV"
assert_true "missing CAA noted as informational" grep -q "No CAA record published" "$FINAL_TSV"
assert_true "subdomains found by wordlist" bash -c "grep -q '^dev.app.example.test' '$LOG_DIR/subdomains.txt' && grep -q '^old.app.example.test' '$LOG_DIR/subdomains.txt'"
assert_true "GitHub Pages dangling CNAME = takeover INDICATOR (potential)" bash -c "awk -F'\037' '\$4 ~ /Subdomain takeover indicator: old.app.example.test/ {print \$7}' '$FINAL_TSV' | grep -q 'Potential vulnerability'"
assert_true "unknown-provider dangling CNAME is a low-severity potential finding" bash -c "awk -F'\037' '\$4 ~ /Dangling CNAME record: blog/ {print \$3\$7}' '$FINAL_TSV' | grep -q 'LOWPotential vulnerability'"
assert_false "resolving CNAME to a provider is not flagged (and no HTTP request was made)" grep -q "ghost.app.example.test ->" "$FINAL_TSV"
assert_false "no takeover finding is ever 'Confirmed'" bash -c "awk -F'\037' '\$4 ~ /takeover/ {print \$7}' '$FINAL_TSV' | grep -q Confirmed"
assert_false "zone transfer is not attempted outside full mode" grep -q " AXFR " "$DNS_LOG"
assert_false "only names under the approved host (or CNAME targets) were queried" bash -c "grep -vE 'app.example.test|abandoned.github.io|zzz.unknown-provider.net|foo.herokuapp.com' '$DNS_LOG' | grep -q ."
run_dns_case passive
assert_false "passive mode performs no wordlist enumeration" test -s "$LOG_DIR/subdomains.txt"
limits_have() { printf '%s\n' "${LIMITS[@]}" | grep -q "$1"; }
assert_true "passive limitation recorded" limits_have "Passive mode: subdomain enumeration"
run_dns_case standard wildcard
assert_true "wildcard DNS detected and filtered" grep -q "Wildcard DNS record detected" "$FINAL_TSV"
assert_eq "wildcard-only answers do not create subdomains (only dev, old, blog remain)" "$(cut -f1 "$LOG_DIR/subdomains.txt" | tr '\n' ' ')" "blog.app.example.test dev.app.example.test old.app.example.test "
ALLOW_DANGEROUS=0; run_dns_case full
assert_false "zone transfer needs approval (not run, non-interactive)" grep -q "zone transfer (AXFR) permitted" "$FINAL_TSV"
assert_true "denied approval recorded as a limitation" limits_have "AXFR"
ALLOW_DANGEROUS=1; run_dns_case full
assert_true "approved zone transfer reported as HIGH with CVSS 5.3 and no zone content stored" bash -c "awk -F'\037' '\$4 ~ /zone transfer/ {print \$3\"|\"\$13}' '$FINAL_TSV' | grep -qx 'HIGH|5.3'"
assert_false "zone contents are not stored" grep -rq "secret.app.example.test" "$OUTDIR"
ALLOW_DANGEROUS=0
unset DNS_FIXTURE DNS_LOG
# IP targets: nothing to inspect
reset_env; IS_IP=1; HOST=127.0.0.1; run_dns >/dev/null 2>&1; assert_eq "IP target skips the dns module" "$MODULE_STATUS" "SKIPPED"

# =============================================================================================
section "Stage 2: scan comparison"
mk_scan() { # dir ; findings from stdin as "title|url|sev|module"
  reset_env; CURRENT_MODULE=unit
  local t u sv m
  while IFS='|' read -r t u sv m; do CURRENT_MODULE=$m; add_finding "$t" "$u" "Security headers" "$sv" "Confirmed vulnerability" d e t High r >/dev/null; done
  IPS=(127.0.0.1); START_EPOCH=$(date +%s); HOST=lab.test; report_prepare
}
rm -rf "$W/cmp_prev"; mkdir -p "$W/cmp_prev/logs"
mk_scan <<'EOF2'
A header|http://lab.test/|HIGH|http
B header|http://lab.test/|MEDIUM|http
C nikto item|http://lab.test/c|LOW|nikto
D gobuster item|http://lab.test/d|LOW|gobuster
EOF2
cp "$LOG_DIR/findings.final.tsv" "$W/cmp_prev/logs/"; printf 'http\tOK\t1\tx\nnikto\tOK\t1\tx\ngobuster\tOK\t1\tx\n' >"$W/cmp_prev/logs/modules.tsv"
printf 'host=lab.test\ntarget=http://lab.test\n' >"$W/cmp_prev/logs/scan_meta.txt"
mk_scan <<'EOF2'
A header|http://lab.test/|HIGH|http
B header|http://lab.test/|LOW|http
E new header|http://lab.test/e|MEDIUM|http
EOF2
printf 'http\tOK\t1\tx\nnikto\tSKIPPED\t0\tnot installed\ngobuster\tOK\t1\tx\n' >"$MODULES_TSV"
COMPARE_SPEC="$W/cmp_prev"; OUTPUT_ROOT="$W"; compare_scans
assert_eq "counts: new, resolved, persistent, changed, not re-tested" "$CMP_NEW|$CMP_RESOLVED|$CMP_PERSISTENT|$CMP_CHANGED|$CMP_NOTRETESTED" "1|1|1|1|1"
assert_true "severity change recorded with both severities" grep -qP '^CHANGED\t[^\t]+\tLOW\tMEDIUM\tB header' "$CMP_FILE"
assert_true "finding of a module that did not run is NOT called resolved" grep -qP '^NOT_RETESTED\t.*C nikto item' "$CMP_FILE"
assert_true "finding of a module that ran OK and no longer reports it is resolved" grep -qP '^RESOLVED\t.*D gobuster item' "$CMP_FILE"
HOST=other.test; compare_scans; assert_eq "comparison refuses a different host" "$COMPARE_DONE" "0"
assert_true "refusal reason is explained" grep -q "previous scan was for host" <<<"$COMPARE_ERROR"
COMPARE_SPEC="/nonexistent/dir"; HOST=lab.test; compare_scans; assert_eq "missing previous directory is reported" "$COMPARE_DONE|$([[ -n $COMPARE_ERROR ]] && echo err)" "0|err"
COMPARE_SPEC=""

CD="$W/cmp"; mkdir -p "$CD"
"$ROOT/doxa.sh" --target "http://127.0.0.1:$HP" --mode custom --modules recon,http,js,api --authorized --no-color -o "$CD" --rate 500 >"$W/cmp1.log" 2>&1; sleep 1.2
"$ROOT/doxa.sh" --target "http://127.0.0.1:$HP" --mode custom --modules recon,http,js,api --authorized --no-color -o "$CD" --rate 500 --compare auto >"$W/cmp2.log" 2>&1
DC=$(ls -dt "$CD"/127.0.0.1_"$HP"_* | head -1)
assert_true "--compare auto finds the previous scan and reports no changes" python3 -c "
import json;c=json.load(open('$DC/findings.json'))['comparison'];assert c['enabled'] and c['new']==0 and c['resolved']==0 and c['severity_changed']==0 and c['persistent']>10, c"
assert_true "comparison appears in the HTML report" grep -q "15. Comparison with previous scan" "$DC/report.html"
assert_true "comparison appears in the TXT report" grep -q "11. COMPARISON WITH PREVIOUS SCAN" "$DC/report.txt"
assert_true "comparison.csv written" test -s "$DC/comparison.csv"
assert_true "comparison shown in the terminal summary" grep -q "Compared : new 0, resolved 0" "$W/cmp2.log"
"$ROOT/doxa.sh" --target "http://127.0.0.1:$HP" --mode custom --modules recon --authorized --no-color -o "$W/cmp_first" --rate 500 --compare auto >"$W/cmp3.log" 2>&1
DC3=$(ls -dt "$W/cmp_first"/127.0.0.1_"$HP"_* | head -1)
assert_true "--compare auto without a previous scan degrades gracefully" grep -q "Scan comparison was requested but is unavailable" "$DC3/report.txt"

# =============================================================================================
section "Stage 2: PDF export"
if have wkhtmltopdf && have pdftotext; then
  assert_true "report.pdf produced by the standard scan (wkhtmltopdf)" bash -c "head -c 5 '$D/report.pdf' | grep -q '%PDF-'"
  assert_true "PDF is readable and has pages" python3 -c "
from pypdf import PdfReader;r=PdfReader('$D/report.pdf');assert len(r.pages)>=1"
  assert_true "PDF text contains branding and findings" bash -c "pdftotext '$D/report.pdf' - | grep -q 'DOXA' && pdftotext '$D/report.pdf' - | grep -qi 'Exposed environment file'"
  assert_false "no secret values inside the PDF" bash -c "pdftotext '$D/report.pdf' - | grep -qE 'hunter2hunter2|SECRETVALUE123'"
  assert_true "PDF hashed in reports.sha256" grep -q "report.pdf" "$D/logs/reports.sha256"
else
  note "real PDF rendering test skipped (wkhtmltopdf and pdftotext not both installed)"
fi
pdf_case() { reset_env; OUTDIR="$W/pdfcase"; rm -rf "$OUTDIR"; mkdir -p "$OUTDIR/logs"; LOG_DIR="$OUTDIR/logs"; MAIN_LOG="$LOG_DIR/doxa.log"; TOOLS_TSV="$LOG_DIR/tools.tsv"; echo "<html><body>x</body></html>" >"$OUTDIR/report.html"; PDF_STATUS=""; PDF_TOOL=""; NO_PDF=0; }
mkdir -p "$W/fakepdf"
cat >"$W/fakepdf/chromium" <<'FAKECHROMIUM'
#!/bin/sh
for a in "$@"; do case $a in --print-to-pdf=*) f=${a#--print-to-pdf=}; printf '%s\n' '%PDF-1.4' 'fake' >"$f";; esac; done
exit 0
FAKECHROMIUM
printf '#!/bin/sh\necho "render error" >&2\nexit 1\n' >"$W/fakepdf/chromium-broken"
chmod +x "$W/fakepdf/"*
pdf_case; PATH="$W/fakepdf:$PATH" pdf_tool_detect; PATH="$W/fakepdf:$PATH" generate_pdf_report
assert_eq "chromium path: valid PDF accepted" "$PDF_STATUS" "generated with chromium"
pdf_case; cp "$W/fakepdf/chromium-broken" "$W/fakepdf/chromium"; PATH="$W/fakepdf:$PATH" pdf_tool_detect; PATH="$W/fakepdf:$PATH" generate_pdf_report 2>/dev/null
assert_true "failed render is reported, never silent" grep -q "^failed" <<<"$PDF_STATUS"
assert_false "invalid output file is removed" test -e "$OUTDIR/report.pdf"
mkdir -p "$W/nopdf"; for f in /usr/bin/* /bin/*; do b=$(basename "$f"); case $b in chromium*|google-chrome*|wkhtmltopdf|weasyprint) continue ;; esac; [[ -e $W/nopdf/$b ]] || ln -s "$f" "$W/nopdf/$b" 2>/dev/null; done
pdf_case; PATH="$W/nopdf" pdf_tool_detect
assert_true "no PDF tool: skipped with a recorded limitation" bash -c "grep -q '^skipped' <<<'$PDF_STATUS'"
pdf_case; NO_PDF=1; pdf_tool_detect; assert_eq "--no-pdf honoured" "$PDF_STATUS" "disabled (--no-pdf)"
NO_PDF=0

# =============================================================================================
section "Interrupted scan"
python3 - "$ROOT" "$HP" "$W/int" <<'EOF' >"$W/int.result"
import subprocess, sys, time, signal
root, port, out = sys.argv[1:4]
p = subprocess.Popen([root + "/doxa.sh", "--target", "http://127.0.0.1:%s" % port, "--mode", "standard", "--authorized",
                      "--no-color", "-o", out, "--rate", "4"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))  # background shells ignore SIGINT; restore default
time.sleep(7)
p.send_signal(signal.SIGINT)
try:
    rc = p.wait(timeout=60)
except subprocess.TimeoutExpired:
    p.kill(); rc = -999
print(rc)
EOF
assert_eq "SIGINT exits with code 130" "$(cat "$W/int.result")" "130"
DI=$(ls -d "$W/int"/127.0.0.1_"$HP"_* 2>/dev/null | head -1)
assert_true "partial report written after interrupt" test -s "$DI/report.html" -a -s "$DI/findings.json"
assert_true "interrupted module recorded" grep -q "INTERRUPTED" "$DI/logs/modules.tsv"
assert_true "partial findings.json is valid" python3 -c "import json;json.load(open('$DI/findings.json'))"
assert_false "temporary directories cleaned up" bash -c "ls -d /tmp/doxa.* >/dev/null 2>&1"

# =============================================================================================
section "AI integration"
note "Ollama failure handling: AI module is not part of this stage (pending)"

printf '\n==============================\nPassed: %d   Failed: %d   Skipped: %d\n' "$PASS" "$FAIL" "$SKIPPED"
(( FAIL == 0 ))
