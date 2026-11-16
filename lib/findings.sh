# shellcheck shell=bash
# DOXA finding management.
#
# Storage: one record per line in logs/findings.raw.tsv, fields separated by US (0x1f);
# newlines inside a field are stored as RS (0x1e). Reports are generated from this store.
#
# Record layout (19 fields):
#  1 fingerprint  2 severity  3 title  4 url  5 category  6 classification  7 confidence
#  8 module  9 tool  10 timestamp  11 owasp  12 cvss_score  13 cvss_vector  14 cvss_justification
#  15 description  16 impact  17 evidence  18 remediation  19 false_positive_notes
shopt -u patsub_replacement 2>/dev/null || true

readonly FS=$'\037' RS=$'\036'
FINDINGS_TSV="${FINDINGS_TSV:-/dev/null}"
declare -A FIND_SEEN=()
FIND_DUP=0
FIND_COUNT=0

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) mapping. Indicative only: an automated mapping is not a
# statement of OWASP compliance or non-compliance.
# ---------------------------------------------------------------------------
owasp_for() { # category title
  local c=$1 t=${2,,}
  case $t in
    *hsts*|*https*|*"tls "*|*tls\ *|*certificate*|*"protocol"*|*cipher*|*cleartext*|*unencrypted*) printf 'A02:2021 Cryptographic Failures'; return ;;
    *"cors"*"credentials"*) printf 'A01:2021 Broken Access Control'; return ;;
    *ssrf*) printf 'A10:2021 Server-Side Request Forgery'; return ;;
  esac
  case $c in
    "TLS configuration"|"Transport security") printf 'A02:2021 Cryptographic Failures' ;;
    "Session management") printf 'A07:2021 Identification and Authentication Failures' ;;
    "Known vulnerable software") printf 'A06:2021 Vulnerable and Outdated Components' ;;
    "Injection indicators"|"Cross-Site Scripting indicators"|"SQL injection indicators"|"Injection / code execution") printf 'A03:2021 Injection' ;;
    "CORS misconfiguration") printf 'A05:2021 Security Misconfiguration' ;;
    "Security headers"|"Security misconfiguration"|"Information disclosure"|"Sensitive file exposure"|"Exposed network service"|"Attack surface"|"API security"|"JavaScript security"|"DNS configuration")
      printf 'A05:2021 Security Misconfiguration' ;;
    "Subdomain takeover indicators") printf 'A05:2021 Security Misconfiguration' ;;
    *) printf 'Not mapped (informational)' ;;
  esac
}

impact_for() { # category severity
  case $1 in
    "Security headers") printf 'Browsers are not instructed to apply defence-in-depth protections, which makes exploitation of other flaws (XSS, clickjacking, downgrade attacks) easier.' ;;
    "Session management") printf 'Session cookies may be exposed to script access or sent over insecure channels, increasing the risk of session theft.' ;;
    "Transport security"|"TLS configuration") printf 'Traffic may be intercepted or modified in transit, exposing credentials and user data.' ;;
    "Sensitive file exposure") printf 'Sensitive configuration, source code or data may be disclosed to unauthenticated users, enabling follow-on attacks.' ;;
    "Information disclosure") printf 'Technical details help attackers choose and tune attacks against the system.' ;;
    "CORS misconfiguration") printf 'A malicious website may be able to read responses from this application in a victim browser.' ;;
    "Exposed network service") printf 'Unnecessary network exposure enlarges the attack surface of the host.' ;;
    "Known vulnerable software") printf 'Known vulnerabilities in outdated components may be exploitable by attackers.' ;;
    "Injection indicators"|"Cross-Site Scripting indicators"|"SQL injection indicators") printf 'If confirmed, attackers could run script in victims browsers or manipulate backend queries. Manual verification is required.' ;;
    "Security misconfiguration") printf 'Weak configuration may expose unnecessary functionality or information.' ;;
    "Attack surface") printf 'Exposed administrative or sensitive interfaces are attractive targets for credential attacks.' ;;
    *) printf 'No direct security impact; the observation provides context for the assessment.' ;;
  esac
}

# ---------------------------------------------------------------------------
# CVSS v3.1 base score calculator (FIRST specification, Roundup per Appendix A).
# cvss31_score "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" -> prints score, returns 1 if invalid.
# ---------------------------------------------------------------------------
cvss31_score() {
  local v=${1#CVSS:3.1/}
  awk -v vec="$v" '
    function roundup(x,   i) { i = int(x * 100000 + 0.5); if (i % 10000 == 0) return i / 100000; return (int(i / 10000) + 1) / 10 }
    BEGIN {
      n = split(vec, p, "/")
      for (k = 1; k <= n; k++) { split(p[k], kv, ":"); m[kv[1]] = kv[2] }
      split("AV AC PR UI S C I A", req, " ")
      for (k = 1; k <= 8; k++) if (!(req[k] in m)) exit 1
      av = (m["AV"]=="N")?0.85:(m["AV"]=="A")?0.62:(m["AV"]=="L")?0.55:(m["AV"]=="P")?0.2:-1
      ac = (m["AC"]=="L")?0.77:(m["AC"]=="H")?0.44:-1
      ui = (m["UI"]=="N")?0.85:(m["UI"]=="R")?0.62:-1
      sc = m["S"]; if (sc != "U" && sc != "C") exit 1
      if (m["PR"]=="N") pr = 0.85
      else if (m["PR"]=="L") pr = (sc=="U")?0.62:0.68
      else if (m["PR"]=="H") pr = (sc=="U")?0.27:0.5
      else exit 1
      c = (m["C"]=="H")?0.56:(m["C"]=="L")?0.22:(m["C"]=="N")?0:-1
      i = (m["I"]=="H")?0.56:(m["I"]=="L")?0.22:(m["I"]=="N")?0:-1
      a = (m["A"]=="H")?0.56:(m["A"]=="L")?0.22:(m["A"]=="N")?0:-1
      if (av<0||ac<0||ui<0||c<0||i<0||a<0) exit 1
      iss = 1 - (1-c)*(1-i)*(1-a)
      if (sc=="U") imp = 6.42 * iss; else imp = 7.52*(iss-0.029) - 3.25*((iss-0.02)^15)
      ex = 8.22 * av * ac * pr * ui
      if (imp <= 0) { printf "0.0\n"; exit 0 }
      if (sc=="U") base = roundup((imp+ex > 10) ? 10 : imp+ex)
      else base = roundup((1.08*(imp+ex) > 10) ? 10 : 1.08*(imp+ex))
      printf "%.1f\n", base
    }'
}

cvss_rating() { # score -> None/Low/Medium/High/Critical
  awk -v s="$1" 'BEGIN{ if (s==0) print "None"; else if (s<4) print "Low"; else if (s<7) print "Medium"; else if (s<9) print "High"; else print "Critical" }'
}

# ---------------------------------------------------------------------------
# add_finding title url category severity classification description evidence tool confidence \
#             remediation [fp_notes] [impact] [cvss_vector] [cvss_justification]
# classification: "Confirmed vulnerability" | "Potential vulnerability" |
#                 "Informational observation" | "False positive or unverified result"
# CVSS is attached ONLY when a vector is supplied together with its justification.
# ---------------------------------------------------------------------------
tsv_field() { # sanitise one field for the store
  local s
  s=$(printf '%s' "$1" | LC_ALL=C tr -cd '\11\12\40-\176')
  s=${s//$FS/ }; s=${s//$RS/ }; s=${s//$'\t'/ }; s=${s//$'\r'/}
  s=${s//$'\n'/$RS}
  printf '%s' "$s"
}

add_finding() {
  local title=$1 url=$2 category=$3 severity=$4 status=$5 desc=$6 evidence=$7 tool=$8 conf=$9
  local remediation=${10:-} fp=${11:-} impact=${12:-} vector=${13:-} cvj=${14:-}
  local owasp score="" fp_hash key ts
  case $severity in CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL) ;; *) severity=INFORMATIONAL ;; esac
  case $status in
    "Confirmed vulnerability"|"Potential vulnerability"|"Informational observation"|"False positive or unverified result") ;;
    *) status="False positive or unverified result" ;;
  esac
  key="${title,,}|${url%/}|${category,,}"
  fp_hash=$(printf '%s' "$key" | sha256sum | cut -c1-12)
  if [[ -n ${FIND_SEEN[$fp_hash]:-} ]]; then
    FIND_DUP=$((FIND_DUP + 1)); log DEDUP "duplicate finding suppressed: $title ($url)"
    return 0
  fi
  FIND_SEEN[$fp_hash]=1
  evidence=$(printf '%s' "$evidence" | head -c 2500 | redact_text)
  desc=$(printf '%s' "$desc" | redact_text)
  owasp=$(owasp_for "$category" "$title")
  [[ -n $impact ]] || impact=$(impact_for "$category" "$severity")
  if [[ -n $vector && -n $cvj ]]; then
    if score=$(cvss31_score "$vector") && [[ -n $score ]]; then :; else
      log WARN "invalid CVSS vector for '$title': $vector"; score=""; vector=""; cvj="Vector rejected as invalid; not scored."
    fi
  else
    vector=""; score=""
    cvj="Not scored: no directly demonstrated impact, or insufficient evidence for a defensible CVSS vector."
  fi
  ts=$(now_iso)
  printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
    "$fp_hash" "$severity" "$(tsv_field "$title")" "$(tsv_field "$url")" "$(tsv_field "$category")" "$status" "$(tsv_field "$conf")" \
    "$(tsv_field "${CURRENT_MODULE:-core}")" "$(tsv_field "$tool")" "$ts" "$(tsv_field "$owasp")" "$score" "$vector" "$(tsv_field "$cvj")" \
    "$(tsv_field "$desc")" "$(tsv_field "$impact")" "$(tsv_field "$evidence")" "$(tsv_field "$remediation")" "$(tsv_field "$fp")" >>"$FINDINGS_TSV"
  FIND_COUNT=$((FIND_COUNT + 1))
  printf '    %s %s\n' "$(sev_tag "$severity")" "$title"
  log FINDING "[$severity] $title ($url)"
}

finding_exists() { # title url category -> true when an identical finding was already recorded
  local h; h=$(printf '%s' "${1,,}|${2%/}|${3,,}" | sha256sum | cut -c1-12)
  [[ -n ${FIND_SEEN[$h]:-} ]]
}

count_findings() { wc -l <"$FINDINGS_TSV" 2>/dev/null | tr -d ' '; }
