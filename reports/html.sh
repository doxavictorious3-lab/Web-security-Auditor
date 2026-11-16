# shellcheck shell=bash
# DOXA HTML report (report.html), assembled from templates/report.html
shopt -u patsub_replacement 2>/dev/null || true

_h() { html_escape "$1"; }

_html_section_summary() {
  local B=$1 s st i=0 id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn
  {
    printf '<nav>'
    for s in summary scope methodology tech ports stats owasp findings remediation tools limits integrity; do printf '<a href="#%s">%s</a>' "$s" "$s"; done
    printf '</nav>\n<section id="summary"><h2>1. Executive summary</h2>\n'
    printf '<p>An automated, non-destructive assessment of <code>%s</code> was performed in <b>%s</b> mode. DOXA recorded <b>%s</b> finding(s) after de-duplication. ' \
      "$(_h "$TARGET_URL")" "$(_h "$MODE")" "$TOTAL"
    printf 'Overall risk rating: <span class="risk">%s</span>.</p>\n<div class="cards">' "$OVERALL_RISK"
    for s in "${SEVERITIES[@]}"; do printf '<div class="card c-%s"><b>%s</b>%s</div>' "$s" "${SEV_COUNT[$s]}" "$s"; done
    printf '</div>\n<p class="note">Findings are classified as confirmed vulnerability, potential vulnerability, informational observation, or unverified result. '
    printf 'Potential and unverified items need manual validation. Severity reflects evidence and potential impact, not scanner alert volume.</p>\n'
    printf '<h4>Highest-priority findings</h4>'
    if (( CNT_CRITICAL + CNT_HIGH + CNT_MEDIUM > 0 )); then
      printf '<ol>'
      while IFS=$'\037' read -r id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn; do
        [[ $sev == LOW || $sev == INFORMATIONAL ]] && continue
        i=$((i + 1)); (( i > 5 )) && break
        printf '<li><span class="badge sev-%s">%s</span><a href="#%s" style="color:var(--cyan)">%s</a> &mdash; %s</li>' "$sev" "$sev" "$id" "$(_h "$title")" "$(_h "$status")"
      done <"$FINAL_TSV"
      printf '</ol>'
    else
      printf '<p>No findings of medium or higher severity were recorded.</p>'
    fi
    printf '</section>\n'
  } >>"$B"
}

_html_section_scope() {
  local B=$1
  {
    printf '<section id="scope"><h2>2. Scope and authorization</h2><table>'
    printf '<tr><th>In-scope target</th><td>%s</td></tr>' "$(_h "$TARGET_URL")"
    printf '<tr><th>Authorization</th><td>Operator confirmed ownership of, or written permission to test, the target (method: %s, at %s).</td></tr>' "$(_h "${AUTH_METHOD:-unknown}")" "$(_h "${AUTH_TIME:-n/a}")"
    printf '<tr><th>Approved hosts</th><td>%s</td></tr>' "$(_h "${SCOPE_HOSTS[*]}")"
    printf '<tr><th>Approved ports</th><td>%s%s</td></tr>' "$(_h "${SCOPE_PORTS[*]}")" "$( ((${SCOPE_PORTS_DEFAULTED:-1})) && echo ' (default from target URL)' )"
    printf '<tr><th>Out-of-scope requests blocked</th><td>%s</td></tr>' "$SCOPE_OOS_COUNT"
    printf '<tr><th>TLS certificate verification</th><td>%s</td></tr>' "$( ((INSECURE_TLS)) && echo '<b style="color:var(--crit)">DISABLED (explicit diagnostic override)</b>' || echo 'Enabled' )"
    printf '<tr><th>Mode / rate / threads</th><td>%s / %s requests per second / %s</td></tr>' "$(_h "$MODE")" "$RATE" "$THREADS"
    printf '<tr><th>Out of scope by design</th><td>Exploitation, credential extraction, data modification, brute force, denial of service, authenticated testing.</td></tr>'
    printf '</table></section>\n'
    printf '<section id="target"><h2>3. Target information</h2><table>'
    printf '<tr><th>Hostname</th><td>%s</td></tr><tr><th>Resolved IP(s)</th><td>%s</td></tr>' "$(_h "$HOST")" "$(_h "${IPS[*]}")"
    printf '<tr><th>Primary service</th><td>%s</td></tr><tr><th>HTTP / HTTPS reachable</th><td>%s / %s</td></tr>' "$(_h "${SCAN_BASE:-none}")" "$( ((HTTP_OK)) && echo yes || echo no )" "$( ((HTTPS_OK)) && echo yes || echo no )"
    printf '<tr><th>Server header</th><td>%s</td></tr><tr><th>Page title</th><td>%s</td></tr>' "$(_h "${SERVER_HDR:-n/a}")" "$(_h "${PAGE_TITLE:-n/a}")"
    printf '<tr><th>Operator</th><td>%s</td></tr><tr><th>Started / finished</th><td>%s / %s (%s seconds)</td></tr></table></section>\n' \
      "$(_h "$(whoami 2>/dev/null)@$(hostname 2>/dev/null)")" "$START_ISO" "$END_ISO" "$DURATION"
  } >>"$B"
}

_html_section_method() {
  local B=$1 line
  {
    printf '<section id="methodology"><h2>4. Testing methodology</h2><ol>'
    printf '<li><b>Reconnaissance</b> &ndash; target validation, DNS, HTTP/HTTPS detection, scope-checked redirect chain, robots.txt, sitemap.xml, soft-404 baseline.</li>'
    printf '<li><b>Port and service assessment</b> &ndash; Nmap service detection with safe NSE scripts.</li>'
    printf '<li><b>Fingerprinting</b> &ndash; WhatWeb technology identification.</li>'
    printf '<li><b>HTTP security</b> &ndash; headers, cookies, redirects, CORS, TRACE, content-validated exposed-file probes, directory listing.</li>'
    printf '<li><b>TLS</b> &ndash; certificate validity, trust, hostname match, signature/key strength, protocol support.</li>'
    printf '<li><b>Enumeration and scanning</b> &ndash; Gobuster (wildcard filtering), Nikto (safe tuning), Nuclei (non-intrusive templates), optional approved parameter indicators.</li>'
    printf '<li><b>Normalisation</b> &ndash; de-duplication by title, URL and category; OWASP Top 10 (2021) mapping; CVSS v3.1 only where evidence supports a vector.</li></ol>'
    printf '<h4>Modules executed</h4><table class="grid"><tr><th>Module</th><th>Status</th><th>Duration</th><th>Detail</th></tr>'
    local name mst dur detail
    while IFS=$'\t' read -r name mst dur detail; do
      [[ -n $name ]] || continue
      printf '<tr><td>%s</td><td class="st-%s">%s</td><td>%ss</td><td>%s</td></tr>' "$(_h "$name")" "$(_h "$mst")" "$(_h "$mst")" "$(_h "$dur")" "$(_h "$detail")"
    done <"$MODULES_TSV"
    printf '</table></section>\n'
    printf '<section id="tech"><h2>5. Technologies detected</h2>'
    if [[ -n $(report_technologies) ]]; then printf '<ul>'; while IFS= read -r line; do printf '<li>%s</li>' "$(_h "$line")"; done < <(report_technologies); printf '</ul>'
    else printf '<p>No technologies detected.</p>'; fi
    printf '</section>\n<section id="ports"><h2>6. Open ports and services</h2>'
    if [[ -s $LOG_DIR/open_ports.txt ]]; then printf '<pre>%s</pre>' "$(_h "$(cat "$LOG_DIR/open_ports.txt")")"; else printf '<p>No port scan data (nmap not run, skipped or no open ports).</p>'; fi
    printf '</section>\n'
  } >>"$B"
}

_html_section_stats() {
  local B=$1 s st k t=$TOTAL col n
  (( t > 0 )) || t=1
  {
    printf '<section id="stats"><h2>7. Vulnerability statistics</h2><h4>Severity distribution</h4><table class="grid"><tr><th>Severity</th><th>Count</th><th>Distribution</th></tr>'
    for s in "${SEVERITIES[@]}"; do
      case $s in CRITICAL) col="#ff2d55" ;; HIGH) col="#ff6b35" ;; MEDIUM) col="#ffc107" ;; LOW) col="#3fa9f5" ;; *) col="#8a9ba8" ;; esac
      n=${SEV_COUNT[$s]}
      printf '<tr><td><span class="badge sev-%s">%s</span></td><td>%s</td><td><div class="bar"><span style="width:%s%%;background:%s"></span></div></td></tr>' "$s" "$s" "$n" "$(( n * 100 / t ))" "$col"
    done
    printf '</table><h4>By classification</h4><table class="grid"><tr><th>Classification</th><th>Count</th><th>Distribution</th></tr>'
    for st in "${STATUSES[@]}"; do
      n=${STATUS_COUNT[$st]}
      printf '<tr><td>%s</td><td>%s</td><td><div class="bar"><span style="width:%s%%;background:#00e5ff"></span></div></td></tr>' "$(_h "$st")" "$n" "$(( n * 100 / t ))"
    done
    printf '</table><p class="note">CVSS v3.1 scores are attached to %s finding(s) where the evidence supports a defensible vector; all other findings are intentionally unscored. Duplicate findings suppressed: %s.</p></section>\n' "$CVSS_SCORED" "$FIND_DUP"
    printf '<section id="owasp"><h2>8. OWASP Top 10 (2021) mapping</h2><table class="grid"><tr><th>Category</th><th>Findings</th></tr>'
    for k in "${!OWASP_COUNT[@]}"; do printf '%s\t%s\n' "$k" "${OWASP_COUNT[$k]}"; done | LC_ALL=C sort \
      | while IFS=$'\t' read -r k n; do printf '<tr><td>%s</td><td>%s</td></tr>' "$(_h "$k")" "$n"; done
    printf '</table><p class="note">The mapping is indicative. Automated checks cannot establish OWASP compliance or non-compliance.</p></section>\n'
  } >>"$B"
}

_html_section_findings() {
  local B=$1 id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn
  printf '<h2 id="findings">9. Detailed findings</h2>\n' >>"$B"
  if (( TOTAL == 0 )); then printf '<section><p>No findings were recorded.</p></section>\n' >>"$B"; return; fi
  while IFS=$'\037' read -r id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn; do
    {
      printf '<article id="%s"><div class="fhead sev-%s"><span class="badge sev-%s">%s</span><h3>%s: %s</h3></div><table>' "$id" "$sev" "$sev" "$sev" "$id" "$(_h "$title")"
      printf '<tr><th>Classification</th><td>%s</td></tr><tr><th>Affected URL</th><td>%s</td></tr><tr><th>OWASP Top 10</th><td>%s</td></tr>' "$(_h "$status")" "$(_h "$url")" "$(_h "$owasp")"
      if [[ -n $cs ]]; then
        printf '<tr><th>CVSS v3.1</th><td><b>%s</b> (%s) <code>%s</code></td></tr>' "$cs" "$(cvss_rating "$cs")" "$(_h "$cv")"
      else
        printf '<tr><th>CVSS</th><td>Not scored</td></tr>'
      fi
      printf '<tr><th>CVSS justification</th><td>%s</td></tr><tr><th>Confidence</th><td>%s</td></tr>' "$(_h "$cj")" "$(_h "$conf")"
      printf '<tr><th>Detection module / tool</th><td>%s / %s</td></tr><tr><th>Timestamp</th><td>%s</td></tr></table>' "$(_h "$module")" "$(_h "$tool")" "$(_h "$ts")"
      printf '<h4>Description</h4><p>%s</p><h4>Evidence</h4><pre>%s</pre><h4>Business impact</h4><p>%s</p><h4>Remediation</h4><p>%s</p>' \
        "$(_h "$(unesc "$desc")")" "$(_h "$(unesc "$ev")")" "$(_h "$(unesc "$impact")")" "$(_h "$rem")"
      printf '<h4>False-positive considerations</h4><p>%s</p></article>\n' "$(_h "${fpn:-None noted.}")"
    } >>"$B"
  done <"$FINAL_TSV"
}

_html_section_tail() {
  local B=$1 id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn
  local -A rem_ids=(); local -a rem_order=(); local r
  while IFS=$'\037' read -r id fp sev title url cat status conf module tool ts owasp cs cv cj desc impact ev rem fpn; do
    [[ $sev == INFORMATIONAL || -z $rem ]] && continue
    if [[ -z ${rem_ids[$rem]:-} ]]; then rem_order+=("$rem"); rem_ids[$rem]=$id; else rem_ids[$rem]+=", $id"; fi
  done <"$FINAL_TSV"
  {
    printf '<section id="remediation"><h2>10. Remediation recommendations</h2>'
    if (( ${#rem_order[@]} )); then
      printf '<ol>'; for r in "${rem_order[@]}"; do printf '<li>%s <span class="note">(%s)</span></li>' "$(_h "$r")" "$(_h "${rem_ids[$r]}")"; done; printf '</ol>'
    else printf '<p>No remediation actions required for the recorded findings.</p>'; fi
    printf '<p class="note">Recommendations are ordered by the highest-severity finding they address.</p></section>\n'
    printf '<section id="tools"><h2>11. Tool execution status</h2><table class="grid"><tr><th>Tool</th><th>Command</th><th>Exit</th><th>Time</th></tr>'
    local label cmd rc dur logf
    while IFS=$'\t' read -r label cmd rc dur logf; do
      [[ -n $label ]] || continue
      printf '<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%ss</td></tr>' "$(_h "$label")" "$(_h "$cmd")" "$(_h "$rc")" "$(_h "$dur")"
    done <"$TOOLS_TSV"
    printf '</table><h4>Tool versions</h4><pre>'
    local k; for k in "${!TOOL_VER[@]}"; do printf '%s: %s\n' "$(_h "$k")" "$(_h "${TOOL_VER[$k]}")"; done | LC_ALL=C sort
    printf '</pre></section>\n<section id="limits"><h2>12. Scan limitations</h2><ul>'
    local line; while IFS= read -r line; do printf '<li>%s</li>' "$(_h "$line")"; done < <(report_limitations)
    printf '</ul></section>\n<section id="integrity"><h2>13. Evidence integrity (SHA-256)</h2>'
    printf '<p>Raw artefacts were hashed before the reports were written (<code>logs/evidence.sha256</code>). Report files and the main log are hashed in <code>logs/reports.sha256</code>. Verify with <code>sha256sum -c</code> from the report directory.</p>'
    if [[ -s $LOG_DIR/evidence.sha256 ]]; then
      printf '<table class="grid"><tr><th>File</th><th>SHA-256</th></tr>'
      local h p n=0
      while read -r h p; do
        n=$((n + 1)); (( n > 80 )) && { printf '<tr><td colspan="2">... %s more entries in the manifest</td></tr>' "$(( $(wc -l <"$LOG_DIR/evidence.sha256") - 80 ))"; break; }
        printf '<tr><td>%s</td><td><code>%s</code></td></tr>' "$(_h "${p#\*}")" "$h"
      done <"$LOG_DIR/evidence.sha256"
      printf '</table>'
    fi
    if compgen -G "$OUTDIR/screenshots/*.png" >/dev/null; then
      local shot; shot=$(compgen -G "$OUTDIR/screenshots/*.png" | head -1)
      if (( $(wc -c <"$shot") < 3000000 )); then printf '<h4>Captured home page screenshot</h4><img class="shot" alt="Home page screenshot" src="data:image/png;base64,%s">' "$(base64 -w0 "$shot")"; fi
    fi
    printf '</section>\n'
  } >>"$B"
}

generate_html_report() {
  local B="$TMPD/report.body" H="$OUTDIR/report.html" tpl="$DOXA_HOME/templates/report.html"
  [[ -r $tpl ]] || { err "report template missing: $tpl"; return 1; }
  : >"$B"
  _html_section_summary "$B"; _html_section_scope "$B"; _html_section_method "$B"
  _html_section_stats "$B"; _html_section_findings "$B"; _html_section_tail "$B"
  awk -v target="$(_h "$TARGET_URL")" -v ver="$DOXA_VERSION" -v bodyf="$B" '
    /@@BODY@@/ { while ((getline l < bodyf) > 0) print l; close(bodyf); next }
    { i = index($0, "@@TARGET@@"); if (i) $0 = substr($0, 1, i - 1) target substr($0, i + 10)
      i = index($0, "@@VERSION@@"); if (i) $0 = substr($0, 1, i - 1) ver substr($0, i + 11)
      print }' "$tpl" >"$H"
}
