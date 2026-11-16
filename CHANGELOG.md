# Changelog

## 2.0.1 - fixes from the first real-world scan (DVWA on Kali)

- **Nuclei module failed (exit 2).** `nuclei -h | grep -q -jsonl` ran under `set -o pipefail`; `grep -q` exits early, nuclei receives SIGPIPE, the pipeline reports failure, and DOXA fell back to the invalid `-json` flag. The help text is now captured before matching (`nuclei_json_flag`); the same pattern was removed from the TLS and HTTP modules. Failure details now include the last lines of the tool log.
- **Root redirects.** When `/` redirects (DVWA: 302 to `login.php`), security headers were analysed on the empty 302. DOXA now follows the in-scope redirect, analyses the final page (affected URL, evidence and page title come from it) and collects `Set-Cookie` headers from every hop.
- Cookie names are no longer repeated in cookie findings.
- TXT report: the last evidence line no longer runs into the "Remediation" line.
- Nikto "Directory indexing" items are not duplicated when DOXA already confirmed the same listing.
- Gobuster: `.ini`, `.yml`, `.yaml`, `.cfg`, `.inc`, `.env` files returning 200 are flagged for manual verification (for example `php.ini`).
- Version column of `--check-tools` no longer prints usage/error text for gobuster and sslyze; it falls back to the package version.
- Information-disclosure evidence shows the real header line.
- Tests: 12 new regression tests (141 total).

## 2.0.0 (Stage 1) - 2026-11-15

### Security and scope
- **TLS verification is now on by default.** v1 used `curl -k` (and gobuster `-k`) for every request. v2 validates certificates, reports validation failures as findings instead of bypassing them, supports `--ca-cert`, and offers a separate, recorded `--insecure-tls-diagnostic` override.
- **Approved-host / approved-port scope.** Every DOXA request, every redirect hop and every external-tool target is checked. v1 only compared hostnames on redirects and let WhatWeb follow redirects anywhere; v2 sets WhatWeb `--max-redirects=0`.
- Redirect validation: scope, loop detection, redirect limit, HTTPS-to-HTTP downgrade finding.
- Global request rate limiter (`--rate`) shared by all DOXA requests; the same value is passed to nmap (`--max-rate`), nuclei (`-rl`) and gobuster (delay).
- Strict parsing of IPv4, IPv6 (bracketed), hostnames and ports; rejects credentials in URLs, whitespace, control characters, backslashes, traversal segments.
- Config files are parsed with a whitelist, never `source`d. Output directory and numeric options are validated.
- Redaction of tokens, passwords, JWTs, cloud keys, private keys and cookie values before storage (v1 relied on per-check redaction only).

### Findings and reporting
- New finding schema: id, fingerprint, impact, OWASP Top 10 (2021) category, CVSS v3.1 score/vector/justification (only when evidence supports it), module and tool.
- Built-in CVSS v3.1 calculator, verified against reference vectors (9.8, 6.1, 7.5, 5.3, 7.8, 10.0).
- Deduplication at record time; invalid classifications are downgraded to "unverified".
- Reports are generated in pure Bash from one findings store: HTML dashboard, JSON, TXT and new CSV export. v1's `jq`-based report code could not be verified end-to-end and has been replaced; `jq` is now only needed to parse third-party tool output.
- SHA-256 manifests for raw artefacts and reports; scope, authorization and TLS-verification state recorded in every report.
- Exposure checks attach CVSS only when the evidence supports it (for example `.env` variable names indicating credentials).

### Architecture and UX
- Split the 1,700-line `doxa.sh` into `lib/`, `modules/`, `reports/`, `config/` and `templates/`; v1 check logic was preserved.
- Profiles (`passive`, `standard`, `full`, `custom`), `--modules`, `--scope-host`, `--scope-port`, interactive menu, `--target`/`--mode` aliases.
- Modules not in the profile or skipped by `--skip` are recorded in the report instead of disappearing.
- Nikto/Nuclei parsers rewritten to feed the common `add_finding` path (shared dedupe, redaction, OWASP and ids).
- TLS module now analyses the certificate even when the HTTPS service fails verification, and honours `--ca-cert`.

### Fixed from v1
- `hdr_excerpt`-style helper gaps and report variables that were never exercised.
- Findings printed with empty evidence for missing headers.
- Report ids were assigned inconsistently; ids are now assigned after severity sorting.

### Testing
- `tests/run_tests.sh`: 141 checks against a local lab server (see README).

### Pending (next stages)
- Stage 2: JavaScript analysis, API assessment, DNS/subdomain checks, scan comparison, PDF export.
- Stage 3: local Ollama analysis (`--ai`), final polishing.
