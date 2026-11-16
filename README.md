# DOXA Web Security Auditor v2.0.1 (Stage 1)

Scope-enforcing, evidence-first web application assessment and reporting framework for Kali Linux and Debian-based systems, written in Bash.

> **Legal and ethical use.** DOXA is for systems you own or have explicit written permission to test. It never exploits vulnerabilities, extracts credentials, modifies data, uploads files, brute-forces logins or performs denial of service, and it refuses to start without an authorization confirmation. You are responsible for how you use it.

Philosophy: accuracy over the number of detected vulnerabilities, evidence over assumptions, safety over aggressive scanning, useful remediation over flashy output.

## Project status

| Component | Status |
|---|---|
| Modular architecture, config and profiles, launcher, interactive menu | Done |
| Strict target validation (hostname, IPv4, IPv6, URL, port), safe argument handling | Done, tested |
| Approved-host / approved-port scope enforcement, redirect validation at every hop | Done, tested |
| Certificate verification **on by default** (no `curl -k`), `--ca-cert`, explicit `--insecure-tls-diagnostic` | Done, tested |
| Global request rate limiter, configurable timeouts, cleanup on interrupt | Done, tested |
| Findings: consistent schema, dedupe, redaction, OWASP Top 10 (2021) mapping, evidence-based CVSS v3.1 | Done, tested |
| Reports: HTML dashboard, JSON, TXT, CSV, SHA-256 manifests | Done, tested |
| Ported and hardened v1 modules: recon, http, tls, nmap, whatweb, gobuster, nikto, nuclei, params, evidence | Done. recon/http/tls/evidence are exercised by the test suite; the modules that wrap external scanners were hardened but have **not** been executed in the development sandbox (those tools are not installed there) |
| Test suite (141 checks) | Done |
| JavaScript analysis module, API assessment module, DNS/subdomain module | **Pending (Stage 2)** |
| Previous-vs-current scan comparison, PDF export | **Pending (Stage 2)** |
| Local Ollama AI analysis (`--ai`) | **Pending (Stage 3)** |

## Features

- **Profiles** (`--mode`): `passive`, `standard`, `full`, `custom` (choose modules with `--modules`). Passive modules only observe normal responses; active modules send probes or run scanners.
- **Scope control**: only the target host and its port(s) are contacted. Every request made by DOXA, every redirect hop, and every external-tool target is checked first. Blocked attempts are counted and logged in `logs/out_of_scope.log`.
- **TLS verification**: HTTPS requests validate certificates. If validation fails, DOXA reports it (it does not silently bypass it), still inspects the certificate with `openssl`, and skips web modules. Lab CAs: `--ca-cert FILE`. Diagnostics: `--insecure-tls-diagnostic` (recorded in the report and as a finding).
- **Findings**: id, title, description, affected URL, severity, CVSS score/version/vector/justification, OWASP category, confidence, classification (confirmed / potential / informational / unverified), evidence, impact, remediation, module, tool, timestamp, false-positive notes.
- **CVSS honesty**: CVSS v3.1 is attached only where the evidence supports a vector (e.g. a readable `.env` whose variable names indicate credentials = 7.5; repository metadata only = 5.3). Hardening gaps and scanner observations are deliberately *not scored*. Scores are computed by a built-in implementation of the FIRST v3.1 formula and verified against reference vectors.
- **Redaction**: cookie values, `Authorization` headers, bearer tokens, JWTs, cloud keys, passwords and private keys are masked before anything is stored; values from `.env`-style files are never recorded.
- **Evidence integrity**: `logs/evidence.sha256` (raw artefacts) and `logs/reports.sha256` (reports and main log). Verify with `sha256sum -c`.
- **Reports**: `report.html` (dark Matrix-green/cyan dashboard with executive summary, scope and authorization, methodology, technologies, ports, statistics, OWASP table, findings, remediation, tool status, limitations, integrity), `report.txt`, `findings.json`, `findings.csv` (formula-injection safe).

## Architecture

```
doxa.sh                 launcher: CLI, profiles, module orchestration, signals
config/settings.conf    defaults (parsed safely, never sourced)
config/profiles.conf    passive / standard / full / custom profiles
lib/                    logging, common (escaping, redaction, tool runner), validation,
                        scope (scope checks, HTTP client, rate limiter), findings (schema,
                        OWASP map, CVSS), config, ui
modules/                recon http tls nmap whatweb directories(gobuster) nikto nuclei params evidence
reports/                common (sorting, stats, limitations), json (+csv), txt, html
templates/report.html   HTML shell and CSS
tests/                  run_tests.sh and lab_server.py (local intentionally weak server)
install.sh              apt-based dependency installer (--dry-run supported)
```

Design notes:

- `http_fetch` in `lib/scope.sh` is the only HTTP client used by DOXA's own checks; it enforces scope, TLS verification and the global rate limit. External tools receive the same rate value and run one at a time, so the aggregate never exceeds `--rate`.
- Findings are stored in a plain TSV store (`logs/findings.raw.tsv`) and all reports are generated from it in Bash. `jq` is only needed to parse Nikto/Nuclei/WhatWeb/sslyze output.
- Modules never abort the audit. Each result is `OK`, `FAILED`, `TIMEOUT`, `SKIPPED` or `INTERRUPTED` with a reason, and anything not `OK` appears in the report's limitations.
- Nikto, Nuclei and WhatWeb handle TLS themselves; DOXA cannot force certificate validation inside them. They only run after DOXA's own verified request to the service succeeded, and this limitation is recorded in the report.

## Installation (Kali / Debian)

```bash
git clone <your-repo> doxa-web-security-auditor && cd doxa-web-security-auditor
./install.sh            # or: ./install.sh --dry-run
./doxa.sh --check-tools
```

See `DEPENDENCIES.md`. Only bash >= 4.4, curl and standard coreutils are strictly required.

## Usage

```bash
./doxa.sh --target https://example.com --mode passive
./doxa.sh --target http://127.0.0.1:3000 --mode standard --authorized
./doxa.sh --target https://lab.local --ca-cert ./lab-ca.pem --scope-host api.lab.local --authorized
./doxa.sh --target "https://[::1]:8443" --mode custom --modules recon,http,tls --authorized
./doxa.sh --target http://10.10.10.5:8080 --mode full --rate 20 --threads 5 --skip nikto
./doxa.sh                      # interactive menu
./doxa.sh --check-tools
```

### CLI options

| Option | Meaning |
|---|---|
| `-u, --target URL` | Target (hostname, IPv4, `[IPv6]`, optional port/path) |
| `-m, --mode NAME` | `passive`, `standard` (default), `full`, `custom` |
| `--modules LIST` | Modules for `--mode custom` |
| `--skip LIST` | Modules to skip |
| `-o, --output DIR` | Report root (default `./reports_out`) |
| `-t, --threads N` / `-r, --rate N` | Concurrency (1-100) / global requests per second (1-1000) |
| `--timeout SEC` / `--http-timeout SEC` | Per-tool / per-request timeouts |
| `-w, --wordlist FILE` | Gobuster wordlist |
| `--authorized` | Confirm authorization non-interactively (otherwise you must type `I AUTHORIZE`) |
| `--scope-host H` / `--scope-port P` | Approve additional hosts (`api.x.com`, `10.0.0.7`, `*.x.com`) or ports. Nmap is restricted to approved ports when you pass `--scope-port` |
| `--ca-cert FILE` | Trust a lab CA |
| `--insecure-tls-diagnostic` | Disable certificate verification (authorized diagnostics only) |
| `--allow-dangerous` | Pre-approve checks that otherwise ask (parameter probing, nuclei default-login) |
| `--oast` | Allow Nuclei out-of-band checks (contacts a third-party server) |
| `--check-tools`, `--no-color`, `-v`, `-h`, `--version` | Utilities |

### Scan profiles

| Profile | Modules | Notes |
|---|---|---|
| passive | recon whatweb http tls evidence | normal page requests only; no path guessing |
| standard | + nmap gobuster nikto nuclei | safe Nikto tuning, Nuclei excludes intrusive/DoS/fuzz/brute-force/default-login |
| full | + params | deeper scans; parameter probing and default-login need approval |
| custom | `--modules` | any subset |

Exit codes: `0` ok, `1` usage/validation, `2` missing required tool, `3` module failures, `4` HIGH/CRITICAL findings, `130` interrupted.

## Reports

```
reports_out/<host>_<timestamp>/
├── report.html  report.txt  findings.json  findings.csv  reconnaissance.txt
├── nmap/ nuclei/ nikto/ gobuster/ screenshots/
└── logs/   doxa.log  modules.tsv  tools.tsv  findings.raw.tsv  findings.final.tsv
            evidence.sha256  reports.sha256  out_of_scope.log  headers_*.txt (cookies redacted)
```

A real example generated against the local lab is in `examples/local-lab-standard-scan/`. In the sandbox where it was produced only `curl` and `openssl` were installed, so the nmap, whatweb, gobuster, nikto and nuclei modules appear as SKIPPED, exactly as they would on a system without those tools.

## Testing

```bash
tests/run_tests.sh
```

The suite starts `tests/lab_server.py` (127.0.0.1 only, intentionally misconfigured, with an HTTP and a self-signed HTTPS listener) and checks: invalid target input, URL/IPv4/IPv6 parsing, scope enforcement, redirect handling (off-host, off-port, loops, limits), TLS verification (rejected by default, `--ca-cert`, diagnostic override), rate limiting, missing dependencies, module failure/timeout/skip recording, interrupted scans (SIGINT, partial report), finding normalization, dedupe, redaction and CVSS, JSON validity, HTML escaping and structure, CSV injection safety, hash manifests, and end-to-end scans. Nothing outside loopback is contacted. The AI failure-handling test is pending with the AI module.

For realistic lab practice use DVWA or OWASP Juice Shop locally (see the v1 README for `docker run` examples) and always add `--authorized` only for targets you control.

## Known limitations

- Unauthenticated black-box scope; no login or business-logic testing.
- DOXA does not pin DNS results; scope is enforced by hostname and port.
- IPv6 zone identifiers and embedded-IPv4 IPv6 notation are rejected.
- ShellCheck was not available in the development sandbox; run `shellcheck doxa.sh lib/*.sh modules/*.sh reports/*.sh` on your machine.

## License

MIT (see `LICENSE`) with an authorized-use notice.
# Web-security-Auditor
