# DOXA v2 dependencies

| Tool | Required? | Used by | Debian/Kali package |
|---|---|---|---|
| bash >= 4.4, curl, awk, sed, grep, coreutils (timeout, mktemp, sort, sha256sum, md5sum, od, head, tr, wc, cut, date) | **Required** | everything | `curl gawk sed grep coreutils` |
| openssl | Needed for the `tls` module | tls | `openssl` |
| jq | Needed only to parse Nikto/Nuclei/WhatWeb/sslyze output | nikto, nuclei, whatweb, tls (sslyze) | `jq` |
| nmap | `nmap` module, TLS fallback | nmap, tls | `nmap` |
| nikto | `nikto` module | nikto | `nikto` |
| gobuster (+ wordlist) | `gobuster` module | gobuster | `gobuster dirb seclists` |
| whatweb | `whatweb` module | whatweb | `whatweb` |
| nuclei (+ templates) | `nuclei` module | nuclei | `nuclei` then `nuclei -update-templates` |
| sslyze | optional, preferred for TLS protocol checks | tls | `sslyze` |
| dig | needed for the `dns` module | dns | `dnsutils` |
| subfinder | optional, only with `--dns-passive-sources` | dns | `subfinder` |
| chromium / wkhtmltopdf / weasyprint | optional, for `report.pdf` | pdf | `chromium` or `wkhtmltopdf` or `weasyprint` |
| chromium / gowitness | optional, screenshots | evidence | `chromium` |
| python3 | tests only (lab server, JSON/HTML validation) | tests/ | `python3` |

A module whose tool is missing is recorded as SKIPPED with the reason, and the skip appears in the report.
