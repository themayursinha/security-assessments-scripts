# Security Assessment Scripts

A collection of small Python scripts for security assessment practice, network
experimentation, web scraping, and Python language examples. These scripts were
originally written as standalone learning utilities and have been modernized for
Python 3.

This repository is meant to help early-career engineers and security learners
connect Python fundamentals with practical cybersecurity workflows. The scripts
are intentionally small enough to read in one sitting, run from the command
line, and modify while learning.

## Important Notice

Use these tools only on systems and networks you own or are explicitly
authorized to assess. Some scripts can generate network traffic, modify local
firewall rules, spoof packets, or attempt form-based attacks. Run them in a lab
environment first and review the source before using them.

## Repository Layout

Scripts are grouped into numbered categories that follow the rough order of an
assessment engagement: passive research, then web and network testing, then
host-side analysis, with fundamentals at the end.

```
01-recon-osint/           Passive intel: DNS, subdomains, WHOIS, CVEs, search
02-web-assessment/        HTTP/TLS checks + active vulnerability probes
03-network-scanning/      Port scans, banners, pcaps, wireless monitoring
04-spoofing-lab/          ARP/DNS spoofing demonstrations (isolated labs only)
05-host-forensics/        Logs, entropy, secrets, PE/email triage
06-encoding-utils/        Base64, XOR, hashing helpers
07-server-examples/       Minimal TCP/HTTP servers and clients
08-python-fundamentals/   Threads, signals, exceptions, debugging basics
09-web-vuln-scanners/     One detector per Academy vulnerability class
```

Each directory has its own `README.md` listing every script in that category,
what it does, and what is safe to run where.

| Category | Scripts | Use it when you want to... |
| --- | --- | --- |
| [`01-recon-osint`](01-recon-osint) | 13 | Map DNS, subdomains, registrations, CVEs, and search footprint passively. |
| [`02-web-assessment`](02-web-assessment) | 18 | Inspect headers/cookies/TLS/JWTs, then probe authorized web apps. |
| [`03-network-scanning`](03-network-scanning) | 10 | Scan ports, grab banners, parse nmap output, watch traffic. |
| [`04-spoofing-lab`](04-spoofing-lab) | 2 | Study ARP/DNS man-in-the-middle mechanics in an isolated lab. |
| [`05-host-forensics`](05-host-forensics) | 9 | Triage logs, hunt secrets, analyze suspicious emails and binaries. |
| [`06-encoding-utils`](06-encoding-utils) | 3 | Transform data during exploitation or analysis work. |
| [`07-server-examples`](07-server-examples) | 6 | Run throwaway listeners or study socket programming. |
| [`08-python-fundamentals`](08-python-fundamentals) | 9 | Learn the Python building blocks used everywhere else. |
| [`09-web-vuln-scanners`](09-web-vuln-scanners) | 23 | Run class-by-class detectors mapped to PortSwigger Academy topics. |

Repo tooling: `requirements_helper.py` (repo root) scans all category
directories and reports the third-party imports each script needs.

## How to Learn From This Repo

The best way to use this repo is to read a script, run it against a safe target,
then change one thing and observe the result. Avoid treating the scripts as
black-box tools. The value is in understanding the code paths, inputs, outputs,
and failure modes.

Recommended workflow:

1. Read the script top to bottom.
2. Run `python3 script_name.py --help` when the script supports arguments.
3. Run it against a local file, localhost service, or intentionally vulnerable
   lab target.
4. Add one small improvement, such as better error handling, a timeout, or CSV
   output.
5. Re-run `python3 -m compileall -q .` before committing changes.

Suggested learning path across categories:

1. **Python basics** (`08-python-fundamentals`): `pythagoras.py`,
   `user_exceptions.py`, `threads1.py`.
2. **Files, logs, and encodings** (`05-host-forensics`, `06-encoding-utils`):
   `dir_recurser.py`, `file_entropy.py`, `log_grep.py`, `xor_file.py`.
3. **Passive recon** (`01-recon-osint`): `dns_lookup.py`,
   `whois_rdaps_lookup.py`, `cve_lookup.py`, `subdomain_wordlist_check.py`.
4. **Web security concepts** (`02-web-assessment`): `http_headers.py`,
   `cookie_flags_check.py`, `jwt_decode.py`, `cors_check.py`.
5. **Networking basics** (`03-network-scanning`, `07-server-examples`):
   `port_banner_grabber.py`, `pcap_summary.py`, `tcpServer_SocketServer.py`.
6. **Active testing, lab only** (`02-web-assessment` probes, `04-spoofing-lab`,
   `09-web-vuln-scanners`): `open_redirect_probe.py`, `ssrf_probe.py`,
   `arp_spoof.py`, then class detectors such as `sqli_detection_probe.py`,
   `ssti_probe.py`, and `cache_poisoning_probe.py`.

## Safe Practice Targets

Use local or intentionally vulnerable targets while learning. Good options
include:

- Local files for `basic_hash_tool.py`, `file_entropy.py`, `log_grep.py`, and
  `xor_file.py`.
- `http://127.0.0.1` services you start yourself.
- OWASP Juice Shop, DVWA, WebGoat, or other intentionally vulnerable labs.
- The vulnerability-probe and scanner scripts are best practiced against those
  same local lab targets: everything in `02-web-assessment` probes plus every
  script in `09-web-vuln-scanners` accepts a URL, so point them at your own
  instance of a vulnerable app.
- Public websites only for passive checks such as headers, TLS certificate
  details, robots.txt, and URL status. Do not brute force, spoof, scan ports, or
  probe wordlists against third-party systems without written authorization.
- Fully passive tools such as `cve_lookup.py`, `security_txt_checker.py`,
  `typosquat_domain_check.py` (without `--resolve`), and the report converters
  (`nmap_xml_parser.py`, `email_header_analyzer.py`, `secrets_scanner.py`) are
  safe to run anywhere on data you already have.

## Concepts Covered

This repo can help learners practice:

- Python command-line interfaces with `argparse` and `optparse`.
- Text, bytes, JSON, Base64, hashing, and binary file handling.
- HTTP requests, response headers, cookies, redirects, and simple HTML parsing.
- DNS, TCP sockets, raw sockets, packet capture, and packet crafting.
- Threads, queues, signal handling, subprocess usage, and exception handling.
- Security assessment habits: authorization, scope control, rate limiting,
  repeatable evidence, and clear reporting.

## Requirements

- Python 3.12 or newer is recommended.
- Some scripts require elevated privileges, especially raw socket and Scapy
  packet-crafting tools.
- Several scripts depend on third-party packages that are not vendored in this
  repository; run `python3 requirements_helper.py` to regenerate the
  authoritative import map.

Common optional dependencies:

```bash
python3 -m pip install beautifulsoup4 mechanize pefile psutil scapy selenium watchdog
```

Platform-specific notes:

- `windows_WirelessAccessPoint.py` is intended for Windows and uses `netsh`.
- Packet capture/spoofing scripts generally require Linux, root privileges, and
  appropriate network interface configuration.
- Selenium usage requires a browser and matching WebDriver support.

## Usage

Scripts run directly from their category directories:

```bash
python3 01-recon-osint/cve_lookup.py --id CVE-2024-21762
python3 01-recon-osint/security_txt_checker.py github.com
python3 02-web-assessment/http_headers.py https://example.com
python3 02-web-assessment/tls_check.py example.com
python3 03-network-scanning/nmap_xml_parser.py scan.xml --open-only --csv report.csv
python3 05-host-forensics/secrets_scanner.py ./my-project --strict
python3 05-host-forensics/email_header_analyzer.py suspicious.eml
python3 06-encoding-utils/xor_file.py input.bin output.bin "de ad be ef"
python3 09-web-vuln-scanners/ssti_probe.py "https://lab.example/page?tpl=x" --param tpl
python3 09-web-vuln-scanners/graphql_probe.py https://lab.example
python3 09-web-vuln-scanners/jwt_weakness_check.py "$TOKEN" --wordlist rockyou.txt
```

For scripts that send packets or bind raw sockets, run with appropriate
privileges:

```bash
sudo python3 03-network-scanning/synScan_threaded.py
sudo python3 04-spoofing-lab/arp_spoof.py
sudo python3 02-web-assessment/http_request_smuggling_probe.py 127.0.0.1:8080
```

## Development

Validate syntax across all categories with:

```bash
python3 -m compileall -q .
```

The repository ignores Python cache files via `.gitignore`. Keep generated files,
captures, screenshots, and downloaded content out of commits unless they are
intentional fixtures or documentation assets.

## License

See `LICENSE.txt`.
