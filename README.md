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
5. Re-run `python3 -m compileall -q *.py` before committing changes.

Good beginner-friendly scripts:

| Start Here | What You Learn |
| --- | --- |
| `pythagoras.py` | Input handling, type conversion, basic math. |
| `ez_base64.py` | Encoding, decoding, bytes versus strings. |
| `basic_hash_tool.py` | File reading, hashing, command-line options. |
| `file_entropy.py` | Loops, counters, math, binary files. |
| `url_status_checker.py` | HTTP requests, error handling, simple parsing. |
| `http_headers.py` | HTTP response headers and web security basics. |
| `jwt_decode.py` | Structured data, JSON, Base64URL, token anatomy. |
| `threads1.py` | Queues, worker threads, and concurrency basics. |

Suggested learning path:

1. Python basics: `pythagoras.py`, `user_exceptions.py`, `basic_hash_tool.py`.
2. Files and logs: `dir_recurser.py`, `file_entropy.py`, `log_grep.py`.
3. HTTP basics: `url_status_checker.py`, `http_headers.py`,
   `robots_sitemap_fetcher.py`.
4. Web security concepts: `cookie_flags_check.py`, `cors_check.py`,
   `jwt_decode.py`, `json_endpoint_probe.py`.
5. Networking basics: `dns_lookup.py`, `port_banner_grabber.py`,
   `tcpClient_signals.py`, `tcpServer_SocketServer.py`.
6. Advanced lab-only packet work: `arp_scan.py`, `synScan_threaded.py`,
   `xmasScan_threaded.py`, `dns_spoof.py`, `arp_spoof.py`.

## Safe Practice Targets

Use local or intentionally vulnerable targets while learning. Good options
include:

- Local files for `basic_hash_tool.py`, `file_entropy.py`, `log_grep.py`, and
  `xor_file.py`.
- `http://127.0.0.1` services you start yourself.
- OWASP Juice Shop, DVWA, WebGoat, or other intentionally vulnerable labs.
- Public websites only for passive checks such as headers, TLS certificate
  details, robots.txt, and URL status. Do not brute force, spoof, scan ports, or
  probe wordlists against third-party systems without written authorization.

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
  repository.

Common optional dependencies:

```bash
python3 -m pip install beautifulsoup4 mechanize pefile psutil scapy selenium watchdog
```

Platform-specific notes:

- `windows_WirelessAccessPoint.py` is intended for Windows and uses `netsh`.
- Packet capture/spoofing scripts generally require Linux, root privileges, and
  appropriate network interface configuration.
- Selenium usage requires a browser and matching WebDriver support.

## Script Inventory

### Network and Packet Tools

| Script | Purpose |
| --- | --- |
| `arp_scan.py` | Scans a local subnet with ARP requests using Scapy. |
| `arp_spoof.py` | Demonstrates ARP spoofing and packet forwarding concepts. |
| `dns_spoof.py` | Watches DNS requests and sends spoofed DNS responses. |
| `dns_lookup.py` | Resolves A/AAAA records and reverse PTR lookups. |
| `monitor_tcp_ports.py` | Monitors TCP SYN packets using raw sockets. |
| `monitor_wifi_probes.py` | Prints Wi-Fi probe requests from monitor-mode traffic. |
| `pcap_summary.py` | Summarizes packet counts and top endpoints from a pcap file. |
| `port_banner_grabber.py` | Connects to TCP ports and captures simple service banners. |
| `synScan_threaded.py` | Performs a threaded SYN scan with Scapy. |
| `subdomain_wordlist_check.py` | Resolves candidate subdomains from a wordlist. |
| `wifi_ssid_parser.py` | Extracts SSIDs and BSSIDs from saved Wi-Fi scan output. |
| `xmasScan_threaded.py` | Performs a threaded XMAS scan with Scapy. |

### Web and Internet Utilities

| Script | Purpose |
| --- | --- |
| `BaseHTTPServer1.py` | Minimal custom HTTP server example. |
| `SimpleHTTPServer1.py` | Simple static HTTP server with a custom `/test` route. |
| `selenium_webdriver.py` | Captures a screenshot of a target site with Selenium. |
| `search_duckduckgo.py` | Queries DuckDuckGo HTML search and extracts result URLs. |
| `search_scrape_parse_threaded.py` | Searches, fetches, and parses web pages with worker threads. |
| `mechanize_scraper_threaded.py` | Fetches a path from a list of domains using threaded mechanize workers. |
| `mechanize_webform_inspect.py` | Lists web forms and form controls on a target page. |
| `mechanize_webform_brute.py` | Demonstrates a form-based password-list workflow. |
| `mechanize_webform_sqli.py` | Demonstrates submitting SQL injection payloads into form fields. |
| `gatherThreatIntel_ISC_IPs.py` | Scrapes top source IPs from the SANS ISC sources page. |
| `cors_check.py` | Checks CORS response headers for supplied origins. |
| `cookie_flags_check.py` | Inspects `Set-Cookie` attributes for common security flags. |
| `http_headers.py` | Summarizes common HTTP security headers and cookies. |
| `json_endpoint_probe.py` | Fetches JSON endpoints and summarizes status, keys, and size. |
| `jwt_decode.py` | Decodes JWT header and payload locally without verification. |
| `lab_target_healthcheck.py` | Checks local lab web targets for reachability. |
| `robots_sitemap_fetcher.py` | Fetches `robots.txt` and `sitemap.xml` paths. |
| `tls_check.py` | Inspects certificate expiry and negotiated TLS details. |
| `url_status_checker.py` | Checks URL status, redirects, titles, and server headers. |
| `web_wordlist_probe.py` | Probes authorized web paths from a wordlist with rate limiting. |
| `whois_rdaps_lookup.py` | Fetches RDAP registration data for domains or IPs. |

### TCP, FTP, and Server Examples

| Script | Purpose |
| --- | --- |
| `tcpClient_signals.py` | Basic TCP client with SIGINT cleanup. |
| `tcpServer_SocketServer.py` | Basic TCP echo server using `socketserver`. |
| `tcpServer_signals.py` | TCP listener example with signal handling. |
| `ftp_explorer.py` | Connects to FTP servers from a list and prints directory entries. |

### Host and File Utilities

| Script | Purpose |
| --- | --- |
| `dir_recurser.py` | Recursively lists directory contents and file sizes. |
| `basic_hash_tool.py` | Calculates common hashes for files or strings. |
| `file_entropy.py` | Calculates Shannon entropy for files. |
| `log_grep.py` | Searches logs for IPs, URLs, emails, auth events, and errors. |
| `monitor_directory.py` | Monitors filesystem events with watchdog. |
| `monitor_process.py` | Prints process metadata and network connections with psutil. |
| `pe_imports.py` | Prints imported DLLs and functions from a PE file. |
| `usb_logs.py` | Prints USB-related lines from `/var/log/syslog`. |
| `xor_file.py` | XORs an input file with supplied hex bytes and writes the result. |
| `ez_base64.py` | Encodes or decodes a value with Base64. |
| `windows_WirelessAccessPoint.py` | Starts and stops a Windows hosted wireless network. |

### Python Examples

| Script | Purpose |
| --- | --- |
| `forker.py` | Demonstrates process forking. |
| `lock_threads.py` | Demonstrates thread locking around a shared counter. |
| `threads1.py` | Basic worker-thread queue example. |
| `threads2.py` | Thread queue example with command-line options. |
| `signals.py` | Demonstrates custom signal handling. |
| `user_exceptions.py` | Demonstrates custom exception classes. |
| `pdb_example.py` | Small debugging example. |
| `pythagoras.py` | Calculates a hypotenuse from two legs. |
| `mysql_example.py` | Minimal MySQL usage example. |
| `requirements_helper.py` | Reports third-party imports and a suggested install command. |

## Usage

Each script is intended to be run directly. Most scripts either take command-line
options or prompt interactively when required values are missing.

Examples:

```bash
python3 ez_base64.py encode "hello"
python3 xor_file.py input.bin output.bin "de ad be ef"
python3 selenium_webdriver.py --site https://example.com --out example.png
python3 mechanize_webform_inspect.py --target https://example.com/login
python3 http_headers.py https://example.com
python3 tls_check.py example.com
python3 jwt_decode.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature
python3 requirements_helper.py
```

For scripts that send packets or bind raw sockets, run with appropriate
privileges:

```bash
sudo python3 arp_scan.py
sudo python3 synScan_threaded.py
```

## Development

Validate syntax for all scripts with:

```bash
python3 -m compileall -q *.py
```

The repository ignores Python cache files via `.gitignore`. Keep generated files,
captures, screenshots, and downloaded content out of commits unless they are
intentional fixtures or documentation assets.

## License

See `LICENSE.txt`.
