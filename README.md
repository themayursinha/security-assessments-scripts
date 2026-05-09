# Security Assessment Scripts

A collection of small Python scripts for security assessment practice, network
experimentation, web scraping, and Python language examples. These scripts were
originally written as standalone learning utilities and have been modernized for
Python 3.

## Important Notice

Use these tools only on systems and networks you own or are explicitly
authorized to assess. Some scripts can generate network traffic, modify local
firewall rules, spoof packets, or attempt form-based attacks. Run them in a lab
environment first and review the source before using them.

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
| `monitor_tcp_ports.py` | Monitors TCP SYN packets using raw sockets. |
| `monitor_wifi_probes.py` | Prints Wi-Fi probe requests from monitor-mode traffic. |
| `synScan_threaded.py` | Performs a threaded SYN scan with Scapy. |
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

## Usage

Each script is intended to be run directly. Most scripts either take command-line
options or prompt interactively when required values are missing.

Examples:

```bash
python3 ez_base64.py encode "hello"
python3 xor_file.py input.bin output.bin "de ad be ef"
python3 selenium_webdriver.py --site https://example.com --out example.png
python3 mechanize_webform_inspect.py --target https://example.com/login
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
