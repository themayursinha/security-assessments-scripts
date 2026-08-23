# Host & File Forensics

Local system and file analysis: log triage, hashing, entropy screening,
malware triage helpers, filesystem/process monitoring, secret discovery, and
email header analysis. These scripts read local data and are safe to run on
any files you control.

| Script | Purpose |
| --- | --- |
| `dir_recurser.py` | Recursively list directory contents and file sizes. |
| `email_header_analyzer.py` | Triage an .eml for phishing indicators (Received chain, SPF/DKIM/DMARC). |
| `file_entropy.py` | Calculate Shannon entropy for files. |
| `log_grep.py` | Search logs for IPs, URLs, emails, auth events, errors. |
| `monitor_directory.py` | Monitor filesystem events with watchdog. |
| `monitor_process.py` | Print process metadata and network connections with psutil. |
| `pe_imports.py` | Print imported DLLs and functions from a PE file. |
| `secrets_scanner.py` | Scan files for credential-like strings with redacted output. |
| `usb_logs.py` | Print USB-related lines from /var/log/syslog. |
