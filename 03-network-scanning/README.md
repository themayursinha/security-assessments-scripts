# Network Scanning & Monitoring

Port scanning, banner grabbing, packet capture summaries, and wireless
monitoring. Raw-socket and Scapy-based scripts generally require Linux and
root privileges. Scan only networks you own or are authorized to assess.

| Script | Purpose |
| --- | --- |
| `arp_scan.py` | Scan a local subnet with ARP requests using Scapy. |
| `monitor_tcp_ports.py` | Monitor TCP SYN packets using raw sockets. |
| `monitor_wifi_probes.py` | Print Wi-Fi probe requests from monitor-mode traffic. |
| `nmap_xml_parser.py` | Convert nmap -oX XML into a table, CSV, or Markdown report. |
| `pcap_summary.py` | Summarize packet counts and top endpoints from a pcap file. |
| `port_banner_grabber.py` | Connect to TCP ports and capture service banners. |
| `synScan_threaded.py` | Threaded SYN scan with Scapy. |
| `wifi_ssid_parser.py` | Extract SSIDs and BSSIDs from saved Wi-Fi scan output. |
| `windows_WirelessAccessPoint.py` | Start/stop a Windows hosted wireless network via netsh. |
| `xmasScan_threaded.py` | Threaded XMAS scan with Scapy. |
