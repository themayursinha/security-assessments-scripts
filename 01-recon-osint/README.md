# Recon & OSINT

Passive and light-touch intelligence gathering: DNS enumeration, WHOIS/RDAP,
subdomain discovery and takeover checks, CVE lookups, security.txt validation,
search-engine scraping, and threat-intel feeds. These scripts read public data
sources and are safe to run against any domain.

| Script | Purpose |
| --- | --- |
| `cve_lookup.py` | Query the public NVD API 2.0 by CVE ID or keyword. |
| `dns_lookup.py` | Resolve A/AAAA records and reverse PTR lookups. |
| `dns_zone_transfer.py` | Attempt AXFR zone transfers via a minimal raw DNS client. |
| `gatherThreatIntel_ISC_IPs.py` | Scrape top source IPs from the SANS ISC sources page. |
| `mechanize_scraper_threaded.py` | Fetch a path from a list of domains using threaded workers. |
| `robots_sitemap_fetcher.py` | Fetch robots.txt and sitemap.xml paths. |
| `search_duckduckgo.py` | Query DuckDuckGo HTML search and extract result URLs. |
| `search_scrape_parse_threaded.py` | Search, fetch, and parse web pages with worker threads. |
| `security_txt_checker.py` | Discover and validate security.txt per RFC 9116. |
| `subdomain_takeover_check.py` | Flag dangling DNS records and takeover-vulnerable fingerprints. |
| `subdomain_wordlist_check.py` | Resolve candidate subdomains from a wordlist. |
| `typosquat_domain_check.py` | Generate and optionally resolve lookalike domains. |
| `whois_rdaps_lookup.py` | Fetch RDAP registration data for domains or IPs. |

Sample data: `alexa_10000_domains.txt` feeds the threaded scraper example.
