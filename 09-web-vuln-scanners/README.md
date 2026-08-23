# Web Vulnerability Scanners

Automated detectors for the PortSwigger Web Security Academy vulnerability
classes. Each script targets one class and is built for authorized lab targets
(OWASP Juice Shop, DVWA, PortSwigger labs) or systems with written permission.
They find indicators and narrow the engine/mechanism; confirm every finding
manually before reporting.

| Script | Detects | Method |
| --- | --- | --- |
| `api_docs_discovery.py` | Exposed API surface (api-testing) | Probes Swagger/OpenAPI, actuator, expvar, status paths |
| `auth_enumeration_check.py` | Username enumeration (authentication) | Diffs status/size/content/timing between valid and invalid users |
| `cache_deception_probe.py` | Web cache deception | Requests authenticated pages under static-looking suffixes, checks caching headers |
| `cache_poisoning_probe.py` | Web cache poisoning | Injects canaries into candidate unkeyed headers, re-reads the cached entry |
| `clickjacking_check.py` | Clickjacking | Validates X-Frame-Options / CSP frame-ancestors |
| `cmd_injection_probe.py` | OS command injection | Output signatures (`uid=`) plus sleep-based timing across separator variants |
| `csrf_token_check.py` | Missing CSRF protection (csrf) | Parses forms for token fields, cross-origin actions, SameSite cookies |
| `deserialization_fingerprint.py` | Insecure deserialization | Fingerprints PHP/Java/Python/Ruby/.NET serialized blobs in cookies and ViewState |
| `dom_sinks_scanner.py` | DOM-based vulnerabilities | Static scan of inline/external JS for source-to-sink patterns and origin checks |
| `graphql_probe.py` | GraphQL misconfigurations (graphql) | Endpoint discovery, introspection, GET queries, field-suggestion leaks |
| `idor_access_probe.py` | Broken access control (access-control) | Replays object IDs with a low-privilege session and flags cross-principal data |
| `info_disclosure_scan.py` | Information disclosure | Source maps, .git metadata, debug endpoints, stack traces, comment leaks |
| `jwt_weakness_check.py` | JWT flaws (jwt) | kid/jku header risks, HS256 wordlist cracking, alg=none acceptance test |
| `nosql_injection_probe.py` | NoSQL injection | Operator ($ne/$gt/$regex) and syntax payloads against login endpoints |
| `oauth_flow_check.py` | OAuth misconfigurations (oauth) | Audits state/nonce/PKCE/redirect_uri on authorization requests |
| `prototype_pollution_probe.py` | Prototype pollution | Query-string and JSON __proto__/constructor pollution with reflection detection |
| `race_condition_probe.py` | Race conditions | Fires synchronized duplicate requests and reports success/reject distribution |
| `sqli_detection_probe.py` | SQL injection | Database error fingerprints plus boolean true/false response diffing |
| `ssti_probe.py` | Server-side template injection (ssti) | Math-expression payloads fingerprint Jinja2/Twig/Freemarker/ERB |
| `ssrf_probe.py` (in `02-web-assessment`) | SSRF (ssrf) | Loopback/metadata payloads plus timing analysis |
| `websocket_origin_check.py` | Cross-site WebSocket hijacking (websockets) | Raw handshake with attacker Origin; also flags missing upgrades |
| `xss_reflection_probe.py` | Reflected XSS (xss) | Classifies reflection context (JS/attribute/tag/body) and encoding survival |
| `xxe_probe.py` | XXE injection | Classic internal-entity and out-of-band payloads with parser fingerprints |
| `file_upload_form_check.py` | File upload flaws | Finds multipart forms and probes extension filtering with harmless uploads |

Not automated here by design:

- **Business logic**: exploitation is application-specific; use
  `mechanize_webform_inspect.py` and manual request crafting.
- **Web LLM attacks**: needs conversational probing against a live chat
  endpoint; no reliable generic detector exists.
