# Web Assessment

HTTP, TLS, and token inspection plus active vulnerability probes. Checks in the
first table are non-intrusive single-request inspections. Probes and form
attacks in the second table send crafted or repeated requests: run them only
against lab instances (OWASP Juice Shop, DVWA) or systems with written
authorization.

## Non-intrusive checks

| Script | Purpose |
| --- | --- |
| `cookie_flags_check.py` | Inspect Set-Cookie attributes for Secure/HttpOnly/SameSite. |
| `cors_check.py` | Check CORS response headers for supplied origins. |
| `http_headers.py` | Summarize common HTTP security headers and cookies. |
| `json_endpoint_probe.py` | Fetch JSON endpoints and summarize status, keys, size. |
| `jwt_decode.py` | Decode JWT header/payload locally without verification. |
| `lab_target_healthcheck.py` | Check local lab web targets for reachability. |
| `selenium_webdriver.py` | Capture a screenshot of a target site. |
| `tls_check.py` | Inspect certificate expiry and negotiated TLS details. |
| `url_status_checker.py` | Check URL status, redirects, titles, server headers. |

## Active probes and form attacks (authorized targets only)

| Script | Purpose |
| --- | --- |
| `hostheader_injection_probe.py` | Test Host/X-Forwarded-* handling for reflections. |
| `http_request_smuggling_probe.py` | CL.TE / TE.CL desync differential probes over raw sockets. |
| `mechanize_webform_brute.py` | Form-based password-list workflow demo. |
| `mechanize_webform_inspect.py` | List web forms and controls on a page. |
| `mechanize_webform_sqli.py` | Submit SQL injection payloads into form fields. |
| `open_redirect_probe.py` | Fuzz redirect parameters and flag off-site hops. |
| `path_traversal_probe.py` | Fuzz file parameters with traversal payloads. |
| `ssrf_probe.py` | Probe URL-fetch parameters for SSRF indicators. |
| `web_wordlist_probe.py` | Probe authorized web paths from a wordlist with rate limiting. |
