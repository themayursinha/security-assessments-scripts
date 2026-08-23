#!/usr/bin/env python3
"""Enumerate HTTP methods and flag TRACE reflection or write-method exposure."""

import argparse
import http.client
import ssl
import time
import urllib.parse

UA = "security-assessment-scripts/1.0"


def request(parsed, method, headers, timeout, body=None):
  is_https = parsed.scheme == "https"
  connection_class = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
  kwargs = {"timeout": timeout}
  if is_https:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    kwargs["context"] = context
  path = parsed.path or "/"
  if parsed.query:
    path += "?" + parsed.query
  connection = connection_class(parsed.hostname, parsed.port or (443 if is_https else 80), **kwargs)
  try:
    if method == "OPTIONS":
      connection.putrequest("OPTIONS", path, skip_host=True)
      connection.putheader("Host", parsed.hostname)
      for name, value in headers.items():
        connection.putheader(name, value)
      connection.putheader("User-Agent", UA)
      connection.endheaders()
    else:
      connection.request(method, path, body=body, headers={"User-Agent": UA, **headers})
    response = connection.getresponse()
    data = response.read(65536).decode("utf-8", "replace")
    return response.status, dict(response.getheaders()), data
  except (http.client.HTTPException, OSError) as exc:
    return None, {}, f"{type(exc).__name__}: {exc}"


def main():
  parser = argparse.ArgumentParser(description="Audit allowed HTTP methods on an authorized target.")
  parser.add_argument("url")
  parser.add_argument("--test-write", action="store_true",
                      help="probe PUT/DELETE with a random harmless path (authorized targets only)")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  parsed = urllib.parse.urlsplit(args.url)

  status, headers, _ = request(parsed, "OPTIONS", {}, args.timeout)
  allow = headers.get("Allow") or headers.get("Public") or ""
  if status == 501:
    print("[*] OPTIONS not implemented (HTTP 501); probing common methods directly.")
  elif allow:
    print(f"[*] OPTIONS -> HTTP {status}, Allow: {allow}")
  else:
    print(f"[*] OPTIONS -> HTTP {status} without Allow header")

  trace_status, _, trace_body = request(parsed, "TRACE", {"X-Canary": "zxtrace123"}, args.timeout)
  if trace_status == 200:
    reflected = "zxtrace123" in trace_body
    flag = "[!]" if reflected else "[ ]"
    print(f"{flag} TRACE: HTTP 200" + (" - reflects request (Cross-Site Tracing risk)" if reflected else ""))
  elif trace_status in (405, 501):
    print(f"[+] TRACE disabled (HTTP {trace_status})")
  else:
    print(f"[ ] TRACE: HTTP {trace_status}")

  if args.test_write:
    probe_path = "/zx-probe-" + urllib.parse.quote(str(int(time.time())))
    for method in ("PUT", "DELETE"):
      split_probe = parsed._replace(path=probe_path)
      w_status, w_headers, _ = request(split_probe, method, {}, args.timeout, body="zxharmless\n")
      if w_status in (200, 201, 204):
        print(f"[!] {method} accepted on {probe_path} (HTTP {w_status}) - verify whether content was stored/executed")
      else:
        print(f"[+] {method} rejected (HTTP {w_status})")

  if allow:
    flagged = [m for m in ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT") if m in allow.upper()]
    print(f"\n[*] server-declared Allow: {allow}")
    for method in flagged:
      print(f"[!] {method} advertised as allowed")


if __name__ == "__main__":
  main()
