#!/usr/bin/env python3
"""Test authorized web targets for host header injection reflections."""

import argparse
import http.client
import ssl
import urllib.parse

UA = "security-assessment-scripts/1.0"
CANARY = "canary.hostheader.example"


def insecure_context():
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  return context


def send_request(parsed, headers, timeout):
  is_https = parsed.scheme == "https"
  connection_class = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
  kwargs = {"timeout": timeout}
  if is_https:
    kwargs["context"] = insecure_context()
  connection = connection_class(parsed.hostname, parsed.port or (443 if is_https else 80), **kwargs)
  try:
    path = parsed.path or "/"
    if parsed.query:
      path += "?" + parsed.query
    connection.putrequest("GET", path, skip_host=True)
    for name, value in headers:
      connection.putheader(name, value)
    connection.putheader("User-Agent", UA)
    connection.endheaders()
    response = connection.getresponse()
    body = response.read(65536).decode("utf-8", "replace")
    return response.status, dict(response.getheaders()), body
  finally:
    connection.close()


def scan_body_for_canary(body):
  hits = []
  for line in body.splitlines():
    if CANARY in line and len(line.strip()) > 0:
      hits.append(line.strip()[:160])
  return hits


def check_result(test_name, status, headers, body, baseline_status):
  findings = []
  location = headers.get("Location", "") or headers.get("location", "")
  if CANARY in location:
    findings.append(f"Location header contains canary: {location[:120]}")
  for hit in scan_body_for_canary(body)[:3]:
    findings.append(f"body reflection: {hit}")
  if status != baseline_status:
    findings.append(f"status changed from {baseline_status} to {status}")
  marker = "[!]" if findings else "[ ]"
  print(f"{marker} {test_name}")
  for finding in findings:
    print(f"      -> {finding}")
  return bool(findings)


def main():
  parser = argparse.ArgumentParser(description="Probe Host/X-Forwarded-* header handling on an authorized target.")
  parser.add_argument("url", help="target URL (e.g. https://lab.example/reset)")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  args = parser.parse_args()

  parsed = urllib.parse.urlsplit(args.url)
  real_host = parsed.hostname
  base_headers = [
    ("Host", real_host),
    ("Accept", "*/*"),
  ]

  tests = [
    ("baseline (normal Host)", base_headers),
    ("Host replaced with canary", [("Host", CANARY), ("Accept", "*/*")]),
    ("X-Forwarded-Host canary", base_headers + [("X-Forwarded-Host", CANARY)]),
    ("X-Host canary", base_headers + [("X-Host", CANARY)]),
    ("X-HTTP-Host-Override canary", base_headers + [("X-HTTP-Host-Override", CANARY)]),
    ("Forwarded header canary", base_headers + [("Forwarded", f"host={CANARY}")]),
    ("X-Original-URL canary", base_headers + [("X-Original-URL", f"https://{CANARY}/")]),
  ]

  vulnerable = False
  baseline_status = None
  for test_name, headers in tests:
    try:
      status, response_headers, body = send_request(parsed, headers, args.timeout)
    except (OSError, http.client.HTTPException) as exc:
      print(f"[x] {test_name}: request failed ({exc})")
      continue
    if test_name.startswith("baseline"):
      baseline_status = status
      print(f"[*] baseline: HTTP {status}, {len(body)} bytes")
      continue
    if check_result(test_name, status, response_headers, body, baseline_status):
      vulnerable = True

  print()
  if vulnerable:
    print("Reflections detected - review manually (password reset poisoning, cache key confusion).")
  else:
    print("No canary reflections observed in the tested headers.")


if __name__ == "__main__":
  main()
