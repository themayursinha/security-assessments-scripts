#!/usr/bin/env python3
"""Probe authenticated pages for web cache deception (sensitive data cached)."""

import argparse
import difflib
import random
import string
import time
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"


def rand_token():
  return "".join(random.choices(string.ascii_lowercase, k=8))


def fetch(url, cookie, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA, "Cookie": cookie})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    headers = {k.lower(): v for k, v in response.headers.items()}
    return getattr(response, "status", response.code), response.read(131072).decode("utf-8", "replace"), headers
  except urllib.error.HTTPError as exc:
    headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
    return exc.code, exc.read(131072).decode("utf-8", "replace"), headers
  except (urllib.error.URLError, OSError):
    return None, "", {}


def cacheable(headers):
  cache_control = headers.get("cache-control", "")
  if any(token in cache_control for token in ("no-store", "no-cache", "private")):
    return False
  return bool(cache_control) or any(k in headers for k in ("age", "x-cache", "cf-cache-status", "x-varnish", "x-served-by"))


def main():
  parser = argparse.ArgumentParser(description="Test whether an authenticated page is served and cached under static-looking paths.")
  parser.add_argument("url", help="authenticated page URL, e.g. https://lab.example/my-account")
  parser.add_argument("--cookie", required=True, help="authenticated session cookie, e.g. 'session=abc'")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  auth_status, auth_body, _ = fetch(args.url, args.cookie, args.timeout)
  print(f"[*] authenticated baseline: HTTP {auth_status}, {len(auth_body)} bytes")
  if auth_status != 200:
    print("[!] baseline page did not return 200 - check the cookie before trusting results.")

  anon_status, anon_body, _ = fetch(args.url, "zxnone=1", args.timeout)
  print(f"[*] anonymous control: HTTP {anon_status}, {len(anon_body)} bytes\n")

  suffix_styles = [
    ("/{t}.css", "{url}/{t}.css"),
    ("%2F{t}.css", "{url}%2F{t}.css"),
    (";{t}.css", "{url};{t}.css"),
    ("/{t}.js", "{url}/{t}.js"),
  ]

  confirmed = []
  for label, template in suffix_styles:
    token = "cdc" + rand_token()
    probe_url = template.format(url=args.url.rstrip("/"), t=token)
    status, body, headers = fetch(probe_url, args.cookie, args.timeout)
    similarity = difflib.SequenceMatcher(None, body, auth_body).ratio()
    looks_authed = auth_status == 200 and similarity > 0.9
    cacheable_hit = cacheable(headers)

    flags = []
    if looks_authed:
      flags.append(f"authenticated content served (sim={similarity:.3f})")
    if cacheable_hit:
      flags.append(f"cacheable: cc={headers.get('cache-control', '')!r} age={headers.get('age', '?')}")

    flag = "[!]" if looks_authed else "[ ]"
    print(f"{flag} {label:<12} HTTP {status}, {len(body)}B" + (f" -> {'; '.join(flags)}" if flags else ""))

    if looks_authed and cacheable_hit:
      confirmed.append((label, probe_url))
    elif looks_authed:
      print("      note: deception path works; caching not confirmed from headers alone")

  print()
  if confirmed:
    print("[!] Web cache deception candidates:")
    for label, url in confirmed:
      print(f"    - {label}: {url}")
    print("Confirm end-to-end by fetching the .css path WITHOUT the cookie after a short delay;")
    print("if private data returns anonymously, the victim cache entry was reused.")
  else:
    print("[+] No cache deception indicators on this page.")


if __name__ == "__main__":
  main()
