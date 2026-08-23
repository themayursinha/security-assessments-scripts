#!/usr/bin/env python3
"""Check pages for framing protection (clickjacking) headers."""

import argparse
import re
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"
CSP_FRAME_RE = re.compile(r"frame-ancestors([^;]*)", re.IGNORECASE)


def check(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.headers
  except urllib.error.HTTPError as exc:
    return exc.code, exc.headers
  except (urllib.error.URLError, OSError):
    return None, None


def main():
  parser = argparse.ArgumentParser(description="Report X-Frame-Options and CSP frame-ancestors on authorized targets.")
  parser.add_argument("urls", nargs="+", help="one or more URLs")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  framable = 0
  for url in args.urls:
    status, headers = check(url, args.timeout)
    if headers is None:
      print(f"[x] {url}: no response")
      continue

    xfo = headers.get("X-Frame-Options")
    csp = headers.get("Content-Security-Policy") or ""
    frame_match = CSP_FRAME_RE.search(csp)
    frame_ancestors = frame_match.group(1).strip() if frame_match else None

    if xfo:
      value = xfo.strip()
      if value.upper() == "ALLOW-FROM":
        verdict = f"X-Frame-Options: {value} is obsolete and ignored by modern browsers"
        flag = "[!]"
        framable += 1
      elif value.upper() in ("DENY", "SAMEORIGIN"):
        verdict = f"protected (X-Frame-Options: {value})"
        flag = "[+]"
      else:
        verdict = f"invalid X-Frame-Options value: {value}"
        flag = "[!]"
        framable += 1
    elif frame_ancestors:
      if frame_ancestors.lower().replace(" ", "") in ("'none'", "'self'"):
        verdict = f"protected (CSP frame-ancestors {frame_ancestors})"
        flag = "[+]"
      else:
        verdict = f"framing allowed from: {frame_ancestors}"
        flag = "[?]"
    else:
      verdict = "NO framing protection - page can be framed (clickjacking)"
      flag = "[!]"
      framable += 1

    print(f"{flag} HTTP {status} {url}\n     -> {verdict}")

  print()
  if framable:
    print(f"{framable} URL(s) lack effective framing protection.")
  else:
    print("[+] All targets have framing protection.")


if __name__ == "__main__":
  main()
