#!/usr/bin/env python3
"""Inspect Set-Cookie attributes for Secure, HttpOnly, and SameSite."""

import argparse
import http.cookies
import urllib.error
import urllib.request


def main():
  parser = argparse.ArgumentParser(description="Check Set-Cookie security attributes.")
  parser.add_argument("url", help="URL to fetch")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  args = parser.parse_args()

  request = urllib.request.Request(args.url, headers={"User-Agent": "security-assessment-scripts/1.0"})
  try:
    response = urllib.request.urlopen(request, timeout=args.timeout)
  except urllib.error.HTTPError as exc:
    response = exc

  cookies = response.headers.get_all("Set-Cookie", [])
  if not cookies:
    print("No Set-Cookie headers found")
    return

  for header in cookies:
    parsed = http.cookies.SimpleCookie()
    parsed.load(header)
    for name, morsel in parsed.items():
      secure = "yes" if morsel["secure"] else "no"
      httponly = "yes" if morsel["httponly"] else "no"
      samesite = morsel["samesite"] or "missing"
      print(f"{name}: Secure={secure} HttpOnly={httponly} SameSite={samesite}")


if __name__ == "__main__":
  main()
