#!/usr/bin/env python3
"""Fetch a URL and summarize common HTTP security headers."""

import argparse
import http.cookiejar
import urllib.error
import urllib.request


SECURITY_HEADERS = [
  "Content-Security-Policy",
  "Strict-Transport-Security",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
  "Cross-Origin-Embedder-Policy",
]


def build_opener():
  cookie_jar = http.cookiejar.CookieJar()
  return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar)), cookie_jar


def fetch_headers(url, timeout):
  opener, cookie_jar = build_opener()
  request = urllib.request.Request(url, headers={"User-Agent": "security-assessment-scripts/1.0"})
  try:
    response = opener.open(request, timeout=timeout)
  except urllib.error.HTTPError as exc:
    response = exc
  return response, cookie_jar


def print_report(url, response, cookie_jar):
  print(f"URL: {url}")
  print(f"Status: {getattr(response, 'status', response.code)}")
  print(f"Final URL: {response.geturl()}")
  print()
  print("Security headers:")
  for header in SECURITY_HEADERS:
    value = response.headers.get(header)
    print(f"  {header}: {value if value else 'MISSING'}")

  print()
  print("Cookies:")
  if not cookie_jar:
    print("  No cookies set")
  for cookie in cookie_jar:
    secure = "Secure" if cookie.secure else "not Secure"
    httponly = "HttpOnly" if "httponly" in {k.lower() for k in cookie._rest} else "not HttpOnly"
    samesite = cookie._rest.get("SameSite") or cookie._rest.get("samesite") or "missing SameSite"
    print(f"  {cookie.name}: {secure}, {httponly}, {samesite}")


def main():
  parser = argparse.ArgumentParser(description="Summarize HTTP security headers for a URL.")
  parser.add_argument("url", help="URL to fetch")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  args = parser.parse_args()

  response, cookie_jar = fetch_headers(args.url, args.timeout)
  print_report(args.url, response, cookie_jar)


if __name__ == "__main__":
  main()
