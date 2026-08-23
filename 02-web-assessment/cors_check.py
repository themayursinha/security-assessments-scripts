#!/usr/bin/env python3
"""Check CORS response headers for one or more Origin values."""

import argparse
import urllib.error
import urllib.request


def check(url, origin, timeout):
  request = urllib.request.Request(url, headers={"Origin": origin, "User-Agent": "security-assessment-scripts/1.0"})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
  except urllib.error.HTTPError as exc:
    response = exc
  return {
    "status": getattr(response, "status", response.code),
    "allow_origin": response.headers.get("Access-Control-Allow-Origin", ""),
    "allow_credentials": response.headers.get("Access-Control-Allow-Credentials", ""),
    "vary": response.headers.get("Vary", ""),
  }


def main():
  parser = argparse.ArgumentParser(description="Check CORS behavior for supplied origins.")
  parser.add_argument("url", help="target URL")
  parser.add_argument("--origin", action="append", required=True, help="Origin header to test; repeatable")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  args = parser.parse_args()

  for origin in args.origin:
    result = check(args.url, origin, args.timeout)
    print(f"Origin: {origin}")
    print(f"  Status: {result['status']}")
    print(f"  Access-Control-Allow-Origin: {result['allow_origin'] or 'MISSING'}")
    print(f"  Access-Control-Allow-Credentials: {result['allow_credentials'] or 'MISSING'}")
    print(f"  Vary: {result['vary'] or 'MISSING'}")


if __name__ == "__main__":
  main()
