#!/usr/bin/env python3
"""Check whether local lab web targets are reachable."""

import argparse
import urllib.error
import urllib.request


DEFAULT_TARGETS = [
  "http://127.0.0.1:3000",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:8000",
]


def check(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": "security-assessment-scripts/1.0"})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.geturl(), response.headers.get("Server", "")
  except urllib.error.HTTPError as exc:
    return exc.code, exc.geturl(), exc.headers.get("Server", "")


def main():
  parser = argparse.ArgumentParser(description="Check local lab targets for reachability.")
  parser.add_argument("targets", nargs="*", default=DEFAULT_TARGETS, help="URLs to check")
  parser.add_argument("--timeout", type=float, default=3.0, help="request timeout in seconds")
  args = parser.parse_args()

  for url in args.targets:
    try:
      status, final_url, server = check(url, args.timeout)
      print(f"UP {status} {url} -> {final_url} {server}")
    except Exception as exc:
      print(f"DOWN {url} | {exc}")


if __name__ == "__main__":
  main()
