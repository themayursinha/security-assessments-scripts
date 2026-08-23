#!/usr/bin/env python3
"""Probe authorized web paths from a wordlist with rate limiting."""

import argparse
import time
import urllib.error
import urllib.parse
import urllib.request


def probe(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": "security-assessment-scripts/1.0"})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    body = response.read(512)
    return getattr(response, "status", response.code), response.headers.get("Content-Length", len(body)), response.geturl()
  except urllib.error.HTTPError as exc:
    return exc.code, exc.headers.get("Content-Length", 0), exc.geturl()


def main():
  parser = argparse.ArgumentParser(description="Probe paths from a wordlist against an authorized target.")
  parser.add_argument("base_url", help="authorized base URL")
  parser.add_argument("wordlist", help="file of paths")
  parser.add_argument("--delay", type=float, default=0.2, help="delay between requests in seconds")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  parser.add_argument("--show-all", action="store_true", help="show non-interesting status codes too")
  args = parser.parse_args()

  base = args.base_url.rstrip("/") + "/"
  with open(args.wordlist, encoding="utf-8") as handle:
    paths = [line.strip().lstrip("/") for line in handle if line.strip() and not line.startswith("#")]

  for path in paths:
    url = urllib.parse.urljoin(base, path)
    try:
      status, length, final_url = probe(url, args.timeout)
      if args.show_all or status not in {404, 400}:
        print(f"{status} {length} {url} -> {final_url}")
    except Exception as exc:
      if args.show_all:
        print(f"ERR {url} | {exc}")
    time.sleep(args.delay)


if __name__ == "__main__":
  main()
