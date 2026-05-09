#!/usr/bin/env python3
"""Fetch JSON endpoints and summarize status, content type, keys, and size."""

import argparse
import json
import urllib.error
import urllib.request


def summarize_json(value):
  if isinstance(value, dict):
    return f"object keys={', '.join(sorted(value.keys())[:20])}"
  if isinstance(value, list):
    return f"array length={len(value)}"
  return type(value).__name__


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "security-assessment-scripts/1.0"})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    body = response.read()
  except urllib.error.HTTPError as exc:
    response = exc
    body = exc.read()
  content_type = response.headers.get("Content-Type", "")
  try:
    parsed = json.loads(body.decode())
    summary = summarize_json(parsed)
  except Exception as exc:
    summary = f"JSON parse failed: {exc}"
  return getattr(response, "status", response.code), content_type, len(body), summary


def main():
  parser = argparse.ArgumentParser(description="Probe JSON endpoints and summarize responses.")
  parser.add_argument("urls", nargs="+", help="endpoint URLs")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  args = parser.parse_args()

  for url in args.urls:
    try:
      status, content_type, size, summary = fetch(url, args.timeout)
      print(f"{status} {size} bytes {content_type} {url} | {summary}")
    except Exception as exc:
      print(f"ERR {url} | {exc}")


if __name__ == "__main__":
  main()
