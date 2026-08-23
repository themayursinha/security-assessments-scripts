#!/usr/bin/env python3
"""Send concurrent identical requests to surface race-condition behavior."""

import argparse
import http.client
import json
import ssl
import threading
import time
import urllib.parse


def send_once(parsed, data, cookie, results, index, barrier, timeout, as_json):
  connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
  context = None
  if parsed.scheme == "https":
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
  kwargs = {"timeout": timeout}
  if context:
    kwargs["context"] = context
  path = parsed.path or "/"
  if parsed.query:
    path += "?" + parsed.query

  if as_json and isinstance(data, str):
    body, content_type = data.encode(), "application/json"
  elif isinstance(data, dict):
    body, content_type = urllib.parse.urlencode(data).encode(), "application/x-www-form-urlencoded"
  elif isinstance(data, str) and data:
    body, content_type = data.encode(), "application/x-www-form-urlencoded"
  else:
    body, content_type = None, None

  barrier.wait()
  start = time.monotonic()
  try:
    connection = connection_class(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), **kwargs)
    headers = {"User-Agent": "security-assessment-scripts/1.0"}
    if cookie:
      headers["Cookie"] = cookie
    if body:
      headers["Content-Type"] = content_type
    connection.request("POST" if body else "GET", path, body=body, headers=headers)
    response = connection.getresponse()
    response.read(4096)
    results[index] = (getattr(response, "status", response.code), round(time.monotonic() - start, 3))
    connection.close()
  except Exception as exc:
    results[index] = (f"ERR {type(exc).__name__}", round(time.monotonic() - start, 3))


def main():
  parser = argparse.ArgumentParser(description="Fire N simultaneous identical requests to test synchronization on an authorized endpoint.")
  parser.add_argument("url", help="target endpoint")
  parser.add_argument("--data", default=None, help="form body to POST, e.g. 'coupon=FREE5' (GET when omitted)")
  parser.add_argument("--cookie", default=None, help="session cookie header value")
  parser.add_argument("--count", type=int, default=20, help="number of requests to fire")
  parser.add_argument("--json", action="store_true", help="send --data as a JSON object instead")
  parser.add_argument("--timeout", type=float, default=15.0)
  args = parser.parse_args()

  parsed = urllib.parse.urlsplit(args.url)

  print(f"[*] firing {args.count} synchronized requests at {parsed.netloc}{parsed.path}")
  results = [None] * args.count
  barrier = threading.Barrier(args.count)
  threads = []
  for index in range(args.count):
    thread = threading.Thread(
      target=send_once,
      args=(parsed, args.data, args.cookie, results, index, barrier, args.timeout, args.json),
    )
    threads.append(thread)
    thread.start()
  for thread in threads:
    thread.join()

  statuses_summary = {}
  for status, elapsed in sorted(results, key=lambda r: r[1]):
    statuses_summary[str(status)] = statuses_summary.get(str(status), 0) + 1
    print(f"    HTTP {status} in {elapsed}s")

  print(f"\n[*] distribution: {statuses_summary}")
  successes = sum(count for code, count in statuses_summary.items() if code.startswith("2"))
  rejects = sum(count for code, count in statuses_summary.items() if code.startswith("4") and code != "429")
  if successes >= 2 and rejects >= 1:
    print(f"[!] {successes} requests succeeded while {rejects} were rejected - possible race window.")
    print("Verify whether that many concurrent successes should be possible; for serious racing")
    print("use Burp Turbo Intruder with HTTP/2 last-byte synchronization.")
  elif successes >= 2:
    print("[?] All requests succeeded - if this action should be single-use, that is a finding.")
  else:
    print("[+] No obvious concurrency anomaly; the endpoint may enforce limits server-side.")


if __name__ == "__main__":
  main()
