#!/usr/bin/env python3
"""Check login endpoints for username enumeration via response or timing."""

import argparse
import difflib
import json
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "security-assessment-scripts/1.0"


def post(url, fields, as_json, timeout):
  if as_json:
    body = json.dumps(fields).encode()
    content_type = "application/json"
  else:
    body = urllib.parse.urlencode(fields).encode()
    content_type = "application/x-www-form-urlencoded"
  request = urllib.request.Request(url, data=body, headers={"User-Agent": UA, "Content-Type": content_type})
  start = time.monotonic()
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    body_out = response.read(131072).decode("utf-8", "replace")
    status = getattr(response, "status", response.code)
  except urllib.error.HTTPError as exc:
    body_out = exc.read(131072).decode("utf-8", "replace")
    status = exc.code
  except (urllib.error.URLError, OSError):
    return None, "", 0.0
  return status, body_out, time.monotonic() - start


def main():
  parser = argparse.ArgumentParser(description="Detect username enumeration on an authorized login endpoint.")
  parser.add_argument("url", help="login endpoint")
  parser.add_argument("--user-field", default="username")
  parser.add_argument("--pass-field", default="password")
  parser.add_argument("--valid-user", required=True, help="username known to exist")
  parser.add_argument("--invalid-user", default="zx-nonexistent-zz9", help="username assumed not to exist")
  parser.add_argument("--password", default="wrongpass12345", help="wrong password to submit")
  parser.add_argument("--json", action="store_true")
  parser.add_argument("--rounds", type=int, default=3, help="requests per user for timing averaging")
  parser.add_argument("--timeout", type=float, default=15.0)
  args = parser.parse_args()

  results = {}
  for label, username in (("valid", args.valid_user), ("invalid", args.invalid_user)):
    statuses, bodies, timings = [], [], []
    for _ in range(args.rounds):
      status, body, elapsed = post(args.url, {args.user_field: username, args.pass_field: args.password}, args.json, args.timeout)
      if status is None:
        raise SystemExit("request failed; check the URL/network")
      statuses.append(status)
      bodies.append(body)
      timings.append(elapsed)
      time.sleep(0.2)
    results[label] = {
      "status": statuses[0],
      "body": bodies[0],
      "median_time": statistics.median(timings),
    }
    print(f"[*] {label:<7} ({username}): HTTP {statuses[0]}, {len(bodies[0])} bytes, median {results[label]['median_time']*1000:.0f} ms")

  v, i = results["valid"], results["invalid"]
  findings = []

  if v["status"] != i["status"]:
    findings.append(f"status codes differ: valid={v['status']} vs invalid={i['status']}")

  if len(v["body"]) and abs(len(v["body"]) - len(i["body"])) > max(len(v["body"]), len(i["body"])) * 0.05:
    findings.append(f"response sizes differ by {abs(len(v['body']) - len(i['body']))} bytes")

  ratio = difflib.SequenceMatcher(None, v["body"], i["body"]).ratio()
  if ratio < 0.98:
    diff_sample = next((line for line in v["body"].splitlines() if line not in i["body"].splitlines()), "")[:120]
    findings.append(f"bodies differ (similarity {ratio:.3f}); e.g. {diff_sample!r}")

  delta_ms = abs(v["median_time"] - i["median_time"]) * 1000
  if delta_ms > 100:
    findings.append(f"median timing differs by {delta_ms:.0f} ms (valid={v['median_time']*1000:.0f}, invalid={i['median_time']*1000:.0f})")

  print()
  if findings:
    print("[!] Username enumeration indicators:")
    for finding in findings:
      print(f"    - {finding}")
  else:
    print("[+] No enumeration indicators across status, size, content, and timing.")


if __name__ == "__main__":
  main()
