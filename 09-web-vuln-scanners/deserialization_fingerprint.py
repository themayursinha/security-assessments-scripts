#!/usr/bin/env python3
"""Fingerprint serialized objects in cookies, bodies, and page fields."""

import argparse
import base64
import binascii
import re
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"

BASE64_SIGNATURES = [
  ("PHP serialized object", re.compile(r"^[Oa]:\d+:"),
   "exploitable if attacker-controlled (POP gadget chains)"),
  ("Java serialized object", re.compile(r"^rO0AB"),
   "high impact with known gadget chains; needs a vulnerable library"),
  ("Python pickle", re.compile(r"^gASV"),
   "remote code execution if deserialized untrusted (pickle.load)"),
  ("Ruby Marshal", re.compile(r"^BAh"),
   "RCE risk with crafted marshal payloads"),
  (".NET ViewState", re.compile(r"^/wEP|^/wEY|^/wPv"),
   "RCE if machineKey leaked or validation disabled"),
]

HEX_PREFIX = b"\xac\xed\x00\x05"
VIEWSTATE_FIELD = re.compile(r"name=\"__VIEWSTATE\"[^>]*value=\"([^\"]{20,})\"", re.IGNORECASE)


def classify(value):
  value = value.strip()
  for name, pattern, note in BASE64_SIGNATURES:
    if pattern.match(value):
      return name, note
  try:
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    if decoded.startswith(HEX_PREFIX):
      return "Java serialized object (hex)", "raw ac ed form; same gadget-chain risk as rO0AB"
  except (binascii.Error, ValueError):
    pass
  return None, ""


def scan_page(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  findings = []
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    headers = response.headers
    body = response.read(262144).decode("utf-8", "replace")
  except (urllib.error.HTTPError, urllib.error.URLError, OSError):
    return findings

  for header in headers.get_all("Set-Cookie") or []:
    cookie_name = header.split("=", 1)[0]
    cookie_value = header.split("=", 1)[1].split(";")[0]
    fmt, note = classify(cookie_value)
    if fmt:
      findings.append((f"cookie '{cookie_name}'", fmt, note))

  for match in VIEWSTATE_FIELD.finditer(body):
    fmt, note = classify(match.group(1))
    if fmt:
      findings.append(("__VIEWSTATE field", fmt, note))
  return findings


def main():
  parser = argparse.ArgumentParser(description="Spot serialization formats in cookies/fields that may be exploitable.")
  parser.add_argument("url", nargs="?", help="page whose cookies and hidden fields to inspect")
  parser.add_argument("--value", default=None, help="classify an arbitrary raw string instead")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  if args.value:
    fmt, note = classify(args.value)
    print(f"[!] {fmt} - {note}" if fmt else "[ ] no known serialization format detected")
    return

  if not args.url:
    raise SystemExit("provide a URL or --value")

  findings = scan_page(args.url, args.timeout)
  print(f"[*] scanned {args.url}")
  if not findings:
    print("[+] No recognizable serialized objects in Set-Cookie or __VIEWSTATE.")
    return
  for where, fmt, note in findings:
    print(f"[!] {fmt} in {where}")
    print(f"      impact: {note}")


if __name__ == "__main__":
  main()
