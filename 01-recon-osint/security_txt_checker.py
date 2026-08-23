#!/usr/bin/env python3
"""Fetch and validate a security.txt file per RFC 9116."""

import argparse
import datetime as dt
import re
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"
REQUIRED_FIELDS = ["contact"]
RECOMMENDED_FIELDS = ["expires", "canonical", "policy", "preferred-languages", "encryption", "hiring"]

PATHS = [
  "https://{host}/.well-known/security.txt",
  "https://{host}/security.txt",
  "http://{host}/.well-known/security.txt",
  "http://{host}/security.txt",
]


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    with urllib.request.urlopen(request, timeout=timeout) as response:
      body = response.read(16384).decode("utf-8", "replace")
      return response.geturl(), getattr(response, "status", response.code), body
  except (urllib.error.HTTPError, urllib.error.URLError, OSError):
    return url, None, ""


def parse_fields(body):
  fields = {}
  for line in body.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
      continue
    if ":" not in line:
      continue
    key, _, value = line.partition(":")
    fields.setdefault(key.strip().lower(), []).append(value.strip())
  return fields


def parse_expires(value):
  try:
    normalized = re.sub(r"[zZ]$", "+00:00", value.strip())
    return dt.datetime.fromisoformat(normalized)
  except ValueError:
    return None


def main():
  parser = argparse.ArgumentParser(description="Discover and validate security.txt on an authorized host.")
  parser.add_argument("host", help="hostname or URL")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  args = parser.parse_args()

  host = urllib.parse.urlsplit(args.host).netloc if "//" in args.host else args.host

  found_url, status, body = None, None, ""
  for template in PATHS:
    candidate = template.format(host=host)
    final_url, status, body = fetch(candidate, args.timeout)
    if status == 200 and "contact" in body.lower():
      found_url = final_url
      break

  if not found_url:
    print(f"[!] no valid security.txt found on {host}")
    print("    Expected at https://{}/.well-known/security.txt".format(host))
    return

  print(f"[*] found: {found_url} (HTTP {status})\n")
  fields = parse_fields(body)
  for name in REQUIRED_FIELDS + RECOMMENDED_FIELDS + sorted(set(fields) - set(REQUIRED_FIELDS) - set(RECOMMENDED_FIELDS)):
    for value in fields.get(name, []):
      marker = "required" if name in REQUIRED_FIELDS else "optional"
      print(f"    {name}: {value}   [{marker}]")

  issues = []
  if not fields.get("contact"):
    issues.append("missing required Contact field")
  if not fields.get("expires"):
    issues.append("missing recommended Expires field")
  else:
    expires_at = parse_expires(fields["expires"][0])
    if expires_at is None:
      issues.append(f"Expires is not ISO 8601: {fields['expires'][0]}")
    elif expires_at < dt.datetime.now(dt.timezone.utc):
      issues.append("Expires date is in the past")
    elif expires_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=395):
      issues.append("Expires more than ~13 months out (RFC suggests under a year)")
  if found_url.startswith("http://"):
    issues.append("served over plain HTTP; RFC 9116 requires HTTPS")

  print()
  if issues:
    print("[!] findings:")
    for issue in issues:
      print(f"    - {issue}")
  else:
    print("[+] security.txt looks well-formed.")


if __name__ == "__main__":
  main()
