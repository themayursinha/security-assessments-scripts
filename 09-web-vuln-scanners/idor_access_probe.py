#!/usr/bin/env python3
"""Probe object IDs with a low-privilege session for access control gaps."""

import argparse
import difflib
import re
import time
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"


def fetch(url, cookie, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA, "Cookie": cookie})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(131072).decode("utf-8", "replace")
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(131072).decode("utf-8", "replace")
  except (urllib.error.URLError, OSError):
    return None, ""


def main():
  parser = argparse.ArgumentParser(description="Enumerate object IDs as a low-privilege user on an authorized target.")
  parser.add_argument("url_template", help='URL containing "{ID}", e.g. "https://lab.example/user/{ID}/profile" or "...?id={ID}"')
  parser.add_argument("--cookie", required=True, help="low-privilege session cookie, e.g. 'session=abc'")
  parser.add_argument("--own-id", required=True, help="the ID your low-privilege account legitimately sees")
  parser.add_argument("--ids", default=None, help="comma-separated IDs to test; default: 1..10 plus neighbors of --own-id")
  parser.add_argument("--leak-markers", default="carlos@,admin@,@internal,.gov,.corp",
                      help="comma-separated strings that indicate another principal's data")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  if "{ID}" not in args.url_template:
    raise SystemExit('url_template must contain the literal placeholder {ID}')

  if args.ids:
    ids = [i.strip() for i in args.ids.split(",") if i.strip()]
  else:
    base = int(re.sub(r"\D", "", args.own_id) or 1)
    ids = [str(n) for n in range(1, 11) if str(n) != args.own_id]
    for neighbor in (base - 1, base + 1, base + 2):
      if neighbor > 0 and str(neighbor) != args.own_id and str(neighbor) not in ids:
        ids.append(str(neighbor))

  markers = [m.strip() for m in args.leak_markers.split(",") if m.strip()]

  own_status, own_body = fetch(args.url_template.replace("{ID}", args.own_id), args.cookie, args.timeout)
  print(f"[*] own ID ({args.own_id}): HTTP {own_status}, {len(own_body)} bytes\n")

  findings = []
  for object_id in ids:
    status, body = fetch(args.url_template.replace("{ID}", object_id), args.cookie, args.timeout)
    if status is None:
      print(f"[ ] ID {object_id}: no response")
      continue

    leaked_markers = [m for m in markers if m in body]
    similar_to_own = difflib.SequenceMatcher(None, body, own_body).ratio()
    accessible = status == 200 and len(body) > 100
    differs_from_own = similar_to_own < 0.995

    flags = []
    if leaked_markers:
      flags.append(f"data markers: {', '.join(leaked_markers)}")
    if accessible and differs_from_own:
      flags.append(f"200 with distinct content ({len(body)}B, sim={similar_to_own:.3f})")

    flag = "[!]" if flags else "[ ]"
    print(f"{flag} ID {object_id}: HTTP {status}, {len(body)} bytes" + (f" -> {'; '.join(flags)}" if flags else ""))
    if leaked_markers:
      position = body.find(leaked_markers[0])
      snippet = body[max(0, position - 60):position + 80].replace("\n", " ")
      print(f"      evidence: ...{snippet}...")
      findings.append(object_id)
    elif accessible and differs_from_own and own_status == 403 or (own_status == 302 and status == 200):
      findings.append(object_id)
    time.sleep(0.2)

  print()
  if findings:
    print(f"[!] {len(findings)} object(s) readable outside your authorization context: {', '.join(findings)}")
    print("Verify each manually against the application's intended permission model.")
  else:
    print("[+] No cross-principal reads detected among tested IDs.")


if __name__ == "__main__":
  main()
