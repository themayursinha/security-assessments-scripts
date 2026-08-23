#!/usr/bin/env python3
"""Fingerprint server-side template injection by matching math results."""

import argparse
import re
import time

from sqli_detection_probe import build_url, fetch

ENGINE_PAYLOADS = [
  ("Jinja2/Twig {{}}", "{{7*7}}", "49"),
  ("Jinja2 (string mult)", "{{7*'7'}}", "7777777"),
  ("Twig (string mult)", "{{7*'7'}}", "49"),
  ("Freemarker/Velocity ${}", "${7*7}", "49"),
  ("ERB/EJS <%%>", "<%= 7*7 %>", "49"),
  ("Ruby/Thymeleaf #{}", "#{7*7}", "49"),
  ("Pebble/Mavo {}", "{7*7}", "49"),
  ("Smarty {php-ish}", "{7*7}", "49"),
]


def main():
  parser = argparse.ArgumentParser(description="Detect SSTI on an authorized target and fingerprint the template engine.")
  parser.add_argument("url", help="endpoint with injectable parameter")
  parser.add_argument("--param", default=None, help="parameter to test; default: first parameter in URL")
  parser.add_argument("--delay", type=float, default=0.2)
  args = parser.parse_args()

  import urllib.parse
  param = args.param
  if not param:
    query = urllib.parse.urlsplit(args.url).query
    param = query.split("=")[0].split("&")[0] if "=" in query else "q"

  baseline_status, baseline_body = fetch(build_url(args.url, param, "sstibaseline"), timeout=10)
  print(f"[*] baseline: HTTP {baseline_status}, {len(baseline_body)} bytes\n")

  confirmed = []
  for engine, payload, expected in ENGINE_PAYLOADS:
    status, body = fetch(build_url(args.url, param, payload), timeout=10)
    hit = expected in body and expected not in baseline_body
    flag = "[!]" if hit else "[ ]"
    print(f"{flag} {engine:<22} payload={payload:<16} expect={expected:<8} HTTP {status}")
    if hit:
      position = body.find(expected)
      snippet = body[max(0, position - 50):position + 20].replace("\n", " ")
      print(f"      evidence: ...{snippet}...")
      confirmed.append((engine, payload))
    time.sleep(args.delay)

  print()
  if not confirmed:
    print("[+] no template evaluation detected; syntax may be filtered or engine differs.")
    return

  engines = sorted({engine.split()[0] for engine, _ in confirmed})
  print(f"[!] SSTI confirmed; candidate engines: {', '.join(engines)}")
  jinja_hint = [p for eng, p in confirmed if "Jinja2 (string mult)" in eng]
  twig_hint = [p for eng, p in confirmed if "Twig (string mult)" in eng]
  if jinja_hint:
    print("    {{7*'7'}} -> 7777777 narrows this to Jinja2.")
  elif twig_hint:
    print("    {{7*'7'}} -> 49 narrows this to Twig.")


if __name__ == "__main__":
  main()
