#!/usr/bin/env python3
"""Probe endpoints for server-side prototype pollution indicators."""

import argparse
import json
import time
import urllib.parse

from sqli_detection_probe import fetch

QUERY_VARIANTS = [
  "__proto__[zxpolluted]=zxvalue",
  "__proto__.zxpolluted=zxvalue",
  "constructor[prototype][zxpolluted]=zxvalue",
  "constructor.prototype.zxpolluted=zxvalue",
]

JSON_KEYS = [
  {"__proto__": {"zxpolluted": "zxvalue"}},
  {"constructor": {"prototype": {"zxpolluted": "zxvalue"}}},
]


def main():
  parser = argparse.ArgumentParser(description="Probe query/body parameters for server-side prototype pollution.")
  parser.add_argument("url", help="endpoint to test")
  parser.add_argument("--param", default=None, help="existing parameter whose value is echoed into JSON responses")
  parser.add_argument("--json-body", default=None,
                      help='baseline JSON body template; use "POLLUTE" as a key placeholder, e.g. \'{"email":"a@b.c","POLLUTE":1}\'')
  parser.add_argument("--delay", type=float, default=0.2)
  args = parser.parse_args()

  confirmed = []

  print("[*] query-string variants:")
  baseline_status, baseline_body = fetch(args.url, timeout=10)
  for variant in QUERY_VARIANTS:
    separator = "&" if "?" in args.url else "?"
    probe_url = f"{args.url}{separator}{variant}"
    status, body = fetch(probe_url, timeout=10)
    reflected = "zxpolluted" in body and "zxpolluted" not in baseline_body
    status_change = baseline_status is not None and status not in (None, baseline_status)
    flag = "[!]" if reflected else "[ ]"
    detail = []
    if reflected:
      detail.append("polluted key/value reflected")
      confirmed.append(variant)
    if status_change:
      detail.append(f"status {baseline_status} -> {status}")
    print(f"{flag} {variant:<42} HTTP {status}" + (f" ({'; '.join(detail)})" if detail else ""))
    time.sleep(args.delay)

  if args.json_body:
    print("\n[*] JSON body variants:")
    try:
      template = json.loads(args.json_body)
    except json.JSONDecodeError as exc:
      raise SystemExit(f"--json-body is not valid JSON: {exc}")

    def send(obj):
      return fetch(args.url, data=json.dumps(obj), timeout=10)

    from sqli_detection_probe import UA
    import urllib.request

    def post_json(obj):
      request = urllib.request.Request(
        args.url, data=json.dumps(obj).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json"})
      import urllib.error
      try:
        response = urllib.request.urlopen(request, timeout=10)
        return getattr(response, "status", response.code), response.read(65536).decode("utf-8", "replace")
      except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536).decode("utf-8", "replace")

    b_status, b_body = post_json({k: v for k, v in template.items() if k != "POLLUTE"})
    for pollution in JSON_KEYS:
      payload_obj = {}
      for key, value in template.items():
        if key == "POLLUTE":
          payload_obj.update(pollution)
        else:
          payload_obj[key] = value
      status, body = post_json(payload_obj)
      reflected = "zxpolluted" in body and "zxpolluted" not in b_body
      flag = "[!]" if reflected else "[ ]"
      print(f"{flag} {list(pollution.keys())[0]:<30} HTTP {status}" + (" (reflected)" if reflected else ""))
      if reflected:
        confirmed.append(str(pollution))
        break
      time.sleep(args.delay)

  print()
  if confirmed:
    print("[!] Server-side prototype pollution candidates:")
    for item in confirmed:
      print(f"    - {item}")
    print("Confirm by observing behavior changes tied to the polluted property (privilege flags, headers, rendered output).")
  else:
    print("[+] No server-side pollution indicators; client-side gadgets need browser analysis.")


if __name__ == "__main__":
  main()
