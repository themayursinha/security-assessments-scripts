#!/usr/bin/env python3
"""Scan a host for exposed source maps, VCS metadata, debug pages, and leaks."""

import argparse
import json
import re
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"

SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js)(?:\?[^"']*)?["']""", re.IGNORECASE)
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
INTERNAL_IP_RE = re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")

STACK_TRACES = [
  ("Python traceback", r"Traceback \(most recent call last\)"),
  ("Java stack trace", r"at (?:org|com|java)\.[\w.]+\([\w]+\.java:\d+\)"),
  (".NET exception", r"System\.\w+Exception:"),
  ("PHP warning/notice", r"(Warning|Notice|Fatal error):.*in /"),
  ("Rails error page", r"<title>Action Controller: Exception caught"),
  ("ASP.NET error", r"Server Error in .* Application"),
]

PATHS = [
  ("/.git/HEAD", "git repository metadata", "ref: refs/"),
  ("/.svn/wc.db", "SVN working copy database", "SQLite format 3"),
  ("/.env", "environment file", "="),
  ("/.DS_Store", "macOS directory metadata", None),
  ("/server-status", "Apache status page", "apache server status"),
  ("/debug/vars", "Go expvar endpoint", "cmdline"),
  ("/actuator/env", "Spring environment", "property"),
]


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    raw = response.read(1048576)
    return getattr(response, "status", response.code), raw
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(65536)
  except (urllib.error.URLError, OSError):
    return None, b""


def main():
  parser = argparse.ArgumentParser(description="Hunt common information-disclosure issues on an authorized host.")
  parser.add_argument("base_url", help="e.g. https://lab.example")
  parser.add_argument("--max-scripts", type=int, default=15)
  parser.add_argument("--timeout", type=float, default=8.0)
  args = parser.parse_args()

  base = args.base_url.rstrip("/")
  status, home = fetch(base + "/", args.timeout)
  if not home:
    raise SystemExit("could not fetch the base URL")
  html = home.decode("utf-8", "replace")
  findings = []

  print("[*] source maps for linked scripts:")
  scripts = list(dict.fromkeys(SCRIPT_SRC_RE.findall(html)))[: args.max_scripts]
  import urllib.parse as up
  origin = up.urlsplit(base).scheme + "://" + up.urlsplit(base).netloc
  for src in scripts:
    resolved = up.urljoin(origin, src)
    map_status, map_body = fetch(resolved + ".map", args.timeout)
    if map_status == 200 and b'"sources"' in map_body:
      try:
        sources = len(json.loads(map_body.decode("utf-8", "replace")).get("sources", []))
      except json.JSONDecodeError:
        sources = "?"
      print(f"[!] source map exposes {sources} original file(s): {resolved}.map")
      findings.append(("source map", resolved + ".map"))
    else:
      print(f"[ ] no map for {src}")

  print("\n[*] sensitive paths:")
  for path, label, marker in PATHS:
    probe_status, body = fetch(base + path, args.timeout)
    hit = probe_status == 200 and body and (marker is None or marker.lower() in body[:512].decode("utf-8", "replace").lower())
    flag = "[!]" if hit else "[ ]"
    size = len(body) if hit else 0
    print(f"{flag} {path:<18} HTTP {probe_status}" + (f" ({label}, {size}B)" if hit else ""))
    if hit:
      findings.append((label, base + path))

  print("\n[*] verbose error pages:")
  error_status, error_body = fetch(base + "/nonexistent-probe-'\"%00<", args.timeout)
  error_text = error_body.decode("utf-8", "replace")
  for label, pattern in STACK_TRACES:
    if re.search(pattern, error_text):
      position = re.search(pattern, error_text).start()
      snippet = error_text[max(0, position - 30):position + 90].replace("\n", " ")
      print(f"[!] {label} in error response: ...{snippet}...")
      findings.append(("stack trace", label))

  print("\n[*] HTML comment leakage:")
  for comment in COMMENT_RE.findall(html):
    emails = EMAIL_RE.findall(comment)
    ips = INTERNAL_IP_RE.findall(comment)
    if emails or ips or any(k in comment.lower() for k in ("todo", "fixme", "password", "internal")):
      snippet = comment.strip()[:140]
      print(f"[!] interesting comment: {snippet}")
      findings.append(("HTML comment", snippet))

  print()
  if findings:
    print(f"{len(findings)} disclosure finding(s) - verify each before reporting.")
  else:
    print("[+] No obvious disclosures detected.")


if __name__ == "__main__":
  main()
