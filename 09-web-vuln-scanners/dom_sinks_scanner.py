#!/usr/bin/env python3
"""Scan page JavaScript for DOM-based vulnerability sinks and patterns."""

import argparse
import re
import urllib.error
import urllib.parse
import urllib.request

UA = "security-assessment-scripts/1.0"

SOURCES_HINT = r"(?:location(?:\.(?:search|hash|href|pathname))?|document\.URL|document\.referrer|window\.name|event\.data)"

PATTERNS = [
  ("innerHTML from source", re.compile(rf"innerHTML\s*=\s*[^'\";\n]*{SOURCES_HINT}", re.IGNORECASE)),
  ("outerHTML from source", re.compile(rf"outerHTML\s*=\s*[^'\";\n]*{SOURCES_HINT}", re.IGNORECASE)),
  ("document.write from source", re.compile(rf"document\.write\s*\([^)]*{SOURCES_HINT}", re.IGNORECASE)),
  ("eval-like sink", re.compile(r"\beval\s*\(|new\s+Function\s*\(")),
  ("setTimeout/setInterval with string", re.compile(r"set(?:Timeout|Interval)\s*\(\s*[\"']")),
  ("location assignment from variable", re.compile(r"(?:location(?:\.href)?|window\.location)\s*=\s*(?!location)[a-zA-Z_$][\w.$\[\]'\"\]]*\s*[;,\n)]")),
  ("jQuery HTML sink", re.compile(r"\$\([^)]*\)\.html\s*\(|\.html\s*\(\s*(?!['\"])")),
  ("postMessage target *", re.compile(r"postMessage\s*\([^)]*,\s*[\"']\*[\"']\)")),
  ("message handler without origin check", None),
]

MESSAGE_HANDLER_RE = re.compile(
  r"addEventListener\(\s*[\"']message[\"']\s*,\s*(function[^{]*\{.*?\}|[\w.$]+)",
  re.IGNORECASE | re.DOTALL,
)
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(1048576).decode("utf-8", "replace")
  except (urllib.error.HTTPError, urllib.error.URLError, OSError):
    return None, ""


def line_number(text, position):
  return text.count("\n", 0, position) + 1


def scan_js(source, origin_label):
  findings = []
  for name, pattern in PATTERNS:
    if pattern is None:
      continue
    for match in pattern.finditer(source):
      snippet = source[max(0, match.start() - 30):match.end() + 40].replace("\n", " ")
      findings.append((origin_label, name, line_number(source, match.start()), snippet.strip()[:150]))

  for match in MESSAGE_HANDLER_RE.finditer(source):
    handler_body = match.group(1)
    window = source[match.end():match.end() + 400]
    combined = handler_body + window
    if "origin" not in combined.lower():
      findings.append((origin_label, "message handler without origin validation",
                       line_number(source, match.start()),
                       match.group(0)[:150].replace("\n", " ")))
  return findings


def main():
  parser = argparse.ArgumentParser(description="Static-scan a page's inline and external scripts for DOM XSS sinks and risky patterns.")
  parser.add_argument("url", help="page to analyze")
  parser.add_argument("--max-scripts", type=int, default=15)
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  status, html = fetch(args.url, args.timeout)
  if not html:
    raise SystemExit(f"could not fetch {args.url}")

  parsed = urllib.parse.urlsplit(args.url)
  base_origin = f"{parsed.scheme}://{parsed.netloc}"

  all_findings = []

  for index, block in enumerate(INLINE_SCRIPT_RE.findall(html)):
    all_findings.extend(scan_js(block, f"inline script #{index + 1}"))

  external_scripts = []
  for src in SCRIPT_SRC_RE.findall(html):
    resolved = urllib.parse.urljoin(base_origin, src)
    if len(external_scripts) >= args.max_scripts:
      break
    if resolved.startswith(("http://", "https://")):
      external_scripts.append(resolved)

  print(f"[*] fetched page; found {len(external_scripts)} external script(s) to scan\n")
  for script_url in external_scripts:
    status, js_source = fetch(script_url, args.timeout)
    label = "OK " if status == 200 else f"{status}"
    print(f"[ ] {label} {script_url}")
    if js_source:
      script_findings = scan_js(js_source, script_url)
      all_findings.extend(script_findings)

  print()
  if all_findings:
    print(f"[!] {len(all_findings)} sink/pattern finding(s):")
    for origin_label, name, line_no, snippet in all_findings:
      print(f"    [{name}] {origin_label}:{line_no}")
      print(f"        {snippet}")
    print("\nThese are heuristic indicators - confirm data flow from source to sink in a browser.")
  else:
    print("[+] No obvious DOM sinks or risky patterns found in scanned scripts.")


if __name__ == "__main__":
  main()
