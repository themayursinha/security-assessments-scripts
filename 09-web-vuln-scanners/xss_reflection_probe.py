#!/usr/bin/env python3
"""Detect reflected XSS by classifying the context where markers land."""

import argparse
import re
import time
import urllib.parse

from sqli_detection_probe import build_url, fetch

MARKERS = [
  ("plain", "zxqmarker1"),
  ("tag-break", '"><svg/onload=zxqmarker2>'),
  ("attr-break", "'><img src=q onerror=zxqmarker3>"),
]

SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[a-zA-Z][^>]*>", re.DOTALL)


def classify_context(body, position):
  script_spans = [(m.start(), m.end()) for m in SCRIPT_RE.finditer(body)]
  for start, end in script_spans:
    if start < position < end:
      return "javascript"
  tag_spans = [(m.start(), m.end()) for m in TAG_RE.finditer(body[:position])]
  if tag_spans and body[tag_spans[-1][0]:position].find(">") == -1:
    inside = body[tag_spans[-1][0]:position]
    if re.search(r"=\s*[\"']?\s*$", inside):
      return "attribute-value"
    return "inside-tag"
  return "html-body"


def raw_html_survives(body, marker):
  index = body.find(marker)
  if index == -1:
    return False
  window = body[max(0, index - 80):index + len(marker) + 20]
  if "&lt;" in window or "%3C" in window.lower():
    return False
  return bool(re.search(r"<(svg|img)\b", window, re.IGNORECASE))


def main():
  parser = argparse.ArgumentParser(description="Probe parameter reflection for XSS context on an authorized target.")
  parser.add_argument("url", help="endpoint with injectable parameter")
  parser.add_argument("--param", default=None, help="parameter to test; default: first parameter in URL")
  parser.add_argument("--delay", type=float, default=0.2)
  args = parser.parse_args()

  param = args.param
  if not param:
    query = urllib.parse.urlsplit(args.url).query
    param = query.split("=")[0].split("&")[0] if "=" in query else "q"

  findings = []
  for label, payload in MARKERS:
    probe_url = build_url(args.url, param, payload)
    status, body = fetch(probe_url)
    if not body:
      print(f"[x] {label}: no response (HTTP {status})")
      time.sleep(args.delay)
      continue

    marker_token = re.search(r"zxqmarker\d", payload).group(0)
    positions = [m.start() for m in re.finditer(re.escape(marker_token), body)]
    if not positions:
      print(f"[ ] {label}: marker not reflected")
    else:
      position = positions[0]
      context = classify_context(body, position)
      unencoded = raw_html_survives(body, payload)
      verdict = {
        "javascript": "JS sink reflection - check encoding, then craft JS breakout",
        "attribute-value": "attribute reflection - try quote breakout",
        "inside-tag": "reflected inside a tag - try event-handler injection",
        "html-body": "plain HTML reflection - exploitable if tags survive",
      }[context]
      strength = "[!]" if unencoded or context == "javascript" else "[ ]"
      print(f"{strength} {label}: reflected in {context} context (HTTP {status})")
      snippet = body[max(0, position - 40):position + 80].replace("\n", " ")
      print(f"      ...{snippet}...")
      if not unencoded:
        print("      note: markup appears encoded; look for a decoding step or another sink")
      findings.append((context, unencoded))
    time.sleep(args.delay)

  hot = [f for f in findings if f[1]]
  if hot:
    print(f"\n{len(hot)} reflection(s) with unencoded markup - manually confirm execution.")
  else:
    print("\nNo unencoded reflections; review contexts above for other injection angles.")


if __name__ == "__main__":
  main()
