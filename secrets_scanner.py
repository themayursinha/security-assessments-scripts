#!/usr/bin/env python3
"""Scan files for likely secrets and report redacted matches."""

import argparse
import math
import re
import sys
from pathlib import Path

PATTERNS = [
  ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
  ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
  ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
  ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
  ("Stripe key", re.compile(r"\b[sp]k_(live|test)_[0-9A-Za-z]{16,}\b")),
  ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
  ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b")),
  ("Generic assignment secret", re.compile(r"(?i)(api[_-]?key|api[_-]?secret|secret|password|passwd|pwd|token|access[_-]?key)[\"']?\s*[:=]\s*(?:[\"'][^\"']{8,}[\"']|[^\s\"']{8,})")),
]

ASSIGNMENT_PATTERN_INDEX = len(PATTERNS) - 1

SKIP_DIRS = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".mp3", ".mp4"}

MAX_TEXT_SIZE = 2 * 1024 * 1024


def shannon_entropy(value):
  if not value:
    return 0.0
  frequencies = {}
  for char in value:
    frequencies[char] = frequencies.get(char, 0) + 1
  length = len(value)
  return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def redact(match_text):
  visible = match_text[:6]
  return f"{visible}...[redacted {len(match_text)} chars]"


def scan_line(line):
  findings = []
  for label, pattern in PATTERNS:
    for match in pattern.finditer(line):
      findings.append((label, match.group(0)))
  quoted_value = None
  generic = PATTERNS[ASSIGNMENT_PATTERN_INDEX][1].search(line)
  if generic:
    quoted_value = generic.group(0)
    entropy_target = quoted_value.rsplit("=", 1)[-1] if "=" in quoted_value else quoted_value.rsplit(":", 1)[-1]
    stripped = entropy_target.strip("\"' ")
    if shannon_entropy(stripped) >= 4.2:
      findings.append(("high-entropy assignment", quoted_value))
  return findings


def looks_like_minified_or_lockfile(path):
  name = path.name.lower()
  return name.endswith((".min.js", "package-lock.json", "yarn.lock", "poetry.lock", "composer.lock"))


def scan_file(path):
  try:
    if path.stat().st_size > MAX_TEXT_SIZE or path.suffix.lower() in BINARY_EXTENSIONS:
      return []
    data = path.read_bytes()
  except OSError:
    return []
  if b"\x00" in data[:4096]:
    return []

  findings = []
  try:
    text = data.decode("utf-8")
  except UnicodeDecodeError:
    text = data.decode("latin-1")

  for line_number, line in enumerate(text.splitlines(), start=1):
    for label, matched in scan_line(line):
      findings.append((path, line_number, label, redact(matched)))
  return findings


def iter_files(targets):
  for target in targets:
    path = Path(target)
    if path.is_file():
      yield path
    elif path.is_dir():
      for child in path.rglob("*"):
        if child.is_file() and not any(part in SKIP_DIRS for part in child.parts):
          yield child


def main():
  parser = argparse.ArgumentParser(description="Search files for credential-like strings; output is always redacted.")
  parser.add_argument("targets", nargs="+", help="files or directories to scan")
  parser.add_argument("--strict", action="store_true", help="skip lockfile/minified noise sources")
  args = parser.parse_args()

  total_findings = 0
  scanned = 0

  for path in iter_files(args.targets):
    if args.strict and looks_like_minified_or_lockfile(path):
      continue
    scanned += 1
    for file_path, line_number, label, redacted_match in scan_file(path):
      total_findings += 1
      print(f"[!] {label}: {file_path}:{line_number} -> {redacted_match}")

  print(f"\nScanned {scanned} file(s); found {total_findings} potential secret(s).")
  if total_findings:
    sys.exit(1)


if __name__ == "__main__":
  main()
