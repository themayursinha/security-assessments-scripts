#!/usr/bin/env python3
"""Search logs for common security-relevant patterns."""

import argparse
import re


PATTERNS = {
  "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
  "url": re.compile(r"https?://[^\s\"'<>]+"),
  "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
  "auth": re.compile(r"\b(login|logout|failed|failure|denied|accepted|authentication)\b", re.I),
  "error": re.compile(r"\b(error|exception|traceback|fatal|panic)\b", re.I),
}


def main():
  parser = argparse.ArgumentParser(description="Grep logs for useful security patterns.")
  parser.add_argument("files", nargs="+", help="log files")
  parser.add_argument("--pattern", choices=sorted(PATTERNS), action="append", help="pattern to search; repeatable")
  parser.add_argument("--context", type=int, default=0, help="print N lines before and after matches")
  args = parser.parse_args()

  selected = args.pattern or sorted(PATTERNS)
  regexes = [(name, PATTERNS[name]) for name in selected]

  for path in args.files:
    with open(path, encoding="utf-8", errors="replace") as handle:
      lines = handle.readlines()
    matched = set()
    for index, line in enumerate(lines):
      hits = [name for name, regex in regexes if regex.search(line)]
      if hits:
        start = max(0, index - args.context)
        end = min(len(lines), index + args.context + 1)
        for row in range(start, end):
          if row not in matched:
            print(f"{path}:{row + 1}: {lines[row].rstrip()}")
            matched.add(row)
        print(f"  matched: {', '.join(hits)}")


if __name__ == "__main__":
  main()
