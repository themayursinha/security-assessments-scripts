#!/usr/bin/env python3
"""Parse saved Wi-Fi scan output for SSIDs and signal details."""

import argparse
import re


SSID_PATTERNS = [
  re.compile(r"SSID[:=]\s*(?P<ssid>.+)", re.I),
  re.compile(r"ESSID:\"(?P<ssid>.*)\"", re.I),
]
SIGNAL_PATTERN = re.compile(r"(signal|quality)[:=]\s*(?P<signal>[-\d/ %.]+)", re.I)
BSSID_PATTERN = re.compile(r"\b(?P<bssid>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)


def parse(path):
  current = {}
  with open(path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
      bssid = BSSID_PATTERN.search(line)
      if bssid:
        if current:
          yield current
        current = {"bssid": bssid.group("bssid")}
      for pattern in SSID_PATTERNS:
        match = pattern.search(line)
        if match:
          current["ssid"] = match.group("ssid").strip().strip('"')
      signal = SIGNAL_PATTERN.search(line)
      if signal:
        current["signal"] = signal.group("signal").strip()
  if current:
    yield current


def main():
  parser = argparse.ArgumentParser(description="Extract SSIDs from saved scan output.")
  parser.add_argument("files", nargs="+", help="scan output files")
  args = parser.parse_args()

  seen = set()
  for path in args.files:
    for network in parse(path):
      key = (network.get("bssid", ""), network.get("ssid", ""))
      if key in seen:
        continue
      seen.add(key)
      print(f"{network.get('bssid', 'unknown')} | {network.get('ssid', '<hidden>')} | {network.get('signal', '')}")


if __name__ == "__main__":
  main()
