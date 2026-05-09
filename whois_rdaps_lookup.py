#!/usr/bin/env python3
"""Look up IP or domain registration data with RDAP endpoints."""

import argparse
import ipaddress
import json
import urllib.parse
import urllib.request


def rdap_url(value):
  try:
    ipaddress.ip_address(value)
    return f"https://rdap.org/ip/{urllib.parse.quote(value)}"
  except ValueError:
    return f"https://rdap.org/domain/{urllib.parse.quote(value)}"


def fetch_json(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": "security-assessment-scripts/1.0"})
  with urllib.request.urlopen(request, timeout=timeout) as response:
    return json.loads(response.read().decode())


def main():
  parser = argparse.ArgumentParser(description="Fetch RDAP data for a domain or IP address.")
  parser.add_argument("target", help="domain or IP address")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  parser.add_argument("--raw", action="store_true", help="print full RDAP JSON")
  args = parser.parse_args()

  data = fetch_json(rdap_url(args.target), args.timeout)
  if args.raw:
    print(json.dumps(data, indent=2, sort_keys=True))
    return

  print(f"Handle: {data.get('handle', '')}")
  print(f"Name: {data.get('name', data.get('ldhName', ''))}")
  print(f"Type: {data.get('objectClassName', '')}")
  for event in data.get("events", []):
    print(f"Event: {event.get('eventAction')} {event.get('eventDate')}")
  for entity in data.get("entities", []):
    roles = ", ".join(entity.get("roles", []))
    print(f"Entity: {entity.get('handle', '')} ({roles})")


if __name__ == "__main__":
  main()
