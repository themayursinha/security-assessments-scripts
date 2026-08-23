#!/usr/bin/env python3
"""Resolve candidate subdomains from a wordlist."""

import argparse
import socket
import time


def resolve(name):
  records = socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
  return sorted({record[4][0] for record in records})


def main():
  parser = argparse.ArgumentParser(description="Resolve subdomains from a wordlist.")
  parser.add_argument("domain", help="base domain, for example example.com")
  parser.add_argument("wordlist", help="file containing subdomain labels")
  parser.add_argument("--delay", type=float, default=0.0, help="delay between lookups in seconds")
  args = parser.parse_args()

  with open(args.wordlist, encoding="utf-8") as handle:
    words = [line.strip() for line in handle if line.strip() and not line.startswith("#")]

  for word in words:
    name = f"{word}.{args.domain}"
    try:
      addresses = resolve(name)
      print(f"{name}: {', '.join(addresses)}")
    except socket.gaierror:
      pass
    if args.delay:
      time.sleep(args.delay)


if __name__ == "__main__":
  main()
