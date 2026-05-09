#!/usr/bin/env python3
"""Resolve common DNS records with the Python standard library."""

import argparse
import socket


def print_addresses(name, family, label):
  try:
    records = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
  except socket.gaierror as exc:
    print(f"{label}: lookup failed: {exc}")
    return
  values = sorted({record[4][0] for record in records})
  print(f"{label}:")
  for value in values:
    print(f"  {value}")


def print_reverse(value):
  try:
    hostname, aliases, addresses = socket.gethostbyaddr(value)
  except (socket.gaierror, socket.herror) as exc:
    print(f"PTR: lookup failed: {exc}")
    return
  print("PTR:")
  print(f"  hostname: {hostname}")
  if aliases:
    print(f"  aliases: {', '.join(aliases)}")
  if addresses:
    print(f"  addresses: {', '.join(addresses)}")


def main():
  parser = argparse.ArgumentParser(description="Resolve A, AAAA, and optional PTR records.")
  parser.add_argument("name", help="domain name or IP address")
  parser.add_argument("--reverse", action="store_true", help="perform reverse lookup for an IP")
  args = parser.parse_args()

  if args.reverse:
    print_reverse(args.name)
    return

  print_addresses(args.name, socket.AF_INET, "A")
  print_addresses(args.name, socket.AF_INET6, "AAAA")
  print()
  print("MX/NS/TXT require dnspython; this script stays standard-library only.")


if __name__ == "__main__":
  main()
