#!/usr/bin/env python3
"""Connect to TCP ports and capture simple service banners."""

import argparse
import socket


def parse_ports(value):
  ports = set()
  for part in value.split(","):
    part = part.strip()
    if "-" in part:
      start, end = [int(item) for item in part.split("-", 1)]
      ports.update(range(start, end + 1))
    elif part:
      ports.add(int(part))
  return sorted(ports)


def grab_banner(host, port, timeout, probe):
  with socket.create_connection((host, port), timeout=timeout) as sock:
    sock.settimeout(timeout)
    if probe:
      sock.sendall(probe.encode())
    try:
      return sock.recv(1024).decode(errors="replace").strip()
    except socket.timeout:
      return ""


def main():
  parser = argparse.ArgumentParser(description="Grab TCP service banners from ports.")
  parser.add_argument("host", help="target host")
  parser.add_argument("--ports", default="21,22,25,80,110,143,443,587,993,995", help="comma/range port list")
  parser.add_argument("--timeout", type=float, default=3.0, help="connection timeout in seconds")
  parser.add_argument("--probe", default="", help="optional text to send after connecting")
  args = parser.parse_args()

  for port in parse_ports(args.ports):
    try:
      banner = grab_banner(args.host, port, args.timeout, args.probe)
      print(f"{port}/tcp open | {banner}")
    except Exception as exc:
      print(f"{port}/tcp unavailable | {exc}")


if __name__ == "__main__":
  main()
