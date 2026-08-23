#!/usr/bin/env python3
"""Inspect a server certificate and negotiated TLS details."""

import argparse
import datetime as dt
import socket
import ssl


def parse_cert_time(value):
  return dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)


def check_tls(host, port, timeout):
  context = ssl.create_default_context()
  with socket.create_connection((host, port), timeout=timeout) as sock:
    with context.wrap_socket(sock, server_hostname=host) as tls_sock:
      cert = tls_sock.getpeercert()
      return {
        "version": tls_sock.version(),
        "cipher": tls_sock.cipher(),
        "cert": cert,
      }


def names_from_cert(cert):
  names = []
  for key, value in cert.get("subjectAltName", []):
    if key.lower() == "dns":
      names.append(value)
  return names


def main():
  parser = argparse.ArgumentParser(description="Inspect certificate and TLS negotiation details.")
  parser.add_argument("host", help="hostname to connect to")
  parser.add_argument("--port", type=int, default=443, help="TLS port")
  parser.add_argument("--timeout", type=float, default=10.0, help="connection timeout in seconds")
  args = parser.parse_args()

  result = check_tls(args.host, args.port, args.timeout)
  cert = result["cert"]
  not_after = parse_cert_time(cert["notAfter"])
  days_left = (not_after - dt.datetime.now(dt.timezone.utc)).days

  print(f"Host: {args.host}:{args.port}")
  print(f"TLS version: {result['version']}")
  print(f"Cipher: {result['cipher'][0]} ({result['cipher'][1]}, {result['cipher'][2]} bits)")
  print(f"Subject: {cert.get('subject')}")
  print(f"Issuer: {cert.get('issuer')}")
  print(f"Valid from: {cert.get('notBefore')}")
  print(f"Valid until: {cert.get('notAfter')} ({days_left} days left)")
  print("Subject alternative names:")
  for name in names_from_cert(cert):
    print(f"  {name}")


if __name__ == "__main__":
  main()
