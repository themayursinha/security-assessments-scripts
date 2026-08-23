#!/usr/bin/env python3
"""Test WebSocket endpoints for cross-origin acceptance (CSWSH) and TLS use."""

import argparse
import base64
import os
import socket
import ssl
import urllib.parse


def handshake(host, port, path, origin, use_tls, timeout=6):
  key = base64.b64encode(os.urandom(16)).decode()
  headers = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}:{port}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
  )
  if origin:
    headers += f"Origin: {origin}\r\n"
  headers += "\r\n"

  with socket.create_connection((host, port), timeout=timeout) as sock:
    if use_tls:
      context = ssl.create_default_context()
      context.check_hostname = False
      context.verify_mode = ssl.CERT_NONE
      sock = context.wrap_socket(sock, server_hostname=host)
    sock.sendall(headers.encode())
    response = b""
    while b"\r\n\r\n" not in response and len(response) < 8192:
      chunk = sock.recv(1024)
      if not chunk:
        break
      response += chunk
  first_line = response.split(b"\r\n", 1)[0].decode("utf-8", "replace")
  header_blob = response.split(b"\r\n\r\n", 1)[0].lower()
  accepted = b"sec-websocket-accept" in header_blob
  return first_line, accepted


def main():
  parser = argparse.ArgumentParser(description="Check whether a WebSocket endpoint accepts cross-browser origins (CSWSH risk).")
  parser.add_argument("target", help="ws(s)://host[:port]/path")
  parser.add_argument("--evil-origin", default="https://evil.example", help="Origin to test with")
  parser.add_argument("--timeout", type=float, default=6.0)
  args = parser.parse_args()

  split = urllib.parse.urlsplit(args.target)
  if split.scheme not in ("ws", "wss"):
    raise SystemExit("target must start with ws:// or wss://")
  use_tls = split.scheme == "wss"
  host = split.hostname
  port = split.port or (443 if use_tls else 80)
  path = split.path or "/"

  print(f"[*] target: {args.target}")

  status, accepted = handshake(host, port, path, None, use_tls, args.timeout)
  print(f"[*] no Origin header   : {status} ({'upgraded' if accepted else 'rejected'})")

  status_evil, accepted_evil = handshake(host, port, path, args.evil_origin, use_tls, args.timeout)
  print(f"[*] Origin {args.evil_origin:<28}: {status_evil} ({'upgraded' if accepted_evil else 'rejected'})")

  print()
  if accepted_evil:
    print("[!] Endpoint upgrades cross-origin connections without validating Origin.")
    print("    A malicious page can open this socket from a victim's browser and read")
    print("    messages if the session cookie is sent - confirm with a real browser test.")
  elif accepted:
    print("[+] Cross-origin upgrade rejected; only same-origin/no-Origin clients connect.")
  else:
    print("[?] Neither attempt upgraded - endpoint may require auth tokens or subprotocol headers.")


if __name__ == "__main__":
  main()
