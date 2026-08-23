#!/usr/bin/env python3
"""Minimal raw DNS client: build queries, parse answers, and attempt AXFR."""

import argparse
import socket
import struct

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 252: "AXFR"}
CLASS_IN = 1


def encode_name(name):
  parts = name.rstrip(".").split(".")
  return b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"


def decode_name(data, offset, seen=None):
  labels, jumped = [], False
  end = offset if seen is None else seen
  guard = 0
  while True:
    length = data[offset]
    if length & 0xC0 == 0xC0:
      pointer = ((length & 0x3F) << 8) | data[offset + 1]
      if not jumped:
        end = offset + 2
      offset = pointer
      jumped = True
      guard += 1
      if guard > 32:
        raise ValueError("decompression loop")
      continue
    offset += 1
    if length == 0:
      break
    labels.append(data[offset:offset + length].decode("ascii", "replace"))
    offset += length
  return ".".join(labels), (end if jumped else offset)


def build_query(name, qtype, query_id=0x1234):
  header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
  question = encode_name(name) + struct.pack(">HH", qtype, CLASS_IN)
  return header + question


def parse_rr(data, offset):
  name, offset = decode_name(data, offset)
  rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
  offset += 10
  rdata_start = offset
  value = ""
  if rtype in (2, 5, 12):
    value, _ = decode_name(data, offset)
  elif rtype == 1:
    value = socket.inet_ntoa(data[offset:offset + 4])
  elif rtype == 28:
    value = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
  elif rtype == 15:
    pref = struct.unpack(">H", data[offset:offset + 2])[0]
    exchange, _ = decode_name(data, offset + 2)
    value = f"{pref} {exchange}"
  elif rtype == 16:
    chunks, pos = [], offset
    while pos < offset + rdlength:
      chunk_len = data[pos]
      chunks.append(data[pos + 1:pos + 1 + chunk_len].decode("utf-8", "replace"))
      pos += 1 + chunk_len
    value = "".join(chunks)
  elif rtype == 6:
    mname, off2 = decode_name(data, offset)
    rname, off3 = decode_name(data, off2)
    serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[off3:off3 + 20])
    value = f"{mname} {rname} serial={serial}"
  offset = rdata_start + rdlength
  return (name, TYPES.get(rtype, str(rtype)), ttl, value), offset


def udp_query(name, qtype, server, timeout):
  packet = build_query(name, qtype)
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(timeout)
    sock.sendto(packet, (server, 53))
    data, _ = sock.recvfrom(4096)
  return data


def tcp_query_stream(name, qtype, server, timeout, max_bytes=262144):
  packet = struct.pack(">H", len(build_query(name, qtype))) + build_query(name, qtype)
  records, buffer = [], b""
  with socket.create_connection((server, 53), timeout=timeout) as sock:
    sock.settimeout(timeout)
    sock.sendall(packet)
    while len(buffer) - 2 <= max_bytes:
      header = sock.recv(2)
      if len(header) < 2:
        break
      (msg_len,) = struct.unpack(">H", header)
      message = b""
      while len(message) < msg_len:
        chunk = sock.recv(msg_len - len(message))
        if not chunk:
          return records
        message += chunk
      buffer += message
      parsed = parse_message(message)
      if parsed is None:
        break
      _, _, answers, authorities = parsed
      records.extend(answers + authorities)
      if len(records) > 1 and records[-1][1] == "SOA":
        break
  return records


def parse_message(data):
  if len(data) < 12:
    return None
  query_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
  rcode = flags & 0xF
  offset = 12
  for _ in range(qdcount):
    _, offset = decode_name(data, offset)
    offset += 4
  records = []
  for count in (ancount, nscount):
    for _ in range(count):
      record, offset = parse_rr(data, offset)
      records.append(record)
  return query_id, rcode, records, []


def find_nameservers(domain, timeout):
  resolvers = ["8.8.8.8", "1.1.1.1"]
  for server in resolvers:
    try:
      data = udp_query(domain, 2, server, timeout)
      parsed = parse_message(data)
      if parsed and parsed[1] == 0:
        return [value for name, rtype, ttl, value in parsed[2] if rtype == "NS"]
    except OSError:
      continue
  return []


def attempt_axfr(nameserver, domain, timeout):
  nameserver_ip = socket.gethostbyname(nameserver)
  try:
    records = tcp_query_stream(domain, 252, nameserver_ip, timeout)
  except (OSError, ValueError) as exc:
    print(f"[-] {nameserver} ({nameserver_ip}): transfer failed ({exc})")
    return False
  if not records:
    print(f"[-] {nameserver}: empty response (likely REFUSED)")
    return False
  soa_count = sum(1 for _, rtype, _, _ in records if rtype == "SOA")
  if soa_count < 2 and len(records) <= 1:
    print(f"[-] {nameserver}: only {len(records)} record(s); zone transfer refused")
    return False
  print(f"[+] {nameserver}: zone transfer returned {len(records)} records!")
  for name, rtype, ttl, value in records:
    print(f"    {name} {ttl:>8} IN {rtype:<5} {value}")
  return True


def main():
  parser = argparse.ArgumentParser(description="Attempt DNS zone transfers (AXFR) against a domain's nameservers.")
  parser.add_argument("domain", help="authorized domain to test")
  parser.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds")
  args = parser.parse_args()

  nameservers = find_nameservers(args.domain, args.timeout)
  if not nameservers:
    print(f"No NS records resolved for {args.domain}")
    return
  print(f"Nameservers for {args.domain}: {', '.join(nameservers)}\n")

  succeeded = False
  for nameserver in sorted(set(nameservers)):
    if attempt_axfr(nameserver, args.domain, args.timeout):
      succeeded = True

  if not succeeded:
    print("\nNo zone transfers succeeded (the expected outcome on hardened servers).")


if __name__ == "__main__":
  main()
