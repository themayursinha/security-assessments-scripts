#!/usr/bin/env python3
"""Summarize packet counts and top endpoints from a pcap file using Scapy."""

import argparse
import collections


def main():
  parser = argparse.ArgumentParser(description="Summarize a pcap file with Scapy.")
  parser.add_argument("pcap", help="pcap file path")
  parser.add_argument("--top", type=int, default=10, help="number of top endpoints to print")
  args = parser.parse_args()

  try:
    from scapy.all import IP, IPv6, TCP, UDP, rdpcap
  except ImportError as exc:
    raise SystemExit("pcap_summary.py requires scapy: python3 -m pip install scapy") from exc

  packets = rdpcap(args.pcap)
  protocols = collections.Counter()
  endpoints = collections.Counter()
  conversations = collections.Counter()

  for packet in packets:
    protocols[packet.__class__.__name__] += 1
    layer = IP if IP in packet else IPv6 if IPv6 in packet else None
    if layer:
      src = packet[layer].src
      dst = packet[layer].dst
      endpoints[src] += 1
      endpoints[dst] += 1
      conversations[(src, dst)] += 1
    if TCP in packet:
      protocols["TCP"] += 1
    if UDP in packet:
      protocols["UDP"] += 1

  print(f"Packets: {len(packets)}")
  print("Protocols:")
  for name, count in protocols.most_common():
    print(f"  {name}: {count}")
  print("Top endpoints:")
  for endpoint, count in endpoints.most_common(args.top):
    print(f"  {endpoint}: {count}")
  print("Top conversations:")
  for (src, dst), count in conversations.most_common(args.top):
    print(f"  {src} -> {dst}: {count}")


if __name__ == "__main__":
  main()
