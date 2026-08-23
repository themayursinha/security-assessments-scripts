#!/usr/bin/env python3
"""Generate and optionally resolve typosquat permutations of a domain name."""

import argparse
import socket
import urllib.parse

KEY_NEIGHBORS = {
  "q": "wa", "w": "qe", "e": "wr", "r": "et", "t": "ry", "y": "tu", "u": "yi", "i": "uo", "o": "ip", "p": "o",
  "a": "s", "s": "ad", "d": "sf", "f": "dg", "g": "fh", "h": "gj", "j": "hk", "k": "jl", "l": "k",
  "z": "x", "x": "zc", "c": "xv", "v": "cb", "b": "vn", "n": "bm", "m": "n",
}

HOMOGLYPHS = {
  "l": "1", "i": "1", "o": "0", "e": "3", "a": "4", "s": "5", "g": "9", "b": "8", "t": "7",
}

COMMON_TLDS = ["com", "net", "org", "co", "io"]


def generate_permutations(domain, limit):
  label, _, tld = domain.rpartition(".")
  candidates = set()

  for index in range(len(label)):
    candidates.add(label[:index] + label[index + 1:])
  for index in range(len(label) - 1):
    if label[index] != label[index + 1]:
      candidates.add(label[:index] + label[index + 1] + label[index] + label[index + 2:])
  for index, char in enumerate(label):
    for neighbor in KEY_NEIGHBORS.get(char, ""):
      candidates.add(label[:index] + neighbor + label[index + 1:])
    if char in HOMOGLYPHS:
      candidates.add(label[:index] + HOMOGLYPHS[char] + label[index + 1:])
    if index > 0:
      candidates.add(label[:index] + "-" + label[index:])
  for extra_tld in COMMON_TLDS:
    if extra_tld != tld:
      candidates.add(f"{label}.{extra_tld}")

  candidates.discard(label)
  return sorted(f"{candidate}.{tld}" for candidate in candidates)[:limit]


def resolve_domain(domain):
  try:
    socket.gethostbyname_ex(domain)
    return True
  except (socket.gaierror, OSError):
    return False


def main():
  parser = argparse.ArgumentParser(description="Enumerate lookalike domains for brand monitoring or defensive registration.")
  parser.add_argument("domain", help="reference domain, e.g. mycompany.com")
  parser.add_argument("--limit", type=int, default=100, help="maximum permutations to consider")
  parser.add_argument("--resolve", action="store_true", help="resolve each candidate to see which are registered")
  args = parser.parse_args()

  parsed = urllib.parse.urlsplit(args.domain if "//" in args.domain else "//" + args.domain)
  domain = parsed.netloc or parsed.path

  permutations = generate_permutations(domain.lower(), args.limit)
  print(f"{len(permutations)} permutation(s) of {domain}\n")

  registered = []
  for candidate in permutations:
    if not args.resolve:
      print(candidate)
      continue
    if resolve_domain(candidate):
      print(f"[registered ] {candidate}")
      registered.append(candidate)
    else:
      print(f"[unregistered] {candidate}")

  if args.resolve:
    print(f"\n{len(registered)} of {len(permutations)} resolve; review those for impersonation risk.")


if __name__ == "__main__":
  main()
