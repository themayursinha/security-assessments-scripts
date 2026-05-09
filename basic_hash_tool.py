#!/usr/bin/env python3
"""Calculate common hashes for strings or files."""

import argparse
import hashlib


ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]


def hash_bytes(data):
  return {name: hashlib.new(name, data).hexdigest() for name in ALGORITHMS}


def hash_file(path):
  hashes = {name: hashlib.new(name) for name in ALGORITHMS}
  with open(path, "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
      for digest in hashes.values():
        digest.update(chunk)
  return {name: digest.hexdigest() for name, digest in hashes.items()}


def main():
  parser = argparse.ArgumentParser(description="Calculate MD5, SHA1, SHA256, and SHA512.")
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument("--file", help="file to hash")
  group.add_argument("--string", help="string to hash")
  args = parser.parse_args()

  results = hash_file(args.file) if args.file else hash_bytes(args.string.encode())
  for name, value in results.items():
    print(f"{name}: {value}")


if __name__ == "__main__":
  main()
