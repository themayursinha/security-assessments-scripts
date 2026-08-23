#!/usr/bin/env python3
"""Calculate Shannon entropy for files."""

import argparse
import collections
import math


def entropy(path):
  with open(path, "rb") as handle:
    data = handle.read()
  if not data:
    return 0.0, 0
  counts = collections.Counter(data)
  total = len(data)
  value = -sum((count / total) * math.log2(count / total) for count in counts.values())
  return value, total


def main():
  parser = argparse.ArgumentParser(description="Calculate file entropy.")
  parser.add_argument("files", nargs="+", help="files to inspect")
  args = parser.parse_args()

  for path in args.files:
    value, size = entropy(path)
    print(f"{path}: entropy={value:.4f} size={size}")


if __name__ == "__main__":
  main()
