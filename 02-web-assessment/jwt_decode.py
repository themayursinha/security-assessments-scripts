#!/usr/bin/env python3
"""Decode JWT header and payload locally without verifying the signature."""

import argparse
import base64
import binascii
import json


def b64url_decode(value):
  value += "=" * (-len(value) % 4)
  return base64.urlsafe_b64decode(value.encode())


def decode_jwt(token):
  parts = token.split(".")
  if len(parts) != 3:
    raise ValueError("JWT must contain header, payload, and signature sections")
  header = json.loads(b64url_decode(parts[0]))
  payload = json.loads(b64url_decode(parts[1]))
  return header, payload, parts[2]


def main():
  parser = argparse.ArgumentParser(description="Decode a JWT without verifying its signature.")
  parser.add_argument("token", help="JWT value")
  args = parser.parse_args()

  header, payload, signature = decode_jwt(args.token)
  print("Header:")
  print(json.dumps(header, indent=2, sort_keys=True))
  print("Payload:")
  print(json.dumps(payload, indent=2, sort_keys=True))
  try:
    print(f"Signature bytes: {len(b64url_decode(signature))}")
  except binascii.Error as exc:
    print(f"Signature bytes: unavailable ({exc})")
  print("Verification: not performed")


if __name__ == "__main__":
  main()
