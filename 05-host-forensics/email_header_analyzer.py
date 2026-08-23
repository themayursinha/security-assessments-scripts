#!/usr/bin/env python3
"""Triage email headers for phishing indicators from an .eml or header dump."""

import argparse
import email
import email.policy
import re


RECEIVED_RE = re.compile(r"from\s+(?P<from>.+?)\s+by\s+(?P<by>\S+[^\s;]*)", re.IGNORECASE)


def load_message(path):
  with open(path, "rb") as handle:
    return email.message_from_binary_file(handle, policy=email.policy.default)


def auth_results(message):
  results = []
  for value in message.get_all("Authentication-Results") or []:
    lowered = value.lower()
    verdict = {}
    for mechanism in ("spf", "dkim", "dmarc"):
      match = re.search(rf"{mechanism}\s*=\s*(\w+)", lowered)
      verdict[mechanism] = match.group(1) if match else "?"
    results.append(verdict)
  return results


def received_chain(message):
  chain = []
  for value in reversed(message.get_all("Received") or []):
    match = RECEIVED_RE.search(value.replace("\n", " "))
    if match:
      chain.append({"from": match.group("from").strip(), "by": match.group("by").strip()})
  return chain


def attachment_summary(message):
  attachments = []
  for part in message.iter_attachments():
    filename = part.get_filename() or "(unnamed)"
    attachments.append(filename)
  return attachments


def domain_of(address):
  if not address:
    return ""
  match = re.search(r"@([\w.-]+)", address)
  return match.group(1).lower() if match else ""


def analyze(message):
  findings = []

  from_header = message.get("From", "")
  return_path = message.get("Return-Path", "")
  reply_to = message.get("Reply-To", "")
  from_domain = domain_of(from_header)
  reply_domain = domain_of(reply_to)
  return_domain = domain_of(return_path)

  if reply_to and reply_domain and reply_domain != from_domain:
    findings.append(f"Reply-To domain differs From domain: {reply_domain} vs {from_domain}")
  if return_path and return_domain and return_domain != from_domain:
    findings.append(f"Return-Path (envelope) differs From domain: {return_domain} vs {from_domain}")
  if not return_path:
    findings.append("no Return-Path header present")

  for index, verdict in enumerate(auth_results(message)):
    for mechanism, result in verdict.items():
      if result in ("fail", "softfail", "none"):
        findings.append(f"Authentication-Results #{index + 1}: {mechanism}={result}")

  chain = received_chain(message)
  external_hops = [hop["by"] for hop in chain]

  attachments = attachment_summary(message)
  risky_exts = (".exe", ".scr", ".js", ".vbs", ".hta", ".zip", ".iso", ".lnk", ".docm")
  for filename in attachments:
    if filename.lower().endswith(risky_exts):
      findings.append(f"suspicious attachment: {filename}")

  display_name = re.match(r"\s*\"?(.*?)\"?\s*<", from_header or "")
  spoofed_brand = False
  if display_name:
    shown_name = display_name.group(1).lower()
    brands = ["paypal", "microsoft", "office365", "apple", "amazon", "google", "netflix", "bank"]
    for brand in brands:
      if brand in shown_name and brand not in (from_domain or ""):
        spoofed_brand = True
  if spoofed_brand:
    findings.append(f"display name references a known brand but sender domain is {from_domain}")

  return {
    "subject": message.get("Subject", "(none)"),
    "date": message.get("Date", "(none)"),
    "from": from_header,
    "to": message.get("To", ""),
    "reply_to": reply_to,
    "chain": chain,
    "attachments": attachments,
    "findings": findings,
  }


def main():
  parser = argparse.ArgumentParser(description="Summarize an .eml file and flag common phishing header patterns.")
  parser.add_argument("eml_file", help="path to the .eml file")
  parser.add_argument("--full-received", action="store_true", help="print full raw Received headers too")
  args = parser.parse_args()

  try:
    message = load_message(args.eml_file)
  except OSError as exc:
    raise SystemExit(f"Could not read {args.eml_file}: {exc}")

  report = analyze(message)

  print(f"Subject   : {report['subject']}")
  print(f"Date      : {report['date']}")
  print(f"From      : {report['from']}")
  print(f"To        : {report['to']}")
  if report["reply_to"]:
    print(f"Reply-To  : {report['reply_to']}")

  print(f"\nReceived chain ({len(report['chain'])} parsed hop(s)):")
  for hop in report["chain"]:
    print(f"  from {hop['from']}")

  if report["attachments"]:
    print(f"\nAttachments ({len(report['attachments'])}):")
    for filename in report["attachments"]:
      print(f"  - {filename}")
  else:
    print("\nNo attachments.")

  print()
  if report["findings"]:
    print("[!] Indicators:")
    for finding in report["findings"]:
      print(f"    - {finding}")
  else:
    print("[+] No obvious phishing indicators in the headers reviewed.")

  if args.full_received:
    print("\nRaw Received headers:")
    for value in message.get_all("Received") or []:
      print("  ----")
      print("  " + value.replace("\n", "\n  ").strip())


if __name__ == "__main__":
  main()
