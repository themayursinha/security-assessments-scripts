#!/usr/bin/env python3
"""Discover upload forms and test extension filtering with harmless payloads."""

import argparse
import re
import time
import urllib.error
import urllib.request
import urllib.parse
import uuid

UA = "security-assessment-scripts/1.0"

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r"""(\w+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))""")


def parse_attrs(text):
  attrs = {}
  for match in ATTR_RE.finditer(text):
    name = match.group(1).lower()
    value = next(group for group in match.groups()[1:] if group is not None)
    attrs[name] = value
  return attrs

DANGEROUS_SUFFIXES = [".php", ".php5", ".jsp", ".asp", ".aspx", ".sh"]
FILTER_BYPASSES = [
  ("double extension", ".php.jpg"),
  ("trailing dot", ".php."),
  ("case change", ".PhP"),
  ("null byte style", ".php%00.jpg"),
  ("semicolon (IIS)", ".asp;.jpg"),
]

HARMLESS_BODY = b"zxupload-test-file: harmless text, safe to store\n"


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(524288).decode("utf-8", "replace")
  except (urllib.error.HTTPError, urllib.error.URLError, OSError):
    return None, ""


def multipart_upload(url, field, filename, timeout):
  boundary = uuid.uuid4().hex
  parts = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
    f"Content-Type: application/octet-stream\r\n\r\n"
  ).encode() + HARMLESS_BODY + f"\r\n--{boundary}--\r\n".encode()
  request = urllib.request.Request(
    url,
    data=parts,
    headers={"User-Agent": UA, "Content-Type": f"multipart/form-data; boundary={boundary}"},
  )
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(131072).decode("utf-8", "replace")
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(131072).decode("utf-8", "replace")
  except (urllib.error.URLError, OSError):
    return None, ""


def find_upload_forms(html):
  forms = []
  for open_tag, block in FORM_RE.findall(html):
    attrs = parse_attrs(open_tag)
    if "multipart" not in attrs.get("enctype", "").lower():
      continue
    file_inputs = re.findall(r"<input\b[^>]*type=[\"']file[\"'][^>]*>", block, re.IGNORECASE) or \
                  re.findall(r"<input\b[^>]*name=[\"'][^\"']+ [^>]*type=[\"']file[\"']", block, re.IGNORECASE)
    field, accept = "file", ""
    for input_text in re.findall(r"<input\b[^>]*>", block, re.IGNORECASE):
      input_attrs = parse_attrs(input_text)
      if input_attrs.get("type", "").lower() == "file":
        field = input_attrs.get("name", "file")
        accept = input_attrs.get("accept", "")
        break
    forms.append({"action": attrs.get("action", ""), "field": field, "accept": accept})
  return forms


def main():
  parser = argparse.ArgumentParser(description="Find upload forms and safely test server-side extension filtering.")
  parser.add_argument("url", help="page containing an upload form")
  parser.add_argument("--test", action="store_true",
                      help="actually upload harmless files with dangerous names (lab targets only)")
  parser.add_argument("--timeout", type=float, default=15.0)
  args = parser.parse_args()

  status, body = fetch(args.url, args.timeout)
  if not body:
    raise SystemExit("could not fetch the page")

  forms = find_upload_forms(body)
  if not forms:
    print("[+] No multipart upload forms found on this page.")
    return

  for form in forms:
    action = urllib.parse.urljoin(args.url, form["action"]) or args.url
    print(f"[!] upload form -> {action}")
    print(f"      file field : {form['field']}")
    print(f"      client-side accept filter: {form['accept'] or 'none'}")

    if not args.test:
      print("      (run with --test to probe server-side filtering with harmless uploads)")
      continue

    print("\n[*] uploading harmless content under risky filenames:")
    for label, suffix in [("baseline", ".txt")] + [(f"bypass: {name}", suffix) for name, suffix in FILTER_BYPASSES]:
      filename = "zxtest-" + uuid.uuid4().hex[:6] + suffix
      up_status, up_body = multipart_upload(action, form["field"], filename, args.timeout)
      accepted = up_status in (200, 201, 204) and "error" not in up_body.lower()
      flag = "[?]" if (accepted and label != "baseline") else "[ ]"
      print(f"{flag} {label:<22} {filename:<28} HTTP {up_status}")
      if accepted and label != "baseline":
        snippet = up_body[:160].replace("\n", " ")
        print(f"      response: {snippet}")
      time.sleep(0.2)

  print("\nVerify whether any accepted 'dangerous' filename is stored/executable at a reachable path.")


if __name__ == "__main__":
  main()
