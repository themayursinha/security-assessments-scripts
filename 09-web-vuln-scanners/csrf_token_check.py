#!/usr/bin/env python3
"""Check forms for CSRF tokens and flag cross-origin-capable actions."""

import argparse
import http.cookies
import re
import urllib.error
import urllib.request
import urllib.parse

UA = "security-assessment-scripts/1.0"

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r"""(\w+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))""")
INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)

TOKEN_NAME_HINTS = ("csrf", "token", "nonce", "authenticity", "_requestverifier", "__requestverification")


def parse_attrs(text):
  attrs = {}
  for match in ATTR_RE.finditer(text):
    name = match.group(1).lower()
    value = next(group for group in match.groups()[1:] if group is not None)
    attrs[name] = value
  return attrs


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(524288).decode("utf-8", "replace"), response.headers
  except (urllib.error.HTTPError, urllib.error.URLError, OSError):
    return None, "", None


def parse_form(open_tag_attrs, block):
  attrs = parse_attrs(open_tag_attrs)
  inputs = [parse_attrs(tag) for tag in INPUT_RE.findall(block)]
  return attrs, inputs


def main():
  parser = argparse.ArgumentParser(description="Audit forms on a page for CSRF protection gaps.")
  parser.add_argument("url", help="page containing the forms to audit")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  status, body, headers = fetch(args.url, args.timeout)
  if not body:
    raise SystemExit(f"could not fetch {args.url}")

  page_origin = urllib.parse.urlsplit(args.url).netloc

  set_cookies = headers.get_all("Set-Cookie") if headers else []
  for header in set_cookies or []:
    try:
      parsed_cookie = http.cookies.SimpleCookie()
      parsed_cookie.load(header.split(";")[0])
      for name in parsed_cookie:
        samesite = next((p.split("=")[-1] for p in header.lower().split(";") if p.strip().startswith("samesite")), None)
        if name.lower() in ("session", "sessid", "jsessionid", "phpsessionid", "aspxauth") and not samesite:
          print(f"[!] session cookie '{name}' has no SameSite attribute")
    except http.cookies.CookieError:
      pass

  forms = FORM_RE.findall(body)
  if not forms:
    print("[+] No forms found on the page.")
    return

  print(f"[*] {len(forms)} form(s) found\n")
  vulnerable = False

  for index, (open_tag_attrs, block) in enumerate(forms, start=1):
    attrs, inputs = parse_form(open_tag_attrs, block)
    action = attrs.get("action", "")
    method = attrs.get("method", "GET").upper()

    action_origin = page_origin
    if action.startswith(("http://", "https://")):
      action_origin = urllib.parse.urlsplit(action).netloc

    has_token = any(
      any(hint in str(input_attrs.get("name", "")).lower() for hint in TOKEN_NAME_HINTS)
      for input_attrs in inputs
      if str(input_attrs.get("type", "text")).lower() == "hidden"
    )
    hidden_names = [i.get("name") for i in inputs if str(i.get("type", "text")).lower() == "hidden"]

    issues = []
    if method == "POST" and not has_token:
      issues.append("no CSRF token field detected")
    if action_origin != page_origin:
      issues.append(f"posts cross-origin ({action_origin})")

    flag = "[!]" if issues else "[+]"
    print(f"{flag} form #{index}: {method} -> {action or '(self)'}")
    print(f"      hidden fields: {hidden_names or 'none'}")
    for issue in issues:
      print(f"      finding: {issue}")
      vulnerable = True

  print()
  if vulnerable:
    print("[!] Review flagged forms - SameSite cookies or per-form tokens may still protect them.")
  else:
    print("[+] All state-changing forms appear to carry token-style hidden fields.")


if __name__ == "__main__":
  main()
