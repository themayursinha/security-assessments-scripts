#!/usr/bin/env python3
"""Audit OAuth authorization requests for common misconfigurations."""

import argparse
import urllib.error
import urllib.parse
import urllib.request


def main():
  parser = argparse.ArgumentParser(description="Analyze an OAuth authorization URL for missing/weak parameters.")
  parser.add_argument("authorize_url", help="full authorization endpoint URL with query string")
  parser.add_argument("--fetch", action="store_true", help="also request the authorize URL and inspect the response")
  args = parser.parse_args()

  split = urllib.parse.urlsplit(args.authorize_url)
  params = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(split.query).items()}
  redirect_uri = params.get("redirect_uri", "")

  print(f"[*] endpoint : {split.scheme}://{split.netloc}{split.path}")
  for key in ("client_id", "response_type", "scope", "redirect_uri", "state", "nonce", "code_challenge"):
    value = params.get(key)
    marker = "present" if value else "MISSING"
    display = (value[:60] + "...") if value and len(value) > 60 else (value or "-")
    print(f"    {key:<15} {marker:<8} {display}")

  findings = []

  if not params.get("state"):
    findings.append("no state parameter -> login CSRF / session fixation risk")
  if not params.get("nonce") and any(t in params.get("scope", "") or t == "" for t in ("openid",)):
    findings.append("openid scope without nonce -> replay risk for ID tokens")

  response_type = params.get("response_type", "")
  if response_type == "token":
    findings.append("implicit flow (response_type=token) is deprecated; prefer code + PKCE")
  if response_type == "code" and not params.get("code_challenge"):
    findings.append("authorization code flow without PKCE (code_challenge)")

  if not redirect_uri:
    findings.append("no redirect_uri sent - server default may be overly permissive")
  else:
    if redirect_uri.startswith("http://"):
      findings.append("redirect_uri uses plain http")
    parsed_redirect = urllib.parse.urlsplit(redirect_uri)
    if parsed_redirect.path in ("", "/"):
      findings.append(f"redirect_uri points at domain root ({redirect_uri}); wildcard matching may allow open redirect")
    if "*" in redirect_uri:
      findings.append("redirect_uri contains a literal wildcard")
    if parsed_redirect.netloc != split.netloc and "auth" not in parsed_redirect.netloc:
      findings.append(f"redirect_uri host differs from authorization server ({parsed_redirect.netloc})")

  print()
  if findings:
    print("[!] Findings:")
    for finding in findings:
      print(f"    - {finding}")
  else:
    print("[+] Authorization request parameters look reasonable.")

  if args.fetch:
    request = urllib.request.Request(args.authorize_url, headers={"User-Agent": "security-assessment-scripts/1.0"})
    try:
      opener = urllib.request.build_opener(_NoRedirect())
      response = opener.open(request, timeout=10)
      status, location, body = getattr(response, "status", response.code), "", ""
      location = response.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
      status, location, body = exc.code, exc.headers.get("Location", ""), exc.read(4096).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
      status, location, body = None, "", str(exc)
    print(f"\n[*] live check: HTTP {status}")
    if location:
      print(f"    Location: {location[:160]}")
      if redirect_uri and redirect_uri not in location and location.startswith("http"):
        findings.append(f"server redirects to unexpected Location: {location[:100]}")
    snippet = body[:300].replace("\n", " ")
    if body:
      print(f"    body: ...{snippet}...")
    if len(findings) > 0 and status is not None:
      extra = [f for f in findings if f.startswith("server redirects")]
      for item in extra:
        print(f"[!] {item}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    return None


if __name__ == "__main__":
  main()
