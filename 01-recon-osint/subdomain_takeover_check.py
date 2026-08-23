#!/usr/bin/env python3
"""Check hostnames for dangling DNS records and subdomain takeover fingerprints."""

import argparse
import socket
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"

SERVICE_FINGERPRINTS = [
    ("GitHub Pages", "There isn't a GitHub Pages site here."),
    ("AWS S3", "NoSuchBucket"),
    ("Azure Web Apps", "404 Web Site not found"),
    ("Heroku", "No such app"),
    ("Fastly", "Fastly error: unknown domain"),
    ("CloudFront", "The request could not be satisfied"),
    ("Shopify", "Sorry, this shop is currently unavailable"),
    ("Tumblr", "Whatever you were looking for doesn't currently exist at this address"),
    ("WordPress.com", "Do you want to register"),
    ("Surge.sh", "project not found"),
    ("Bitbucket", "Repository not found"),
    ("Zendesk", "Help Center Closed"),
    ("Teamwork", "Oops - We couldn't find that page"),
    ("Helpjuice", "We could not find what you're looking for"),
    ("Pantheon", "The gods are wise"),
    ("Readme.io", "Project doesnt exist... yet!"),
    ("Feedpress", "The feed has not been found"),
]

CNAME_SERVICE_HINTS = [
    ("github.io", "GitHub Pages"),
    ("herokuapp.com", "Heroku"),
    ("s3.amazonaws.com", "AWS S3"),
    ("amazonaws.com", "AWS S3"),
    ("cloudfront.net", "CloudFront"),
    ("azurewebsites.net", "Azure Web Apps"),
    ("cloudapp.azure.com", "Azure Web Apps"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("fastly.net", "Fastly"),
    ("zendesk.com", "Zendesk"),
    ("shopify.com", "Shopify"),
    ("tumblr.com", "Tumblr"),
    ("bitbucket.io", "Bitbucket"),
]


def resolve(host):
  try:
    return socket.gethostbyname_ex(host)
  except socket.gaierror:
    return None


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(4096).decode("utf-8", "replace")
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(4096).decode("utf-8", "replace")
  except (urllib.error.URLError, OSError):
    return None, ""


def check_host(host, timeout):
  result = resolve(host)
  if result is None:
    print(f"[dangling] {host}: does not resolve at all (check for a stale record)")
    return

  canonical, _, _ = result
  cname_used = canonical.rstrip(".") != host.rstrip(".")

  hint = ""
  if cname_used:
    for suffix, service in CNAME_SERVICE_HINTS:
      if canonical.rstrip(".").endswith(suffix):
        hint = f" (points at {service}: {canonical})"
        break

  status, body = None, ""
  for scheme in ("https", "http"):
    status, body = fetch(f"{scheme}://{host}/", timeout)
    if status is not None:
      break

  fingerprinted = None
  for service, marker in SERVICE_FINGERPRINTS:
    if marker.lower() in body.lower():
      fingerprinted = service
      break

  if fingerprinted:
    print(f"[takeover?] {host}: HTTP {status} body matches {fingerprinted} fingerprint{hint}")
  elif cname_used and status in (None, 404):
    print(f"[review] {host}: CNAME -> {canonical}, HTTP {status}, no known fingerprint{hint}")
  else:
    detail = f"HTTP {status}" if status is not None else "no HTTP response"
    print(f"[ok] {host}: resolves ({'CNAME -> ' + canonical if cname_used else 'A record'}), {detail}")


def main():
  parser = argparse.ArgumentParser(description="Probe hostnames for subdomain takeover indicators on authorized scope.")
  parser.add_argument("targets", nargs="+", help="one or more hostnames, or @file with one hostname per line")
  parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
  args = parser.parse_args()

  hosts = []
  for target in args.targets:
    if target.startswith("@"):
      with open(target[1:], encoding="utf-8") as handle:
        hosts.extend(line.strip() for line in handle if line.strip() and not line.startswith("#"))
    else:
      hosts.append(target)

  for host in hosts:
    try:
      check_host(host, args.timeout)
    except Exception as exc:
      print(f"[error] {host}: {exc}")


if __name__ == "__main__":
  main()
