#!/usr/bin/env python3
"""Fetch robots.txt and sitemap.xml and print interesting paths."""

import argparse
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def fetch_text(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": "security-assessment-scripts/1.0"})
  with urllib.request.urlopen(request, timeout=timeout) as response:
    return response.read().decode(errors="replace")


def base_url(value):
  parsed = urllib.parse.urlparse(value if "://" in value else f"https://{value}")
  return f"{parsed.scheme}://{parsed.netloc or parsed.path}".rstrip("/")


def parse_robots(text):
  paths = []
  sitemaps = []
  for line in text.splitlines():
    line = line.split("#", 1)[0].strip()
    if not line or ":" not in line:
      continue
    key, value = [part.strip() for part in line.split(":", 1)]
    if key.lower() in {"allow", "disallow"} and value:
      paths.append((key, value))
    elif key.lower() == "sitemap" and value:
      sitemaps.append(value)
  return paths, sitemaps


def parse_sitemap(text):
  try:
    root = ET.fromstring(text)
    return [element.text.strip() for element in root.iter() if element.tag.endswith("loc") and element.text]
  except ET.ParseError:
    return re.findall(r"<loc>(.*?)</loc>", text, flags=re.I | re.S)


def main():
  parser = argparse.ArgumentParser(description="Fetch robots.txt and sitemap.xml for a site.")
  parser.add_argument("site", help="domain or base URL")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  args = parser.parse_args()

  root = base_url(args.site)
  robots_url = f"{root}/robots.txt"
  sitemap_url = f"{root}/sitemap.xml"

  print(f"robots.txt: {robots_url}")
  try:
    robots = fetch_text(robots_url, args.timeout)
    paths, sitemaps = parse_robots(robots)
    for key, path in paths:
      print(f"  {key}: {path}")
    if sitemaps:
      print("  Sitemap entries:")
      for entry in sitemaps:
        print(f"    {entry}")
  except Exception as exc:
    print(f"  fetch failed: {exc}")

  print(f"sitemap.xml: {sitemap_url}")
  try:
    sitemap = fetch_text(sitemap_url, args.timeout)
    for loc in parse_sitemap(sitemap):
      print(f"  {loc}")
  except Exception as exc:
    print(f"  fetch failed: {exc}")


if __name__ == "__main__":
  main()
