#!/usr/bin/env python3
"""Check URL status codes, redirects, titles, and server headers from a file."""

import argparse
import html.parser
import urllib.error
import urllib.request


class TitleParser(html.parser.HTMLParser):
  def __init__(self):
    super().__init__()
    self.in_title = False
    self.title = []

  def handle_starttag(self, tag, attrs):
    if tag.lower() == "title":
      self.in_title = True

  def handle_endtag(self, tag):
    if tag.lower() == "title":
      self.in_title = False

  def handle_data(self, data):
    if self.in_title:
      self.title.append(data.strip())

  def value(self):
    return " ".join(part for part in self.title if part)


def check_url(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": "security-assessment-scripts/1.0"})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    body = response.read(200_000)
  except urllib.error.HTTPError as exc:
    response = exc
    body = exc.read(200_000)
  parser = TitleParser()
  content_type = response.headers.get("Content-Type", "")
  if "html" in content_type.lower():
    parser.feed(body.decode(errors="replace"))
  return {
    "url": url,
    "status": getattr(response, "status", response.code),
    "final_url": response.geturl(),
    "server": response.headers.get("Server", ""),
    "title": parser.value(),
  }


def main():
  parser = argparse.ArgumentParser(description="Check status and basic metadata for URLs in a file.")
  parser.add_argument("file", help="file containing one URL per line")
  parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
  args = parser.parse_args()

  with open(args.file, encoding="utf-8") as handle:
    urls = [line.strip() for line in handle if line.strip() and not line.startswith("#")]

  for url in urls:
    try:
      result = check_url(url, args.timeout)
      print(f"{result['status']} {result['url']} -> {result['final_url']} | {result['server']} | {result['title']}")
    except Exception as exc:
      print(f"ERR {url} | {exc}")


if __name__ == "__main__":
  main()
