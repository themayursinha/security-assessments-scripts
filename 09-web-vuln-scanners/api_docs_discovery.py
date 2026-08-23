#!/usr/bin/env python3
"""Discover exposed API documentation and debug endpoints."""

import argparse
import json
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"

CANDIDATES = [
  ("swagger.json", "OpenAPI/Swagger spec"),
  ("/swagger.json", "OpenAPI/Swagger spec"),
  ("/v1/swagger.json", "OpenAPI/Swagger spec"),
  ("/v2/swagger.json", "OpenAPI/Swagger spec"),
  ("/v3/swagger.json", "OpenAPI/Swagger spec"),
  ("/openapi.json", "OpenAPI spec"),
  ("/v1/openapi.json", "OpenAPI spec"),
  ("/v3/openapi.json", "OpenAPI spec"),
  ("/api-docs", "Swagger UI / docs"),
  ("/api-docs/swagger.json", "OpenAPI/Swagger spec"),
  ("/swagger", "Swagger UI"),
  ("/swagger/ui", "Swagger UI"),
  ("/swagger-ui/", "Swagger UI"),
  ("/docs", "Docs page"),
  ("/redoc", "ReDoc docs"),
  ("/api", "API root"),
  ("/api/v1", "API versioned root"),
  ("/actuator", "Spring Boot actuator"),
  ("/actuator/env", "Spring env (may leak secrets)"),
  ("/actuator/heapdump", "Spring heapdump"),
  ("/metrics", "Metrics endpoint"),
  ("/debug/vars", "Go expvar debug data"),
  ("/server-status", "Apache status"),
  ("/server-info", "Apache info"),
  ("/status", "Status endpoint"),
  ("/info", "Info endpoint"),
]


def fetch(url, timeout):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    body = response.read(262144).decode("utf-8", "replace")
    return getattr(response, "status", response.code), response.headers.get("Content-Type", ""), body
  except urllib.error.HTTPError as exc:
    return exc.code, exc.headers.get("Content-Type", ""), exc.read(4096).decode("utf-8", "replace")
  except (urllib.error.URLError, OSError):
    return None, "", ""


def describe(path, label, status, content_type, body, base):
  if status not in (200,):
    return False
  lowered = body[:2048].lower()
  if path.endswith(".json") or "json" in content_type:
    try:
      parsed = json.loads(body)
      if isinstance(parsed, dict):
        if "paths" in parsed:
          count = len(parsed["paths"])
          title = parsed.get("info", {}).get("title", "?")
          print(f"[!] {label}: {base}{path} - OpenAPI doc '{title}' exposing {count} path(s)")
          for endpoint in list(parsed["paths"])[:10]:
            print(f"      {endpoint}")
          if count > 10:
            print(f"      ...and {count - 10} more")
          return True
        if "actuator" in path or "env" in path:
          print(f"[!] {label}: {base}{path} - keys: {', '.join(list(parsed)[:12])}")
          return True
        if "_links" in parsed:
          print(f"[!] {label}: {base}{path} - HAL index with links: {', '.join(list(parsed['_links'])[:8])}")
          return True
    except json.JSONDecodeError:
      pass
  markers = {
    "Swagger UI": "swagger-ui",
    "Docs page": "<title>",
    "ReDoc": "redoc",
    "Spring Boot actuator": '"_links"',
    "Go expvar debug data": '"cmdline"',
    "Apache status": "apache server status",
    "API root": None,
  }
  expected = markers.get(label)
  if expected and expected in lowered:
    print(f"[!] {label}: {base}{path}")
    return True
  if expected is None and len(body) < 4096:
    print(f"[?] {label}: {base}{path} returned HTTP 200 - review manually")
    return True
  return False


def main():
  parser = argparse.ArgumentParser(description="Enumerate common API documentation and debug endpoints on an authorized host.")
  parser.add_argument("base_url", help="e.g. https://lab.example")
  parser.add_argument("--timeout", type=float, default=8.0)
  args = parser.parse_args()

  base = args.base_url.rstrip("/")
  found = 0
  for path, label in CANDIDATES:
    if not path.startswith("/"):
      path = "/" + path
    url = base + path
    status, content_type, body = fetch(url, args.timeout)
    if status is None:
      continue
    if describe(path, label, status, content_type, body, base):
      found += 1

  print(f"\n{found} exposed documentation/debug endpoint(s) found.")
  if found == 0:
    print("[+] Nothing exposed among the candidate paths.")


if __name__ == "__main__":
  main()
