#!/usr/bin/env python3
"""Discover GraphQL endpoints and test introspection and GET-query exposure."""

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request

UA = "security-assessment-scripts/1.0"

CANDIDATE_PATHS = [
  "/graphql", "/graphiql", "/api/graphql", "/api/graphiql", "/v1/graphql",
  "/v2/graphql", "/graphql/console", "/graphql/explorer", "/explorer",
  "/altair", "/playground", "/gql", "/query/graphql",
]

INTROSPECTION_QUERY = {"query": "{__schema{queryType{name types{name}}}}"}

SUGGESTION_QUERY = {"query": "{zxNoSuchField123}"}

TYPENAME_QUERY = {"query": "{__typename}"}


def post_json(url, obj, timeout=10):
  request = urllib.request.Request(
    url, data=json.dumps(obj).encode(),
    headers={"User-Agent": UA, "Content-Type": "application/json"})
  return send(request, timeout)


def get(url, timeout=10):
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  return send(request, timeout)


def send(request, timeout):
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    body = response.read(131072).decode("utf-8", "replace")
    content_type = response.headers.get("Content-Type", "")
    return getattr(response, "status", response.code), body, content_type
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(131072).decode("utf-8", "replace"), exc.headers.get("Content-Type", "")
  except (urllib.error.URLError, OSError):
    return None, "", ""


def looks_like_graphql(body):
  lowered = body.lower()
  markers = ("graphql", "__schema", "__typename", "graphiql", "did you mean",
             "must provide query", "querytype", "introspection")
  return any(marker in lowered for marker in markers)


def main():
  parser = argparse.ArgumentParser(description="Find GraphQL endpoints on an authorized host and check common misconfigurations.")
  parser.add_argument("base_url", help="e.g. https://lab.example")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  base = args.base_url.rstrip("/")
  live = []

  print("[*] endpoint discovery:")
  for path in CANDIDATE_PATHS:
    url = base + path
    status, body, content_type = post_json(url, TYPENAME_QUERY, args.timeout)
    if status is None:
      continue
    graphql = looks_like_graphql(body) or (status == 200 and "json" in content_type)
    flag = "[!]" if graphql else "[ ]"
    print(f"{flag} {url:<40} HTTP {status} ({content_type.split(';')[0]})")
    if graphql:
      live.append(url)

  if not live:
    print("\n[+] No GraphQL endpoints found among the candidate paths.")
    return

  print(f"\n[*] testing {len(live)} candidate endpoint(s):")
  for url in live:
    print(f"\n== {url}")
    status, body, _ = post_json(url, INTROSPECTION_QUERY, args.timeout)
    if status == 200 and "__schema" in body:
      type_count = body.count('"name"')
      print(f"[!] introspection ENABLED (HTTP {status}, ~{type_count} name entries returned)")
      print("      dump the schema with a full introspection query to map the attack surface.")
    else:
      snippet = body[:120].replace("\n", " ")
      print(f"[ ] introspection blocked or absent (HTTP {status}): ...{snippet}...")

    status, _, _ = get(url + "?query=" + urllib.parse.quote(TYPENAME_QUERY["query"]), args.timeout)
    if status == 200:
      print("[!] GET queries supported - GraphQL CSRF via crafted links may be possible")

    status, body, _ = post_json(url, SUGGESTION_QUERY, args.timeout)
    if "did you mean" in body.lower():
      match = body[body.lower().find("did you mean"):][:120].replace("\n", " ")
      print(f"[!] field suggestions leak schema info: ...{match}...")


if __name__ == "__main__":
  main()
