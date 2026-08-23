#!/usr/bin/env python3
"""Look up CVE details from the NVD API 2.0 by CVE ID or keyword search."""

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "security-assessment-scripts/1.0"


def query_nvd(params, timeout):
  url = NVD_ENDPOINT + "?" + urllib.parse.urlencode(params)
  request = urllib.request.Request(url, headers={"User-Agent": UA})
  try:
    with urllib.request.urlopen(request, timeout=timeout) as response:
      return json.load(response)
  except urllib.error.HTTPError as exc:
    detail = exc.read(300).decode("utf-8", "replace")
    raise SystemExit(f"NVD returned HTTP {exc.code}: {detail}")
  except (urllib.error.URLError, OSError) as exc:
    raise SystemExit(f"Could not reach NVD: {exc}")


def extract_severity(vulnerability):
  metrics = vulnerability.get("cve", {}).get("metrics", {})
  for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
    if metrics.get(key):
      data = metrics[key][0]
      cvss = data.get("cvssData", {})
      return cvss.get("baseSeverity") or data.get("baseSeverity"), cvss.get("baseScore")
  return "unknown", None


def print_result(item):
  cve = item["cve"]
  cve_id = cve["id"]
  published = cve.get("published", "?")[:10]
  severity, score = extract_severity(item)
  descriptions = [d for d in cve.get("descriptions", []) if d.get("lang") == "en"]
  summary = descriptions[0]["value"][:220] if descriptions else "(no description)"
  print(f"{cve_id}  [{severity}{f' {score}' if score is not None else ''}]  published={published}")
  print(f"    {summary}")
  references = list(dict.fromkeys(ref.get("url") for ref in cve.get("references", [])))[:2]
  for reference in references:
    print(f"    ref: {reference}")
  print()


def main():
  parser = argparse.ArgumentParser(description="Query the public NVD API for CVE details.")
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument("--id", help="specific CVE ID, e.g. CVE-2024-21762")
  group.add_argument("--keyword", help="keyword search, e.g. 'fortinet ssl overflow'")
  parser.add_argument("--results", type=int, default=5, choices=range(1, 11), help="results per keyword query (1-10)")
  parser.add_argument("--timeout", type=float, default=30.0, help="request timeout in seconds")
  args = parser.parse_args()

  if args.id:
    params = {"cveId": args.id.upper()}
  else:
    params = {"keywordSearch": args.keyword, "resultsPerPage": args.results}

  data = query_nvd(params, args.timeout)
  results = data.get("vulnerabilities", [])
  total = data.get("totalResults", 0)

  if not results:
    print("No CVEs matched.")
    return

  print(f"{total} match(es); showing {len(results)}\n")
  for item in results:
    print_result(item)


if __name__ == "__main__":
  main()
