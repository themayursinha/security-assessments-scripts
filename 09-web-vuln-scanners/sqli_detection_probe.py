#!/usr/bin/env python3
"""Detect SQL injection via error signatures and boolean-based response diffing."""

import argparse
import difflib
import re
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "security-assessment-scripts/1.0"

DB_ERROR_SIGNATURES = [
  ("MySQL", r"SQL syntax.*?MySQL|Warning.*?mysqli?_|mysql_fetch|MariaDB"),
  ("PostgreSQL", r"PostgreSQL.*?ERROR|pg_query\(\)|syntax error at or near"),
  ("MS SQL Server", r"Unclosed quotation mark after|Microsoft SQL Native Client|ODBC SQL Server Driver"),
  ("SQLite", r"SQLite/JDBC|SQLite3::SQLException|sqlite3\.OperationalError|unrecognized token"),
  ("Oracle", r"ORA-\d{5}|Oracle error|oracle\.jdbc"),
  ("Java/Hibernate", r"java\.sql\.SQLException|HibernateException|org\.hibernate\.exception"),
]

ERROR_PAYLOADS = ["'", "\"", "'", "\\'", "1'", "1\"", "%27"]


def fetch(url, data=None, timeout=10):
  request = urllib.request.Request(
    url,
    data=data.encode() if isinstance(data, str) else data,
    headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
  )
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(131072).decode("utf-8", "replace")
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(131072).decode("utf-8", "replace")
  except (urllib.error.URLError, OSError):
    return None, ""


def build_url(template_url, param, value):
  split = urllib.parse.urlsplit(template_url)
  other = [p for p in split.query.split("&") if p and p.split("=", 1)[0] != param]
  pairs = other + [f"{param}={urllib.parse.quote(value, safe='')}" if value else f"{param}="]
  return urllib.parse.SplitResult(scheme=split.scheme, netloc=split.netloc, path=split.path, query="&".join(pairs), fragment="").geturl()


def similarity(a, b):
  if not a or not b:
    return 0.0
  return difflib.SequenceMatcher(None, a, b).quick_ratio()


def main():
  parser = argparse.ArgumentParser(description="Detect SQLi on an authorized target via DB errors and boolean differential.")
  parser.add_argument("url", help="endpoint with injectable parameter, e.g. https://lab.example/filter?category=x")
  parser.add_argument("--param", default=None, help="parameter to inject; default: last parameter in the URL")
  parser.add_argument("--post", action="store_true", help="send injections as POST form body instead of query string")
  parser.add_argument("--delay", type=float, default=0.2, help="delay between requests")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  param = args.param
  if not param:
    query = urllib.parse.urlsplit(args.url).query
    param = query.split("=")[0].split("&")[0] if "=" in query else "q"
    print(f"[*] using parameter: {param}")

  def send(value):
    if args.post:
      body = urllib.parse.urlencode({param: value})
      return fetch(build_url(args.url, param, ""), body, args.timeout)
    return fetch(build_url(args.url, param, value), None, args.timeout)

  baseline_status, baseline_body = send("normalvalue123")

  findings = []
  for payload in ERROR_PAYLOADS:
    status, body = send(payload)
    for engine, pattern in DB_ERROR_SIGNATURES:
      match = re.search(pattern, body, re.IGNORECASE)
      if match:
        evidence = body[max(0, match.start() - 40):match.end() + 60].replace("\n", " ")
        findings.append(("error-based", engine, payload, status, evidence))
        break
    time.sleep(args.delay)

  true_payload = "normalvalue123' AND '1'='1"
  false_payload = "normalvalue123' AND '1'='2"
  t_status, t_body = send(true_payload)
  time.sleep(args.delay)
  f_status, f_body = send(false_payload)

  sim_true = similarity(t_body, baseline_body)
  sim_false = similarity(f_body, baseline_body)
  sim_tf = similarity(t_body, f_body)
  boolean_indicator = (
    len(t_body) > 200 and len(f_body) > 200
    and sim_true > 0.95 and sim_false < sim_true - 0.05
    and sim_tf < 0.98
  )

  print(f"[*] baseline HTTP {baseline_status}, {len(baseline_body)} bytes")
  for kind, engine, payload, status, evidence in findings:
    print(f"[!] {kind}: {engine} error triggered")
    print(f"      payload={payload!r} -> HTTP {status}")
    print(f"      evidence: ...{evidence}...")
  print(f"[*] boolean test: AND '1'='1 sim={sim_true:.2f}, AND '1'='2 sim={sim_false:.2f}, t-vs-f={sim_tf:.2f}")
  if boolean_indicator:
    findings.append(("boolean-based", "differential", false_payload, f_status, "true/false responses diverge from baseline"))
    print("[!] boolean-based indicator: false condition changes response while true condition matches baseline")

  if not findings:
    print("[+] no SQL injection indicators with basic payloads; try union/blind techniques manually.")


if __name__ == "__main__":
  main()
