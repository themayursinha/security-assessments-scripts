#!/usr/bin/env python3
"""Parse nmap XML output into a readable table, CSV, or Markdown report."""

import argparse
import csv
import sys
import xml.etree.ElementTree as ET


def parse_nmap_xml(path):
  tree = ET.parse(path)
  root = tree.getroot()
  rows = []
  for host in root.findall("host"):
    addresses = [addr.get("addr") for addr in host.findall("address")]
    ip = next((a for a in addresses if a and ":" not in a), addresses[0] if addresses else "")
    hostnames = host.find("hostnames")
    name = ""
    if hostnames is not None:
      hostname = hostnames.find("hostname")
      if hostname is not None:
        name = hostname.get("name", "")
    for port in host.iter("port"):
      state_el = port.find("state")
      service_el = port.find("service")
      rows.append({
        "ip": ip,
        "hostname": name,
        "port": port.get("portid"),
        "protocol": port.get("protocol"),
        "state": state_el.get("state") if state_el is not None else "",
        "service": (service_el.get("name") or "") if service_el is not None else "",
        "product": (service_el.get("product") or "") if service_el is not None else "",
        "version": (service_el.get("version") or "") if service_el is not None else "",
      })
  return rows


def print_table(rows):
  columns = ["ip", "hostname", "port", "protocol", "state", "service", "product", "version"]
  widths = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in columns}
  header = "  ".join(c.ljust(widths[c]) for c in columns)
  print(header)
  print("-" * len(header))
  for row in rows:
    print("  ".join(str(row[c]).ljust(widths[c]) for c in columns))


def write_csv(rows, path):
  with open(path, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)


def write_markdown(rows, path):
  columns = ["ip", "hostname", "port", "state", "service", "product", "version"]
  with open(path, "w", encoding="utf-8") as handle:
    handle.write("| " + " | ".join(columns) + " |\n")
    handle.write("|" + "|".join([" --- "] * len(columns)) + "|\n")
    for row in rows:
      handle.write("| " + " | ".join(str(row[c]) or " " for c in columns) + " |\n")


def main():
  parser = argparse.ArgumentParser(description="Convert nmap -oX XML scan output to a table, CSV, or Markdown.")
  parser.add_argument("xml_file", help="nmap XML file")
  parser.add_argument("--csv", dest="csv_path", help="write CSV to this path")
  parser.add_argument("--markdown", help="write Markdown table to this path")
  parser.add_argument("--open-only", action="store_true", help="only include open ports")
  args = parser.parse_args()

  rows = parse_nmap_xml(args.xml_file)
  if args.open_only:
    rows = [row for row in rows if row["state"] == "open"]
  if not rows:
    print("No matching port entries found in the XML.")
    return

  if args.csv_path:
    write_csv(rows, args.csv_path)
    print(f"Wrote {len(rows)} rows to {args.csv_path}")
  if args.markdown:
    write_markdown(rows, args.markdown)
    print(f"Wrote {len(rows)} rows to {args.markdown}")
  if not args.csv_path and not args.markdown:
    print_table(rows)


if __name__ == "__main__":
  main()
