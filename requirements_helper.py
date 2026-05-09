#!/usr/bin/env python3
"""Report third-party imports used by scripts in this repository."""

import argparse
import ast
import importlib.util
from pathlib import Path


PACKAGE_HINTS = {
  "bs4": "beautifulsoup4",
  "mechanize": "mechanize",
  "mysql": "mysql-connector-python",
  "pefile": "pefile",
  "psutil": "psutil",
  "scapy": "scapy",
  "selenium": "selenium",
  "watchdog": "watchdog",
}


def imports_for(path):
  tree = ast.parse(path.read_text(encoding="utf-8"))
  imports = set()
  for node in ast.walk(tree):
    if isinstance(node, ast.Import):
      imports.update(alias.name.split(".", 1)[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
      imports.add(node.module.split(".", 1)[0])
  return imports


def is_stdlib_or_local(name, script_names):
  if name in script_names:
    return True
  spec = importlib.util.find_spec(name)
  if spec is None:
    return False
  origin = spec.origin or ""
  return "site-packages" not in origin and "dist-packages" not in origin


def main():
  parser = argparse.ArgumentParser(description="Summarize third-party dependencies used by repo scripts.")
  parser.add_argument("--path", default=".", help="repository path")
  args = parser.parse_args()

  root = Path(args.path)
  scripts = sorted(root.glob("*.py"))
  script_names = {path.stem for path in scripts}
  third_party = {}

  for script in scripts:
    for name in imports_for(script):
      if name in PACKAGE_HINTS or not is_stdlib_or_local(name, script_names):
        third_party.setdefault(name, set()).add(script.name)

  if not third_party:
    print("No third-party imports detected.")
    return

  print("Third-party imports:")
  packages = []
  for import_name, users in sorted(third_party.items()):
    package = PACKAGE_HINTS.get(import_name, import_name)
    packages.append(package)
    print(f"  {import_name} ({package}): {', '.join(sorted(users))}")

  print()
  print("Suggested install command:")
  print("python3 -m pip install " + " ".join(sorted(set(packages))))


if __name__ == "__main__":
  main()
