#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

DOMAINS = {"socket.dev", "stepsecurity.io", "pypi.org"}
PACKAGE_VERSIONS = {
  "mflux-streamlit==0.0.3",
  "mflux-streamlit==0.0.4",
  "mrbios==0.1.1",
  "mrbios==0.1.2",
}
PACKAGES = {
  "mflux-streamlit",
  "mrbios",
  "langchain-core-mcp",
  "mem8",
  "openai-mcp",
}
URLS = {
  "https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave",
  "https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious",
  "https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages",
  "https://pypi.org/simple/mflux-streamlit/",
  "https://pypi.org/simple/mrbios/",
}
FILE_MARKERS = {"*-setup.pth", "_index.js", "ensmallen_haswell.abi3.so", "ensmallen_core2.abi3.so"}
REGISTRY_MARKER = "pypi:project-status=quarantined"


def scan(root: Path) -> dict[str, list[str]]:
  package_hits: list[str] = []
  file_hits: list[str] = []
  registry_hits: list[str] = []
  source_hits: list[str] = []
  version_hits: list[str] = []
  domain_hits: list[str] = []
  for path in root.rglob("*"):
    if path.is_dir() or any(part in {".git", "node_modules", "vendor", "dist"} for part in path.parts):
      continue
    try:
      text = path.read_text(errors="ignore")
    except Exception:
      text = ""
    for package in PACKAGES:
      if package in text:
        package_hits.append(f"{path}: {package}")
    for package_version in PACKAGE_VERSIONS:
      if package_version in text:
        version_hits.append(f"{path}: {package_version}")
    for domain in DOMAINS:
      if domain in text:
        domain_hits.append(f"{path}: {domain}")
    for url in URLS:
      if url in text:
        source_hits.append(f"{path}: {url}")
    if REGISTRY_MARKER in text:
      registry_hits.append(f"{path}: {REGISTRY_MARKER}")
    if path.name in FILE_MARKERS:
      file_hits.append(f"{path}: {path.name}")
  return {
    "package_hits": sorted(set(package_hits)),
    "file_hits": sorted(set(file_hits)),
    "registry_hits": sorted(set(registry_hits)),
    "version_hits": sorted(set(version_hits)),
    "domain_hits": sorted(set(domain_hits)),
    "source_hits": sorted(set(source_hits)),
  }


def main() -> int:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("root", nargs="?", default=".", help="filesystem or log root to scan")
  parser.add_argument("--out", default="hades-scope", help="output directory")
  args = parser.parse_args()

  root = Path(args.root).expanduser().resolve()
  out = Path(args.out).expanduser().resolve()
  out.mkdir(parents=True, exist_ok=True)

  result = scan(root)
  (out / "scan-summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
  print(json.dumps({"scanned_root": str(root), **result}, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
