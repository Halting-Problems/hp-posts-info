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
DOMAINS = ["setup.pth","abi3.so"]
HASHES = ["dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe","e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d","c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c","6d332f814f15f19758d65026bbfd0a8c49671b319ec77b8fa1b27fc48afff7d9","6506d31707a39949f89534bf9705bcf889f1ecae3dbc6f4ff88d67a8be3d01b2"]
PACKAGE_VERSIONS = VERSIONS

# Collect unique indicators
indicators = set()
for group in [DOMAINS, HASHES]:
    for val in group:
        if val:
            indicators.add(val)

FILE_MARKERS = {"*-setup.pth", "_index.js", "ensmallen_haswell.abi3.so", "ensmallen_core2.abi3.so"}
REGISTRY_MARKER = "pypi:project-status=quarantined"


def scan(root: Path) -> dict[str, list[str]]:
  package_hits: list[str] = []
  file_hits: list[str] = []
  registry_hits: list[str] = []
  source_hits: list[str] = []
  version_hits: list[str] = []
  domain_hits: list[str] = []
  hash_hits: list[str] = []
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
    for digest in HASHES:
      if digest in text:
        hash_hits.append(f"{path}: {digest}")
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
    "hash_hits": sorted(set(hash_hits)),
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
