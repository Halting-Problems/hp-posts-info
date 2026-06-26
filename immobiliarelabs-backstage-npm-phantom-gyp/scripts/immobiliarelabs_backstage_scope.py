#!/usr/bin/env python3
"""Scope exposure to the June 26, 2026 @immobiliarelabs Backstage npm compromise.

Exit codes:
  0: completed, no indicators found
  1: completed, indicators found
  2: execution or telemetry collection failure

Inputs:
  argv[1]  root directory to scan, default current directory
  LOG_ROOT optional directory containing exported npm/pnpm/yarn/CI/process logs
  OUT      output directory, default hp-immobiliarelabs-backstage-npm-phantom-gyp-scope

The scanner performs static text matching only. It does not install or execute packages.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
LOG_ROOT = Path(os.environ["LOG_ROOT"]) if os.environ.get("LOG_ROOT") else None
OUT = Path(os.environ.get("OUT", "hp-immobiliarelabs-backstage-npm-phantom-gyp-scope"))

PACKAGES = [
    "@immobiliarelabs/backstage-plugin-gitlab",
    "@immobiliarelabs/backstage-plugin-gitlab-backend",
    "@immobiliarelabs/backstage-plugin-ldap-auth",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend",
]

PACKAGE_VERSIONS = [
    "@immobiliarelabs/backstage-plugin-gitlab@1.0.1",
    "@immobiliarelabs/backstage-plugin-gitlab@2.1.2",
    "@immobiliarelabs/backstage-plugin-gitlab@3.0.3",
    "@immobiliarelabs/backstage-plugin-gitlab@4.0.2",
    "@immobiliarelabs/backstage-plugin-gitlab@5.2.1",
    "@immobiliarelabs/backstage-plugin-gitlab@6.13.1",
    "@immobiliarelabs/backstage-plugin-gitlab@7.0.2",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@3.0.3",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@4.0.2",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@5.2.1",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@6.13.1",
    "@immobiliarelabs/backstage-plugin-gitlab-backend@7.0.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth@1.1.4",
    "@immobiliarelabs/backstage-plugin-ldap-auth@2.0.5",
    "@immobiliarelabs/backstage-plugin-ldap-auth@3.0.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth@4.3.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth@5.2.1",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@1.1.3",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@2.0.5",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@3.0.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@4.3.2",
    "@immobiliarelabs/backstage-plugin-ldap-auth-backend@5.2.1",
]

FILES = ["binding.gyp", "index.js", "package/binding.gyp", "package/index.js"]
PROCESS_PATTERNS = ["node-gyp rebuild", "node index.js", "binding.gyp"]
TARBALL_HASHES = [
    "d830d5b00af9bfe60347dbda5e93d924aac37a39",
    "7ae466337c9f0951feae7b30d6f4b8afc8066bf8",
    "7b4d99626d9c8bfa9fa0f8006e6d37c66320e57d",
    "92a67fe894bdcbb563cf8e09309e41ca34d4773a",
    "a36134e065b6317977cefdd689e4f618634d4919",
    "5987abaf99305c4d9be48ebf35f255cd37b2dbc6",
    "6bd93e1adce382d2172e68ad9fcb73b7e2281de8",
    "6c0196d7df24c4f8c5fa67e179b3864cee571437",
    "5e4fb65fe26b1d81eed844a071218b8e80cb05cc",
    "4ae5348a58060816646ae681495dff6b51ac8a3e",
    "a28eb85ec7d79c7dbb4200e3b79043b2e001a77a",
    "ce5c35e2d682a30a54b64f954c50fa5297f24908",
    "0ef092f8a08f98cdb9670496e2bbe567dde514e0",
    "c63e6d86ebe37f171040f18d916eab0b943e1c26",
    "5b03aec413b8cdb5816ceefe01b6d5d567ea1265",
    "08664303657e7889f51f4d1fe4882847873d165c",
    "de475c8e984307e741f3fa806e8576dc6ae4e3f8",
    "babfa31e6b21e88bd04bd83a066e364d40eb9180",
    "9c70373f80c11afed6cac96363044573a4674f08",
    "4bfc39e5187c2337d76a6999fa085e4332e7ae8b",
    "061a099c939e418bf09b5796852590f0e8ac7e42",
    "54ef1bbcbbcdf9390c70b4628934b434ea871174",
    "7a879ed69a8191df5c68535f6ac41b830577b698de943c66ff40e51482d90d79",
]

URLS = [
    "https://registry.npmjs.org/@immobiliarelabs/backstage-plugin-gitlab/-/backstage-plugin-gitlab-2.1.2.tgz",
]

EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".astro"}
TEXT_SUFFIXES = {
    ".json", ".yaml", ".yml", ".lock", ".txt", ".log", ".md", ".js", ".mjs",
    ".cjs", ".ts", ".tsx", ".sh", ".ps1", ".xml", ".csv", "",
}


def iter_files(root: Path) -> Iterable[Path]:
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for filename in filenames:
            path = Path(current_root) / filename
            if path.suffix.lower() in TEXT_SUFFIXES or "lock" in path.name.lower():
                yield path


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > 25_000_000:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def version_patterns(package_version: str) -> list[str]:
    package, version = package_version.rsplit("@", 1)
    escaped_package = re.escape(package)
    escaped_version = re.escape(version)
    return [
        rf"{escaped_package}@{escaped_version}",
        rf'"{escaped_package}"\s*:\s*"{escaped_version}"',
        rf"'{escaped_package}'\s*:\s*'{escaped_version}'",
        rf"node_modules/{escaped_package}/[^\n\r]*version[=: ]+{escaped_version}",
    ]


def scan_text(label: str, content: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for package_version in PACKAGE_VERSIONS:
        for pattern in version_patterns(package_version):
            if re.search(pattern, content):
                hits.append({"source": label, "type": "package_version", "indicator": package_version})
                break
    for digest in TARBALL_HASHES:
        if digest in content:
            hits.append({"source": label, "type": "tarball_hash", "indicator": digest})
    for url in URLS:
        if url in content:
            hits.append({"source": label, "type": "tarball_url", "indicator": url})
    for process in PROCESS_PATTERNS:
        if process in content:
            hits.append({"source": label, "type": "process_or_file_pattern", "indicator": process})
    return hits


def main() -> int:
    if not ROOT.exists() or not ROOT.is_dir():
        print(f"[x] ROOT is not a directory: {ROOT}", file=sys.stderr)
        return 2
    if LOG_ROOT is not None and (not LOG_ROOT.exists() or not LOG_ROOT.is_dir()):
        print(f"[x] LOG_ROOT is not a directory: {LOG_ROOT}", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "indicators.json").write_text(
        json.dumps(
            {
                "packages": PACKAGES,
                "package_versions": PACKAGE_VERSIONS,
                "files": FILES,
                "urls": URLS,
                "process_patterns": PROCESS_PATTERNS,
                "tarball_hashes": TARBALL_HASHES,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    matches: list[dict[str, str]] = []
    scanned_roots = [("repository", ROOT)]
    if LOG_ROOT is not None:
        scanned_roots.append(("logs", LOG_ROOT))

    for root_type, root in scanned_roots:
        for path in iter_files(root):
            content = read_text(path)
            if content is None:
                continue
            rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
            matches.extend(scan_text(f"{root_type}:{rel}", content))

    # Direct artifact inventory: if an extracted tarball or package cache contains both binding.gyp and index.js
    # under an affected @immobiliarelabs package path, flag it even if lockfile metadata is absent.
    for path in iter_files(ROOT):
        normalized = str(path).replace("\\", "/")
        if "@immobiliarelabs" in normalized and normalized.endswith(("binding.gyp", "index.js")):
            matches.append({"source": normalized, "type": "package_artifact_file", "indicator": Path(normalized).name})

    unique = []
    seen = set()
    for match in matches:
        key = (match["source"], match["type"], match["indicator"])
        if key not in seen:
            seen.add(key)
            unique.append(match)

    result = {
        "event": "immobiliarelabs-backstage-npm-phantom-gyp-2026-06-26",
        "root": str(ROOT),
        "log_root": str(LOG_ROOT) if LOG_ROOT else None,
        "match_count": len(unique),
        "matches": unique,
        "classification": "alert" if unique else "clean",
    }
    (OUT / "scope-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if unique:
        print(f"[!] Found {len(unique)} @immobiliarelabs Backstage compromise indicators. See {OUT / 'scope-results.json'}")
        return 1
    print(f"[+] No @immobiliarelabs Backstage compromise indicators found. See {OUT / 'scope-results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
