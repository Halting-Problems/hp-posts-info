#!/usr/bin/env python3
"""Build deterministic core artifacts for the Lucide Proxy research packet."""

from __future__ import annotations

import json
from pathlib import Path
from pprint import pformat


ROOT = Path(__file__).resolve().parent.parent
REFS = ROOT / "references"
SLUG = "lucide-proxy-npm-browser-ddos-campaign"
TITLE = "Lucide Proxy: 148 npm packages used as browser DDoS and adware delivery infrastructure"

DOMAINS = [
    "woofbeginner.com",
    "c.vipersfutbol.com",
    "realizationnewestfangs.com",
    "protrafficinspector.com",
    "preferencenail.com",
    "skinnycrawlinglax.com",
    "cdn.conditionfuneral.com",
    "lucideon.top",
    "wisp.breadarchive.dpdns.org",
    "21baseballacademy.com",
    "cdn.21baseballacademy.com",
    "abdct.com",
    "geeked.wtf",
]
URLS = [
    "https://cdn.jsdelivr.net/gh/canyoupleasesaysomething/cdn@main/cdn.js",
    "https://cdn.jsdelivr.net/gh/canyoupleasesaysomething/cdn@main/websocket.txt",
    "https://woofbeginner.com/jivd2xu8",
    "https://woofbeginner.com/0a/91/35/0a913561831bdf2c26dcf18b852b5cc1.js",
    "https://wisp.breadarchive.dpdns.org",
    "https://21baseballacademy.com",
    "https://lucideon.top",
    "https://c.vipersfutbol.com/script.js",
    "https://realizationnewestfangs.com",
    "https://protrafficinspector.com/stats",
    "https://preferencenail.com/sfp.js",
    "https://skinnycrawlinglax.com/dnn2hkn8",
    "https://cdn.conditionfuneral.com",
    "https://abdct.com/",
]
IPS = [
    "92.38.177.17",
    "92.38.177.10",
    "153.75.225.178",
    "5.188.124.67",
    "92.38.177.16",
    "92.38.177.37",
]
HASHES = [
    "eb4e1394d537d8eba509dd5c57e7aaf4c1df57715c7161330012a11f6202af84",
    "10ddbbae0070267b8d15888b09a3cdb19fa74d861315b71f21c9ace8b9f85c75",
    "4b188d179e50e8208a6efec85e273e88d8fc390c836f299ba12915e0840408fd",
]
FILES = ["assets/73sxysj46r.js", "assets/script.js"]
CAMPAIGN_IDENTIFIERS = [
    "G-0VL3ZSBXDH",
    "0a913561831bdf2c26dcf18b852b5cc1",
    "c6851a038da578a80eeb201e0588c84c",
]
PUBLISHERS = ["terminal3airport", "eerikakirk"]
REPOSITORIES = ["lucideproxy/svg", "canyoupleasesaysomething/cdn"]
HISTORICAL_DDOS_TARGETS = ["https://cdn.caan.edu/-/?v="]


def build_profile(package_rows: list[dict]) -> dict:
    packages = [row["name"] for row in package_rows]
    package_versions = [
        f"{row['name']}@{version}"
        for row in package_rows
        for version in row["malicious_versions"]
    ]
    unique_versions = sorted({version for row in package_rows for version in row["malicious_versions"]})
    return {
        "schema_version": "3.0",
        "event_id": SLUG,
        "candidate_id": SLUG,
        "event_name": TITLE,
        "source_item_key": "jfrog-research:lucide-proxy-npm-malware-campaign",
        "source_version_hash": "dac4e36c6c63cdfc9ce13b8db4f9d67287877b7ec5bb9516ca8b76681f557fcf",
        "source_version_at": "2026-07-13T00:00:00.000Z",
        "parent_campaign_id": "none",
        "is_campaign_level": True,
        "publication_state": "needs_review",
        "confidence": "high",
        "confidence_reason": (
            "JFrog directly deobfuscated campaign assets and recovered immutable GitHub history; "
            "historical remote-loader, Wisp traffic-generation, and HTTP-flood behavior is high confidence. "
            "Current DDoS capability is only medium confidence because the modules were removed on May 31 "
            "and the July 8 package wave contained later adware-only builds."
        ),
        "attack_types": [
            "npm-registry-abuse",
            "malicious-package-content",
            "browser-content-supply-chain",
            "mutable-remote-code-loading",
            "browser-ddos",
            "adware",
            "service-worker",
        ],
        "tags": ["npm", "browser", "github", "registry-abuse", "malware", "adware"],
        "exploitation_evidence": [
            "JFrog recovered an archived May 30 HTTP flood initiated from visitor browsers.",
            "JFrog and GitHub commit metadata show the mutable loader and Wisp generator in May history.",
        ],
        "sources": {
            "direct": [
                "https://github.com/lucideproxy/svg",
                "https://registry.npmjs.org/charlie-kirk",
            ],
            "primary_research": [
                "https://research.jfrog.com/post/lucide-proxy-npm-malware-campaign/",
                "https://safedep.io/malicious-npm-terminal3airport-proxy-adware-spam/",
            ],
            "correlated": [],
        },
        "affected_assets": {
            "ecosystems": ["npm", "browser", "GitHub"],
            "registries": ["registry.npmjs.org"],
            "packages": packages,
            "versions": unique_versions,
            "repositories": REPOSITORIES,
            "vendors": [],
            "ci_cd_systems": [],
            "container_images": [],
            "developer_tools": [],
            "credentials_at_risk": [],
            "deployment_hostnames_reported": 93,
            "browser_users": "Visitors to deployed Lucide Proxy-derived pages; victim count unknown.",
        },
        "timeline": {
            "first_seen": "2026-03-05T00:00:00Z",
            "malicious_publish_time": "2026-05-27T00:00:00Z",
            "discovery_time": "2026-05-27",
            "removal_time": "2026-07-13T21:55:38Z (147 package names replaced by npm security placeholders; charlie-kirk remained available)",
            "disclosure_time": "2026-07-13",
            "patch_or_fix_time": "2026-05-31T01:30:36Z (historical malicious modules removed from build history; exact source commit mapping needs review)",
        },
        "artifact_analysis": {
            "malicious_artifacts": [
                "lucideproxy/svg@bcc9868e345b6a04e2b2b89de355d1829daf31e1",
                "lucideproxy/svg@9b7ca53d6bd8c197e8fe29eabcff54b03331f98f",
                "lucideproxy/svg@ccc7c921bc931c93cf418a877e16fe768a201500",
            ],
            "execution_trigger": "A user visits a deployed proxy page; browser JavaScript and its service worker execute. No npm install hook was observed.",
            "payload_behavior": [
                "Historical builds loaded mutable JavaScript from a remote CDN path.",
                "Historical builds created Wisp-compatible WebSocket control traffic capable of connection exhaustion.",
                "An archived May 30 payload generated HTTP flood traffic from visitor browsers.",
                "Later builds retained popunder and third-party advertising script behavior without confirmed DDoS modules.",
            ],
            "provenance": {
                "repository": "https://github.com/lucideproxy/svg",
                "signatures": "GitHub commit API reports the inspected commits as unsigned.",
                "registry_provenance": "unknown; tarballs were not downloaded in this safety-constrained run.",
            },
        },
        "contextual_observables": [
            {
                "type": "url",
                "value": "https://cdn.caan.edu/-/?v=",
                "role": "historical_ddos_target",
                "do_not_block_as_attacker_infrastructure": True,
                "source": "JFrog archived May 30 HTTP-flood analysis",
            }
        ],
        "iocs": {
            "package_versions": package_versions,
            "files": FILES,
            "hashes": HASHES,
            "domains": DOMAINS,
            "urls": URLS,
            "ips": IPS,
            "process_patterns": [],
            "network_patterns": CAMPAIGN_IDENTIFIERS,
        },
        "detection": {
            "lockfile_hunts": packages,
            "filesystem_hunts": FILES + HASHES,
            "process_hunts": [],
            "network_hunts": DOMAINS + IPS + CAMPAIGN_IDENTIFIERS,
            "ci_cd_hunts": [],
            "registry_hunts": PUBLISHERS + packages,
        },
        "open_questions": [
            "Whether charlie-kirk 2.0.0/3.0.1 currently serves or can activate DDoS code was not established; registry availability alone is not execution evidence.",
            "The complete 93 deployment-hostname list was not published in the JFrog IOC appendix.",
            "The exact build commit that corresponds to JFrog's abbreviated cf741e982181a module-removal reference remains unresolved.",
            "Victim and browser-session counts remain unknown.",
        ],
        "defender_takeaways": {
            "detection": "Search dependency/lockfile inventories, web proxy logs, DNS logs, browser history, and service-worker inventories with the tested scope scanner.",
            "hunting": "Separate developer/package exposure from end-user browser execution; an npm cache hit does not prove a page was hosted or visited.",
            "remediation": "Remove affected package references and hosted builds, block precise infrastructure, unregister associated service workers, clear affected browser site data, and preserve logs before cleanup.",
            "prevention": "Disallow unreviewed static proxy applications, pin frontend artifacts, enforce CSP and egress controls, and monitor service-worker registration on managed browsers.",
        },
        "remediation_gates": {
            "containment_complete": [
                "Affected hosted proxy deployments are disabled and precise campaign infrastructure is blocked.",
                "Managed-browser service workers tied to confirmed deployment origins are unregistered after evidence preservation.",
            ],
            "eradication_complete": [
                "All 148 package names and malicious version pairs are absent from dependency manifests, lockfiles, caches selected for rebuild, and deployed static assets.",
                "Hosted assets are rebuilt from reviewed sources without mutable campaign loaders or advertising scripts.",
            ],
            "recovery_complete": [
                "Rebuilt deployments pass the provided scope scan and browser/network monitoring shows no campaign selectors.",
                "Users return only after cache invalidation and service-worker cleanup are verified for affected origins.",
            ],
            "closure_required": [
                "Thirty days of DNS, proxy, and managed-browser monitoring show no campaign infrastructure, GA identifier, payload hashes, or affected package versions.",
                "Package consumers and proxy-page visitors are counted separately in the incident record, with unknown exposure left explicit.",
            ],
        },
    }


def build_scanner(package_rows: list[dict]) -> str:
    packages = [row["name"] for row in package_rows]
    package_map = {row["name"]: row["malicious_versions"] for row in package_rows}
    constants = {
        "PACKAGES": packages,
        "PACKAGE_VERSION_MAP": package_map,
        "DOMAINS": DOMAINS,
        "URLS": URLS,
        "IPS": IPS,
        "HASHES": HASHES,
        "FILES": FILES,
        "CAMPAIGN_IDENTIFIERS": CAMPAIGN_IDENTIFIERS,
        "PUBLISHERS": PUBLISHERS,
        "REPOSITORIES": REPOSITORIES,
        "HISTORICAL_DDOS_TARGETS": HISTORICAL_DDOS_TARGETS,
    }
    rendered = "\n\n".join(f"{name} = {pformat(value, width=100, sort_dicts=False)}" for name, value in constants.items())
    return f'''#!/usr/bin/env python3
"""Static Lucide Proxy exposure scanner for reader-owned files and log exports.

Exit codes: 0 clean, 1 campaign selector found, 2 collection or input failure.
The scanner performs no network requests and never executes located content.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


OUT = "hp-{SLUG}-scope"
MAX_FILE_BYTES = 8 * 1024 * 1024
EXCLUDED_DIRS = {{"node_modules", ".git", ".venv", "__pycache__", OUT}}

{rendered}


def scan_file(path: Path) -> list[dict[str, str]]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeError):
        return []
    lower = text.lower()
    findings: list[dict[str, str]] = []

    for package, versions in PACKAGE_VERSION_MAP.items():
        package_pattern = re.compile(r"(?<![a-z0-9_.-])" + re.escape(package.lower()) + r"(?![a-z0-9_.-])")
        for match in package_pattern.finditer(lower):
            window = lower[max(0, match.start() - 160): min(len(lower), match.end() + 160)]
            matched_versions = [version for version in versions if version.lower() in window]
            findings.append({{
                "type": "package_version" if matched_versions else "package_name",
                "value": f"{{package}}@{{matched_versions[0]}}" if matched_versions else package,
                "path": str(path),
            }})
            break

    selector_groups = [
        ("domain", DOMAINS),
        ("url", URLS),
        ("ip", IPS),
        ("sha256", HASHES),
        ("file_path", FILES),
        ("campaign_identifier", CAMPAIGN_IDENTIFIERS),
        ("publisher", PUBLISHERS),
        ("repository", REPOSITORIES),
        ("historical_ddos_target", HISTORICAL_DDOS_TARGETS),
    ]
    for selector_type, selectors in selector_groups:
        for selector in selectors:
            if selector.lower() in lower:
                findings.append({{"type": selector_type, "value": selector, "path": str(path)}})
    return findings


def scan(root: Path) -> tuple[list[dict[str, str]], list[str]]:
    indicators = set()
    findings: list[dict[str, str]] = []
    errors: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in EXCLUDED_DIRS]
        for filename in files:
            path = Path(current) / filename
            try:
                file_findings = scan_file(path)
            except Exception as error:
                errors.append(f"{{path}}:{{type(error).__name__}}")
                continue
            for finding in file_findings:
                key = (finding["type"], finding["value"], finding["path"])
                if key not in indicators:
                    indicators.add(key)
                    findings.append(finding)
    return findings, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope", type=Path, help="Reader-owned repository or exported telemetry directory")
    parser.add_argument("--out", type=Path, help="Optional JSON result path")
    args = parser.parse_args()
    root = args.scope.expanduser().resolve()
    if not root.is_dir():
        print(json.dumps({{"status": "collection_failure", "error": "scope is not a readable directory"}}))
        return 2
    findings, errors = scan(root)
    payload = {{
        "event_id": "{SLUG}",
        "status": "alert" if findings else "clean",
        "finding_count": len(findings),
        "findings": findings,
        "read_errors": errors,
        "interpretation": (
            "A match proves the selector exists in the supplied scope; it does not by itself prove browser execution. "
            "Correlate package/host evidence with deployment, DNS/proxy, browser history, and service-worker records."
        ),
    }}
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        try:
            args.out.expanduser().resolve().write_text(encoded + "\\n", encoding="utf-8")
        except OSError as error:
            print(json.dumps({{"status": "collection_failure", "error": type(error).__name__}}))
            return 2
    print(encoded)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
'''


def main() -> None:
    package_rows = json.loads((REFS / "jfrog-package-version-table.json").read_text(encoding="utf-8"))
    profile = build_profile(package_rows)
    for name in ["event_profile.json", "iocs.json"]:
        (ROOT / name).write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    script = ROOT / "scripts" / "scan_lucide_proxy_exposure.py"
    script.write_text(build_scanner(package_rows), encoding="utf-8")
    script.chmod(0o755)
    print(json.dumps({"packages": len(package_rows), "package_version_pairs": len(profile["iocs"]["package_versions"])}))


if __name__ == "__main__":
    main()
