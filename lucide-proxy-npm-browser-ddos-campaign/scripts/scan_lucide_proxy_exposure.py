#!/usr/bin/env python3
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


OUT = "hp-lucide-proxy-npm-browser-ddos-campaign-scope"
MAX_FILE_BYTES = 8 * 1024 * 1024
EXCLUDED_DIRS = {"node_modules", ".git", ".venv", "__pycache__", OUT}

PACKAGES = ['charlie-kirk',
 'ilovefemboys',
 'abuden1',
 'abuden2',
 'abuden21',
 'abuden210',
 'abuden211',
 'abuden212',
 'abuden213',
 'abuden214',
 'abuden215',
 'abuden216',
 'abuden217',
 'abuden218',
 'abuden219',
 'abuden22',
 'abuden220',
 'abuden221',
 'abuden222',
 'abuden223',
 'abuden224',
 'abuden225',
 'abuden226',
 'abuden227',
 'abuden228',
 'abuden229',
 'abuden23',
 'abuden230',
 'abuden24',
 'abuden25',
 'abuden26',
 'abuden27',
 'abuden28',
 'abuden29',
 'abuden3',
 'abuden4',
 'abuden5',
 'acidic',
 'backup1-gg',
 'backup2-asd',
 'backup3-ff',
 'backup4-gasp',
 'backup5-updated',
 'backupgenuine-updated',
 'backupsitetuff10',
 'backupsitetuff3',
 'backupsitetuff6',
 'backupsitetuff9',
 'bismillahitidakimas',
 'bomboclatwallahi',
 'captainindia',
 'crazynut',
 'fflc-updated',
 'howmanygreatbritain',
 'imillegal1',
 'imillegal2',
 'imillegal3',
 'imillegal4',
 'imillegal5',
 'ishowfeet1',
 'ishowfeet10',
 'ishowfeet11',
 'ishowfeet12',
 'ishowfeet13',
 'ishowfeet14',
 'ishowfeet15',
 'ishowfeet16',
 'ishowfeet17',
 'ishowfeet18',
 'ishowfeet19',
 'ishowfeet2',
 'ishowfeet20',
 'ishowfeet3',
 'ishowfeet4',
 'ishowfeet5',
 'ishowfeet6',
 'ishowfeet7',
 'ishowfeet8',
 'ishowfeet9',
 'kirkland',
 'lowkeybored',
 'lowkirkuenly',
 'midnightrush',
 'miguelphonk',
 'nottuff1',
 'nottuff10',
 'nottuff11',
 'nottuff12',
 'nottuff13',
 'nottuff14',
 'nottuff15',
 'nottuff16',
 'nottuff17',
 'nottuff18',
 'nottuff19',
 'nottuff2',
 'nottuff20',
 'nottuff21',
 'nottuff22',
 'nottuff23',
 'nottuff24',
 'nottuff25',
 'nottuff26',
 'nottuff27',
 'nottuff28',
 'nottuff29',
 'nottuff3',
 'nottuff30',
 'nottuff4',
 'nottuff5',
 'nottuff6',
 'nottuff7',
 'nottuff8',
 'nottuff9',
 'omglucidesotuff',
 'omgyesyesyes',
 'pasirianspirit',
 'ratelimitsucks',
 'ratelimitsucks1',
 'ratelimitsucks10',
 'ratelimitsucks2',
 'ratelimitsucks3',
 'ratelimitsucks4',
 'ratelimitsucks5',
 'ratelimitsucks6',
 'ratelimitsucks9',
 'sixseven1',
 'sixseven10',
 'sixseven2',
 'sixseven3',
 'sixseven4',
 'sixseven5',
 'sixseven6',
 'sixseven7',
 'sixseven8',
 'sixseven9',
 'speed1',
 'speed2',
 'speed3',
 'speed4',
 'speed5',
 'thebigyahu',
 'timmytuffknuckles3',
 'timmytuffknuckles6',
 'timmytuffknuckles9',
 'whatsadmaidk',
 'changiairportpromax',
 'testdonotredeemit']

PACKAGE_VERSION_MAP = {'charlie-kirk': ['2.0.0', '3.0.1'],
 'ilovefemboys': ['1.1.3', '2.0.0'],
 'abuden1': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden2': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden21': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden210': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden211': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden212': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden213': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden214': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden215': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden216': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden217': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden218': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden219': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden22': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden220': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden221': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden222': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden223': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden224': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden225': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden226': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden227': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden228': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden229': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden23': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden230': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden24': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden25': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden26': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden27': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden28': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden29': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden3': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden4': ['1.1.7', '1.7.7', '2.0.0'],
 'abuden5': ['1.1.7', '1.7.7', '2.0.0'],
 'acidic': ['2.0.0'],
 'backup1-gg': ['1.1.2', '2.0.0'],
 'backup2-asd': ['1.1.2', '2.0.0'],
 'backup3-ff': ['1.1.2', '2.0.0'],
 'backup4-gasp': ['1.1.2', '2.0.0'],
 'backup5-updated': ['1.1.2', '2.0.0'],
 'backupgenuine-updated': ['1.1.2', '2.0.0'],
 'backupsitetuff10': ['1.1.7', '2.0.0'],
 'backupsitetuff3': ['1.1.7', '2.0.0'],
 'backupsitetuff6': ['1.1.7', '2.0.0'],
 'backupsitetuff9': ['1.1.7', '2.0.0'],
 'bismillahitidakimas': ['1.1.2', '2.0.0'],
 'bomboclatwallahi': ['1.1.2', '2.0.0'],
 'captainindia': ['1.1.2', '2.0.0'],
 'crazynut': ['1.1.2', '2.0.0'],
 'fflc-updated': ['1.1.2', '2.0.0'],
 'howmanygreatbritain': ['1.1.2', '2.0.0'],
 'imillegal1': ['1.1.7', '1.7.7', '2.0.0'],
 'imillegal2': ['1.1.7', '1.7.7', '2.0.0'],
 'imillegal3': ['1.1.7', '1.7.7', '2.0.0'],
 'imillegal4': ['1.1.7', '1.7.7', '2.0.0'],
 'imillegal5': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet1': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet10': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet11': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet12': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet13': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet14': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet15': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet16': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet17': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet18': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet19': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet2': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet20': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet3': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet4': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet5': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet6': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet7': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet8': ['1.1.7', '1.7.7', '2.0.0'],
 'ishowfeet9': ['1.1.7', '1.7.7', '2.0.0'],
 'kirkland': ['1.1.2', '2.0.0'],
 'lowkeybored': ['1.1.2', '2.0.0'],
 'lowkirkuenly': ['1.1.2', '2.0.0'],
 'midnightrush': ['1.1.2', '2.0.0'],
 'miguelphonk': ['1.1.2', '2.0.0'],
 'nottuff1': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff10': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff11': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff12': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff13': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff14': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff15': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff16': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff17': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff18': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff19': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff2': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff20': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff21': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff22': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff23': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff24': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff25': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff26': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff27': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff28': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff29': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff3': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff30': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff4': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff5': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff6': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff7': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff8': ['1.1.7', '1.7.7', '2.0.0'],
 'nottuff9': ['1.1.7', '1.7.7', '2.0.0'],
 'omglucidesotuff': ['1.1.2', '2.0.0'],
 'omgyesyesyes': ['1.1.2', '2.0.0'],
 'pasirianspirit': ['1.1.2', '2.0.0'],
 'ratelimitsucks': ['1.1.2', '1.1.7', '1.7.7', '2.0.0'],
 'ratelimitsucks1': ['1.1.3', '1.1.7', '2.0.0'],
 'ratelimitsucks10': ['1.1.7', '1.7.7', '2.0.0'],
 'ratelimitsucks2': ['1.1.4', '1.1.7', '1.7.7', '2.0.0'],
 'ratelimitsucks3': ['1.1.5', '1.1.7', '2.0.0'],
 'ratelimitsucks4': ['1.1.6', '1.1.7', '2.0.0'],
 'ratelimitsucks5': ['1.1.7', '1.7.7', '2.0.0'],
 'ratelimitsucks6': ['1.1.7', '1.7.7', '2.0.0'],
 'ratelimitsucks9': ['1.1.7', '2.0.0'],
 'sixseven1': ['1.1.7', '1.7.7', '2.0.0'],
 'sixseven10': ['1.7.7'],
 'sixseven2': ['1.1.7', '1.7.7', '2.0.0'],
 'sixseven3': ['1.1.7', '1.7.7', '2.0.0'],
 'sixseven4': ['1.1.7', '1.7.7', '2.0.0'],
 'sixseven5': ['1.1.7', '1.7.7', '2.0.0'],
 'sixseven6': ['1.1.7', '1.7.7', '2.0.0'],
 'sixseven7': ['1.7.7'],
 'sixseven8': ['1.7.7'],
 'sixseven9': ['1.7.7'],
 'speed1': ['1.1.7', '2.0.0'],
 'speed2': ['1.1.7', '2.0.0'],
 'speed3': ['1.1.7', '2.0.0'],
 'speed4': ['1.1.7', '2.0.0'],
 'speed5': ['1.1.7', '2.0.0'],
 'thebigyahu': ['1.1.2', '2.0.0'],
 'timmytuffknuckles3': ['1.1.7', '2.0.0'],
 'timmytuffknuckles6': ['1.1.7', '2.0.0'],
 'timmytuffknuckles9': ['1.1.7', '2.0.0'],
 'whatsadmaidk': ['1.1.2', '2.0.0'],
 'changiairportpromax': ['1.1.3', '2.0.0'],
 'testdonotredeemit': ['1.0.0', '2.0.0', '2.1.1']}

DOMAINS = ['woofbeginner.com',
 'c.vipersfutbol.com',
 'realizationnewestfangs.com',
 'protrafficinspector.com',
 'preferencenail.com',
 'skinnycrawlinglax.com',
 'cdn.conditionfuneral.com',
 'lucideon.top',
 'wisp.breadarchive.dpdns.org',
 '21baseballacademy.com',
 'cdn.21baseballacademy.com',
 'abdct.com',
 'geeked.wtf']

URLS = ['https://cdn.jsdelivr.net/gh/canyoupleasesaysomething/cdn@main/cdn.js',
 'https://cdn.jsdelivr.net/gh/canyoupleasesaysomething/cdn@main/websocket.txt',
 'https://woofbeginner.com/jivd2xu8',
 'https://woofbeginner.com/0a/91/35/0a913561831bdf2c26dcf18b852b5cc1.js',
 'https://wisp.breadarchive.dpdns.org',
 'https://21baseballacademy.com',
 'https://lucideon.top',
 'https://c.vipersfutbol.com/script.js',
 'https://realizationnewestfangs.com',
 'https://protrafficinspector.com/stats',
 'https://preferencenail.com/sfp.js',
 'https://skinnycrawlinglax.com/dnn2hkn8',
 'https://cdn.conditionfuneral.com',
 'https://abdct.com/']

IPS = ['92.38.177.17', '92.38.177.10', '153.75.225.178', '5.188.124.67', '92.38.177.16', '92.38.177.37']

HASHES = ['eb4e1394d537d8eba509dd5c57e7aaf4c1df57715c7161330012a11f6202af84',
 '10ddbbae0070267b8d15888b09a3cdb19fa74d861315b71f21c9ace8b9f85c75',
 '4b188d179e50e8208a6efec85e273e88d8fc390c836f299ba12915e0840408fd']

FILES = ['assets/73sxysj46r.js', 'assets/script.js']

CAMPAIGN_IDENTIFIERS = ['G-0VL3ZSBXDH', '0a913561831bdf2c26dcf18b852b5cc1', 'c6851a038da578a80eeb201e0588c84c']

PUBLISHERS = ['terminal3airport', 'eerikakirk']

REPOSITORIES = ['lucideproxy/svg', 'canyoupleasesaysomething/cdn']

HISTORICAL_DDOS_TARGETS = ['https://cdn.caan.edu/-/?v=']


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
            findings.append({
                "type": "package_version" if matched_versions else "package_name",
                "value": f"{package}@{matched_versions[0]}" if matched_versions else package,
                "path": str(path),
            })
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
                findings.append({"type": selector_type, "value": selector, "path": str(path)})
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
                errors.append(f"{path}:{type(error).__name__}")
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
        print(json.dumps({"status": "collection_failure", "error": "scope is not a readable directory"}))
        return 2
    findings, errors = scan(root)
    payload = {
        "event_id": "lucide-proxy-npm-browser-ddos-campaign",
        "status": "alert" if findings else "clean",
        "finding_count": len(findings),
        "findings": findings,
        "read_errors": errors,
        "interpretation": (
            "A match proves the selector exists in the supplied scope; it does not by itself prove browser execution. "
            "Correlate package/host evidence with deployment, DNS/proxy, browser history, and service-worker records."
        ),
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        try:
            args.out.expanduser().resolve().write_text(encoded + "\n", encoding="utf-8")
        except OSError as error:
            print(json.dumps({"status": "collection_failure", "error": type(error).__name__}))
            return 2
    print(encoded)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
