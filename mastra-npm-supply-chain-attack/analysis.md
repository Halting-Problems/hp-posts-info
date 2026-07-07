---
title: "Mastra npm Supply Chain Attack"
date: 2026-06-17
severity: "critical"
tags:
  - npm
  - supply-chain
  - typosquatting
  - postinstall
  - credential-theft
  - mastra
summary: "On 2026-06-17, public reporting described an @mastra package-scope compromise that pushed easy-day-js as a malicious dependency across 140+ packages, executed a setup.cjs postinstall dropper, and exposed more than 1.1 million weekly downloads to second-stage credential theft and remote code execution behavior."
sourceCount: 4
---

## Executive Summary

On **2026-06-17**, StepSecurity reported a malicious `@mastra` scope compromise that used `easy-day-js` as a typosquat dependency across 140+ packages in the Mastra AI ecosystem [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)]. The published `easy-day-js@1.11.22` release included a `setup.cjs` file and a `postinstall` hook that downloaded and ran a second-stage payload before deleting traces of the install [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)] [[2](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/)].

Snyk's analysis ties the scope access to a dormant contributor account, `ehindero`, and says the Mastra repository itself was verified clean with remediation PR **#18056** [[2](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/)] [[3](https://github.com/mastra-ai/mastra/issues/18045)]. StepSecurity's timeline shows the first observed hit at `@mastra/schema-compat@1.2.12` at **01:12 UTC**, followed by core package exposure across `@mastra/core@1.42.1`, `@mastra/memory@1.20.4`, `@mastra/server@2.1.1`, `@mastra/loggers@1.1.3`, `@mastra/observability@1.14.2`, and `@mastra/deployer@1.42.1` [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)].

This is a publish compromise, not a vulnerable dependency advisory. The right response is to treat affected installs as credential-exposure events, search for package-manager and lifecycle-script traces, and rotate any credentials reachable from environments that installed the affected versions. Public evidence does **not** currently establish a broader named campaign parent with enough confidence to classify this as a campaign child.

The npm registry metadata for `@mastra/core` corroborates that the package exists in the live registry history and helps anchor the affected-scope inventory, but it does not change the core conclusion that the incident was a registry-side publish compromise rather than a source-tree breach [[4](https://registry.npmjs.org/@mastra%2Fcore)].

### Source-Watcher Candidate Queue

**Candidate Id**: mastra-npm-supply-chain-attack

**First Seen**: 2026-06-17

**Decision**: publish_ready

**Dedupe Keys**:
- npm:@mastra
- npm:@mastra/core
- npm:easy-day-js
- package:easy-day-js@1.11.22
- package:@mastra/schema-compat@1.2.12
- payload:setup.cjs

**Starting Sources**:
- StepSecurity primary research
- Snyk primary research
- Mastra GitHub issue #18045
- npm registry metadata for @mastra/core

## Key Facts

**Threat Type**: npm scope compromise, malicious package publish, install-time credential theft

**Ecosystem**: npm

**Registry**: npmjs.com

**Affected Scope**: @mastra

**Source Repository**: mastra-ai/mastra

**Reported Publish Date**: 2026-06-17

**Reported Package Count**: 140+

**Weekly Downloads Exposed**: 1.1M+

**Execution Trigger**: npm `postinstall` lifecycle hook from `easy-day-js@1.11.22`

**Credential Risk**:
- npm publish access
- GitHub tokens
- developer workstation secrets
- CI/CD secrets
- cloud credentials

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| `easy-day-js@1.11.22` was published as the malicious delivery package for the Mastra scope compromise. | confirmed | StepSecurity identifies `easy-day-js@1.11.22` as the malicious package and shows the `setup.cjs` dropper and `postinstall` execution path [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)]. |
| The first observed affected package was `@mastra/schema-compat@1.2.12` at 01:12 UTC. | confirmed | StepSecurity's timeline places the first hit at 01:12 UTC and names `@mastra/schema-compat@1.2.12` explicitly [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)]. |
| The affected scope included core packages such as `@mastra/core`, `@mastra/memory`, `@mastra/server`, `@mastra/loggers`, `@mastra/observability`, and `@mastra/deployer`. | confirmed | StepSecurity lists those package/version pairs in the event timeline [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)]. |
| Snyk attributes the scope access to a dormant contributor account and describes the second-stage payload fetched from attacker infrastructure. | confirmed | Snyk names `ehindero`, describes the `setup.cjs` `postinstall` dropper, and documents the second-stage fetch from `hxxps://23[.]254[.]164[.]92:8000/update/49890878` with SHA256 `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf` [[2](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/)]. |
| The Mastra repository itself was clean and remediation was forward-rolled through PR #18056. | confirmed | Snyk states that `easy-day-js` was removed from npm, `ehindero` is no longer an owner, and clean versions were forward-rolled via PR #18056 [[2](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/)] [[3](https://github.com/mastra-ai/mastra/issues/18045)]. |
| Public sources reviewed here prove a downstream victim count or a broader campaign parent. | not_observed | The reporting confirms scope compromise and install-time execution, but does not establish a verified victim list or a named parent campaign for this Mastra incident. |

## Impact Determination

| Classification | Criteria | Required evidence | Handling decision | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | An affected `@mastra` or `easy-day-js` version is present and install telemetry, process telemetry, or proxy logs show the `postinstall` dropper ran. | Lockfile/cache hit plus npm logs, process telemetry, build logs, proxy logs, or endpoint telemetry. | Isolate the host or runner, preserve package artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, credentials are rotated, and follow-on GitHub/npm/cloud audit checks are clean. |
| Presumed exposed | An affected version was installed on a developer workstation, CI runner, build host, or release environment, but runtime telemetry is incomplete. | Lockfile, package cache, build log, container layer, or package-manager record tied to the exposure window. | Treat npm, GitHub, cloud, and deployment credentials reachable from that environment as exposed. | Owners confirm clean rebuilds and credential rotation or accept documented residual risk. |
| Potentially exposed | Repositories or builds reference `@mastra/*`, but exact resolved versions or install execution are unknown. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Reconstruct package resolution and lifecycle execution before narrowing scope. | Each hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected package names, versions, caches, tarballs, or runtime selectors appear in complete evidence. | Negative repository, CI, package cache, endpoint, and proxy searches. | Preserve the negative search output and keep lifecycle-script controls active. | Evidence coverage includes developer endpoints, CI runners, production builds, and package mirrors. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is missing. | Named gap with owner and retention window. | Keep reachable credentials in scope until evidence or rotation closes the gap. | Missing evidence is recovered or the risk owner accepts uncertainty. |

## Timeline

- **2026-06-16:** StepSecurity reports that `sergey2016` published a clean `easy-day-js@1.11.21` bait package before the malicious release.
- **2026-06-17T01:01 UTC:** `sergey2016` publishes `easy-day-js@1.11.22` with `setup.cjs` and a `postinstall` hook [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)].
- **2026-06-17T01:12 UTC:** `@mastra/schema-compat@1.2.12` is the first observed affected package hit [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)].
- **2026-06-17T01:15–01:20 UTC:** StepSecurity shows core Mastra packages being exposed across the scope [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)].
- **2026-06-17:** Snyk publishes its analysis, notes the dormant contributor account `ehindero`, and confirms PR #18056 forward-rolled clean releases [[2](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/)] [[3](https://github.com/mastra-ai/mastra/issues/18045)].
- **2026-06-17:** This Halting Problems refresh found no existing Mastra slug in the site index and prepared this standalone post.

## Technical Analysis

The compromise path is a registry publish event, not source-tree tampering. Public reporting indicates a dormant contributor account had publish access to the `@mastra` scope, which let the attacker ship a clean bait package first and then publish `easy-day-js@1.11.22` as the malicious delivery package [[1](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js)] [[2](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/)].

The malicious package added a `setup.cjs` file and executed it through `postinstall`. Snyk's analysis says the dropper disabled TLS verification, fetched the second stage from attacker infrastructure, and then deleted traces after execution. The second-stage payload is a cross-platform cryptocurrency wallet stealer and RAT with the SHA256 `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf` [[2](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/)].

Because the payload executes during install, a successful install on a developer workstation, CI runner, or build container should be treated as credential exposure even if the second stage never surfaced in telemetry [[2](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/)]. The absence of a public victim list means we should keep uncertainty explicit rather than overstate downstream impact.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf

### Domains
- setup.cjs

### Urls
- hxxps://23[.]254[.]164[.]92:8000/update/49890878

### Ips
- 23[.]254[.]164[.]92
- 23[.]254[.]164[.]123


## Detection and Hunting

### Hunt Manifest: mastra-npm-supply-chain-attack-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Mastra npm Supply Chain Attack?
- **Telemetry Family:** network
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

DEFAULT_EXCLUDES = {".git", "__pycache__", "dist", "node_modules", "vendor", "build"}

MASTRA_SEARCH_PACKAGES = [
    "easy-day-js",
    "@mastra/schema-compat",
    "@mastra/core",
    "@mastra/memory",
    "@mastra/server",
    "@mastra/loggers",
    "@mastra/observability",
    "@mastra/deployer",
    "create-mastra",
]
MASTRA_PACKAGE_VERSIONS = [
    "easy-day-js@1.11.22",
    "easy-day-js@1.11.21",
    "@mastra/schema-compat@1.2.12",
    "@mastra/core@1.42.1",
    "@mastra/memory@1.20.4",
    "@mastra/server@2.1.1",
    "@mastra/loggers@1.1.3",
    "@mastra/observability@1.14.2",
    "@mastra/deployer@1.42.1",
    "mastra@1.13.1",
    "create-mastra@1.13.1",
]
MASTRA_FILES = [
    "setup.cjs",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "~/.pkg_history",
    "~/.pkg_logs",
]
MASTRA_HASHES = [
    "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf",
]
MASTRA_IPS = [
    "23[.]254[.]164[.]92",
    "23[.]254[.]164[.]123",
]
MASTRA_URLS = [
    "https://23.254.164.92:8000/update/49890878",
]
MASTRA_PROCESS_PATTERNS = [
    "npm install executing postinstall from easy-day-js",
    "node process launched from setup.cjs",
    "package manager lifecycle script execution on an affected Mastra package",
]
MASTRA_NETWORK_PATTERNS = [
    "HTTPS fetch to raw IP 23[.]254[.]164[.]92 on port 8000",
    "outbound request to attacker-controlled stage-two endpoint",
]


def load_iocs(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _unique(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if isinstance(value, str) and value})


def build_indicators(iocs: dict) -> dict:
    section = iocs.get("iocs", {})
    indicators = {
        "package_versions": _unique(section.get("package_versions", [])),
        "files": _unique(section.get("files", [])),
        "hashes": _unique(section.get("hashes", [])),
        "domains": _unique(section.get("domains", [])),
        "urls": _unique(section.get("urls", [])),
        "ips": _unique(section.get("ips", [])),
        "process_patterns": _unique(section.get("process_patterns", [])),
        "network_patterns": _unique(section.get("network_patterns", [])),
    }
    indicators["literal_indicators"] = _unique(
        indicators["package_versions"]
        + indicators["files"]
        + indicators["hashes"]
        + indicators["domains"]
        + indicators["urls"]
        + indicators["ips"]
        + indicators["process_patterns"]
        + indicators["network_patterns"]
        + MASTRA_SEARCH_PACKAGES
        + MASTRA_PACKAGE_VERSIONS
        + MASTRA_FILES
        + MASTRA_HASHES
        + MASTRA_IPS
        + MASTRA_URLS
        + MASTRA_PROCESS_PATTERNS
        + MASTRA_NETWORK_PATTERNS
    )
    return indicators


def scan_text(path: Path, text: str, indicators: dict) -> list[dict]:
    lowered = text.lower()
    hits: list[dict] = []
    for indicator in indicators["literal_indicators"]:
        if indicator.lower() in lowered:
            hits.append({
                "path": str(path),
                "indicator": indicator,
                "kind": "literal",
            })
    return hits


def scan_root(root: Path, indicators: dict) -> list[dict]:
    hits: list[dict] = []
    for current, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDES]
        for filename in filenames:
            file_path = Path(current) / filename
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            hits.extend(scan_text(file_path, content, indicators))
    return hits


def write_outputs(out_dir: Path, matches: list[dict], indicators: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "indicator_count": len(indicators["literal_indicators"]),
        "match_count": len(matches),
        "matches": matches,
    }
    (out_dir / "scan-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "indicators.txt").write_text("\n".join(indicators["literal_indicators"]) + "\n", encoding="utf-8")
    if matches:
        (out_dir / "repository-indicator-matches.txt").write_text(
            "\n".join(f"{item['path']}: found '{item['indicator']}'" for item in matches) + "\n",
            encoding="utf-8",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mastra npm supply-chain hunt script")
    parser.add_argument("root", nargs="?", default=".", help="Directory to scan")
    parser.add_argument("--iocs", default=str(Path(__file__).resolve().parents[1] / "iocs.json"), help="Path to iocs.json")
    parser.add_argument("--out", default=os.environ.get("OUT", "hp-mastra-npm-supply-chain-attack-scope"), help="Output directory")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log root to scan")
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.exists():
        print(f"directory not found: {root}", file=sys.stderr)
        return 2

    iocs = load_iocs(Path(args.iocs))
    indicators = build_indicators(iocs)

    matches = scan_root(root, indicators)
    log_matches: list[dict] = []
    if args.log_root:
        log_root = Path(args.log_root)
        if log_root.exists():
            log_matches = scan_root(log_root, indicators)
            matches.extend(log_matches)

    out_dir = Path(args.out)
    write_outputs(out_dir, matches, indicators)

    print(json.dumps({"match_count": len(matches), "log_match_count": len(log_matches), "out": str(out_dir)}, indent=2))
    return 1 if matches else 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Sources

1. [StepSecurity: Mastra npm Supply Chain Attack: 140+ Packages Backdoored via easy-day-js Typosquat](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js). **Role:** PRIMARY_RESEARCH **Impact:** Documents the malicious `easy-day-js@1.11.22` release, the `setup.cjs` postinstall dropper, the first-hit timeline, and the 140+ package blast radius.
2. [Snyk: A forgotten contributor account compromised the entire Mastra npm package scope](https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/). **Role:** PRIMARY_RESEARCH **Impact:** Describes the dormant contributor access path, the second-stage payload, remediation PR #18056, and the package-scope cleanup.
3. [Mastra GitHub issue #18045](https://github.com/mastra-ai/mastra/issues/18045). **Role:** PRIMARY_RESEARCH **Impact:** Confirms the public remediation discussion and repository-side status that the source tree itself was not the compromise point.
4. [npm registry metadata for @mastra/core](https://registry.npmjs.org/@mastra%2Fcore). **Role:** PRIMARY_RESEARCH **Impact:** Corroborates the live registry package history and anchors the affected-scope inventory.
