---
title: "buffer-utilities: Lazarus Group npm Brandjacking Dropper"
date: 2026-06-18
severity: "high"
tags:
  - npm
  - node
  - supply-chain
  - brandjacking
  - lazarus-group
summary: "Sonatype and JFrog describe buffer-utilities as a malicious npm brandjacking package in a Lazarus Group campaign; the package acts as a dropper that fetches and launches remote payloads."
sourceCount: 3
---

## Executive Summary

This post is a package-level child analysis for the broader Sonatype campaign rather than a stand-alone campaign master. Sonatype says it is tracking a Lazarus Group npm campaign that uses brandjacking names such as `buffer-utilities`, and it describes `buffer-utilities` as a malicious dropper that fetches and executes remote payloads [1]. JFrog independently describes the same package family as a suffix-added lookalike that keeps legitimate `buffer` code while also acting as a dropper and second-stage backdoor [2].

The registry state is also meaningful. The live npm packument for `buffer-utilities` now resolves to a `0.0.1-security` holding release, while the historical time index still records earlier `1.0.0`, `1.1.0`, and `1.1.1` publication timestamps [3]. In this analysis, that makes the package publishable as a child incident report with a clear campaign attachment, but not yet a complete campaign-wide version matrix.

## Key Facts

**Ecosystem:** npm / Node.js

**Primary package:** `buffer-utilities`

**Related brandjacking names called out by Sonatype:** `buffer-util-extend`, `express-denv`, `jwt-path`, `webpack-patch`, `chai-as-patch`, `chai-beta`, and `react-next-dom` [1]

**Observed package behavior:** JFrog describes a postinstall loader that runs immediately after install, disables TLS verification, writes local marker files, downloads a second-stage JavaScript payload, launches it as a detached Node process, and deletes the loader [2]

**Registry status:** current packument shows `latest = 0.0.1-security`; historical time entries remain for `1.0.0`, `1.1.0`, and `1.1.1` [3]

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| Sonatype is tracking a Lazarus Group npm brandjacking campaign and explicitly names `buffer-utilities` as a focal example. | confirmed | Sonatype’s report describes the campaign, the naming tactic, and the `buffer-utilities` case [1]. |
| `buffer-utilities` behaves like a malicious dropper rather than a benign helper package. | confirmed | Sonatype says the package fetches and executes remote payloads; JFrog says it also loads a second-stage backdoor [1][2]. |
| The secondary payload collects host metadata and stage markers. | confirmed | JFrog says it collects hostname, username, operating system, home directory, and process arguments, and creates `.vscode`, `.pkg_history`, and `.pkg_logs` artifacts [2]. |
| The current npm packument no longer exposes the historical malicious versions as active package objects. | confirmed | Live registry review shows only the `0.0.1-security` package object remains while the time index retains older version timestamps [3]. |
| The broader package-version matrix for the full campaign is complete. | not_observed | Public sources in this packet do not provide a full cross-package version matrix [1][2][3]. |

## Impact Determination

| Disposition | When it applies | Required evidence | Handling decision |
| --- | --- | --- | --- |
| Confirmed compromise | An install host or CI runner shows `postinstall`, `node setup.cjs --no-warnings`, `.pkg_history`, `.pkg_logs`, `.vscode`, or second-stage execution traces. | Install logs, process telemetry, filesystem artifacts. | Isolate the host or runner, preserve artifacts, and rebuild from a clean environment. |
| Presumed exposed | `buffer-utilities` or one of the related brandjacking package names appears in a lockfile, manifest, or build log. | Dependency inventory and install-time context. | Treat the environment as exposed until install-time execution is ruled out. |
| Potentially exposed | The package name appears in source notes or documentation, but no install evidence exists. | Repository review and runtime gap statement. | Collect the missing execution evidence before narrowing scope. |
| Not exposed | No package-name match and no loader-marker match are present. | Negative repository, log, and registry review. | Document closure and keep only normal dependency hygiene. |
| Unknown | Version, artifact, or execution evidence is missing. | Named gap and owner. | Keep the incident open until evidence is recovered. |

## Timeline

- **2026-05-30:** The npm packument’s historical time index records `buffer-utilities@1.0.0` [3].
- **2026-06-03:** Sonatype publishes its Lazarus Group npm brandjacking analysis and calls out `buffer-utilities` [1].
- **2026-06-08:** The packument time index records `buffer-utilities@1.1.0` [3].
- **2026-06-09:** The packument time index records `buffer-utilities@1.1.1`, and the packument now resolves to the `0.0.1-security` holding release [3].

## Technical Analysis

Observed behavior first: the package name is a believable suffix-added variant of `buffer`, and JFrog says the malicious version still contains legitimate `buffer` code while also acting as a dropper [1][2]. That is consistent with brandjacking rather than a noisy typosquat. The attacker’s goal appears to be convincing developers that the package belongs in a normal dependency review, then using install-time execution to plant the second stage [1][2].

The second stage is the real risk. JFrog says the loader collects host details, writes marker files, and launches a detached Node process after fetching a remote payload [2]. That means the package can impact anything that runs `npm install`, including local developer machines and CI runners. If the install environment also has cloud credentials, SSH keys, or npm tokens in the home directory or environment, those secrets become downstream targets by exposure rather than by package intent [2].

The registry evidence adds a useful boundary. The current packument now points to `0.0.1-security`, but the historical time entries show that earlier `1.0.0`, `1.1.0`, and `1.1.1` releases existed [3]. That suggests the package was once live and later replaced by a security placeholder, but it does not by itself prove where older tarballs might still be mirrored. That is why the archive-gap question remains open.

### Applicability Decision

- **Developer endpoint module:** applicable. The loader runs during package installation and JFrog says it collects host metadata from the local machine [2].
- **CI/CD module:** applicable when builds or release jobs install dependencies. Any runner that performs `npm install` can execute the loader under the job identity [2].
- **Cloud module:** conditionally applicable. It becomes relevant if the affected endpoint or runner has cloud API keys, cloud SDK credentials, or deployment secrets in its environment or home directory [2].
- **Registry module:** applicable. The package was distributed through npm, and the current packument plus historical time entries are part of the evidence set [3].
- **GitHub module:** not observed in the reviewed sources. No source here ties the package to a malicious repository workflow or GitHub Action.
- **Browser / CDN module:** not applicable in the reviewed sources. The observed behavior is a Node install-time loader, not browser code or CDN abuse.

## Affected Assets and Blast Radius

**Developer endpoints:** Affected if a developer installed the package locally. The malicious loader can run with the user’s home-directory context and touch files under the user profile, which makes workstation secrets and browser-adjacent developer state relevant even though no browser exploit was reported [2].

**CI/CD:** Affected if dependency installation occurred inside build or release jobs. Because the trigger is npm lifecycle execution, the package can inherit CI environment variables and runner-mounted credentials during install [2].

**Cloud and developer credentials:** The reviewed behavior justifies a focused credential review for npm tokens, SSH keys, cloud provider API keys, and any secrets stored in dotfiles or cached tool directories on the same host [2]. That recommendation is evidence-based because the loader enumerates host context and stages additional code from the local machine [2].

**Registries:** The live npm registry state shows the package name is still claimed by a security holder, but the historical version matrix is incomplete in the public sources reviewed here [3]. That means the incident should be treated as a registry-distribution event with an unresolved archive question, not as a fully closed registry cleanup.

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Remediation and Closure

Remove `buffer-utilities` and the related brandjacking lookalikes from dependency graphs, then regenerate lockfiles from a reviewed source. That recommendation is specific to this campaign because the package names are meant to blend into the `buffer` ecosystem, so leaving adjacent names in place preserves the same review blind spot [1].

If the package was installed on a workstation or runner, review that machine for the hidden `.vscode` directory and the `.pkg_history` / `.pkg_logs` marker files before wiping evidence. Those files matter because JFrog describes them as part of the loader’s local trace, and they help establish whether the second stage executed [2].

Replace any npm tokens, SSH keys, or cloud credentials that were present in the installation context. This is not a generic “rotate everything” instruction; it follows directly from the package’s install-time execution model and host-collection behavior [2].

Close the case only after three things are true: the dependency graph is clean, the install host or runner is no longer executing untrusted lifecycle scripts, and the archive-gap question has been answered with either a mirror hit or a documented negative result [2][3].

## Detection and Hunting

### Hunt Manifest: sonatype-2026-003558-buffer-utilities-hunt-1
- **Title:** repository, log, and npm packument scope
- **Question:** Does the telemetry scope contain patterns associated with the buffer-utilities Lazarus Group npm brandjacking campaign?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem, build log export, or npm packument snapshot
- **Positive Signal:** Indicators of compromise matched in telemetry: buffer family package names, install-time loader markers, or historical buffer-utilities registry metadata
- **False Positives:** Benign mentions of buffer-utilities in source notes or the security-holder package can appear after cleanup; confirm with the matching time entries and loader markers before escalating.
- **Classification on Match:** Presumed exposed if only inventory artifacts are present; confirmed compromise if loader markers or staged payload traces appear in the same host or build context.

```py
#!/usr/bin/env python3
"""Audit the buffer-utilities brandjacking campaign for repo, log, and registry evidence.

The script is designed for offline hunts against filesystem exports and for optional
npm packument snapshots. It looks for the package family names Sonatype listed, the
install-time loader markers JFrog described, and the current npm registry state for
buffer-utilities.
"""

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CANDIDATE_ID = "sonatype-2026-003558-buffer-utilities"
CAMPAIGN_ID = "sonatype-2026-003558"
PACKAGE_NAME = "buffer-utilities"
PACKUMENT_URL = "https://registry.npmjs.org/buffer-utilities"
CURRENT_SECURITY_HOLDER_VERSION = "0.0.1-security"
HISTORICAL_VERSIONS = ["1.0.0", "1.1.0", "1.1.1"]
ARCHIVE_URLS = [
    "https://registry.npmjs.org/buffer-utilities",
    "https://registry.npmjs.org/buffer-utilities/-/buffer-utilities-1.0.0.tgz",
    "https://registry.npmjs.org/buffer-utilities/-/buffer-utilities-1.1.0.tgz",
    "https://registry.npmjs.org/buffer-utilities/-/buffer-utilities-1.1.1.tgz",
    "https://registry.npmjs.org/buffer-utilities/-/buffer-utilities-0.0.1-security.tgz",
]
PACKAGE_FAMILY_NAMES = [
    "buffer",
    "buffer-utilities",
    "buffer-util-extend",
    "express-denv",
    "jwt-path",
    "webpack-patch",
    "chai-as-patch",
    "chai-beta",
    "react-next-dom",
]
LOADER_MARKERS = [
    "postinstall",
    "node setup.cjs --no-warnings",
    "setup.cjs",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "fetch(",
    "spawn(process.execPath, ..., detached: true)",
    ".vscode",
    ".pkg_history",
    ".pkg_logs",
]
EXCLUDED_DIR_NAMES = {".git", "node_modules", "dist", "vendor", "__pycache__", ".venv"}
TEXT_SUFFIXES = {
    "",
    ".json",
    ".md",
    ".markdown",
    ".txt",
    ".log",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
    ".js",
    ".cjs",
    ".mjs",
    ".ts",
    ".py",
    ".lock",
}


def _is_text_candidate(path: Path) -> bool:
    if path.name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def scan_tree(root: Path) -> dict[str, Any]:
    """Scan a directory tree for campaign selectors.

    Returns a JSON-serializable summary with hit counts and matching file paths.
    """

    root = root.expanduser().resolve()
    file_hits: list[dict[str, Any]] = []
    hit_terms: set[str] = set()

    if not root.exists():
        return {
            "root": str(root),
            "exists": False,
            "file_hit_count": 0,
            "hit_terms": [],
            "file_hits": [],
        }

    for path in root.rglob("*"):
        if path.is_dir() or any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        if not _is_text_candidate(path):
            continue
        text = _read_text(path)
        matches = []
        for term in [*PACKAGE_FAMILY_NAMES, *LOADER_MARKERS]:
            if term.lower() in text.lower():
                matches.append(term)
                hit_terms.add(term)
        if matches:
            file_hits.append({"path": str(path), "terms": sorted(set(matches))})

    return {
        "root": str(root),
        "exists": True,
        "file_hit_count": len(file_hits),
        "hit_terms": sorted(hit_terms),
        "file_hits": file_hits,
    }


def load_packument(source: str) -> dict[str, Any]:
    """Load a packument JSON document from a path or URL."""

    source = source.strip()
    if not source:
        raise ValueError("empty packument source")

    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=30) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))

    path = Path(source).expanduser()
    return json.loads(path.read_text(encoding="utf-8"))


def summarize_packument(packument: dict[str, Any]) -> dict[str, Any]:
    versions = packument.get("versions") or {}
    time_map = packument.get("time") or {}
    historical_versions = [version for version in HISTORICAL_VERSIONS if version in time_map]
    missing_version_objects = [version for version in historical_versions if version not in versions]

    return {
        "name": packument.get("name", PACKAGE_NAME),
        "latest": (packument.get("dist-tags") or {}).get("latest", "unknown"),
        "time_entries": {version: time_map.get(version, "unknown") for version in [*HISTORICAL_VERSIONS, CURRENT_SECURITY_HOLDER_VERSION]},
        "historical_versions": historical_versions,
        "missing_version_objects": missing_version_objects,
        "present_versions": sorted(versions.keys()),
    }


def probe_url(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return {"url": url, "status": response.status, "reason": "reachable"}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code, "reason": exc.reason}
    except Exception as exc:  # pragma: no cover - network and resolver failures are environment-specific
        return {"url": url, "status": "error", "reason": str(exc)}


def build_report(scan_root: Path, packument_source: str | None, probe_tarballs: bool) -> dict[str, Any]:
    report: dict[str, Any] = {
        "candidate_id": CANDIDATE_ID,
        "campaign_id": CAMPAIGN_ID,
        "package_name": PACKAGE_NAME,
        "registry": {"packument_url": PACKUMENT_URL, "current_security_holder_version": CURRENT_SECURITY_HOLDER_VERSION},
        "scan": scan_tree(scan_root),
    }

    if packument_source:
        packument = load_packument(packument_source)
        summary = summarize_packument(packument)
        report["packument"] = summary
        report["packument_source"] = packument_source

        if probe_tarballs:
            report["tarball_probes"] = [probe_url(url) for url in ARCHIVE_URLS]
    else:
        report["packument"] = {
            "name": PACKAGE_NAME,
            "latest": "unknown",
            "time_entries": {},
            "historical_versions": [],
            "missing_version_objects": [],
            "present_versions": [],
        }
        if probe_tarballs:
            report["tarball_probes"] = [probe_url(url) for url in ARCHIVE_URLS]

    report["interpretation"] = {
        "campaign_match": bool(report["scan"]["file_hit_count"]),
        "registry_artifact_gap": bool(report.get("packument", {}).get("missing_version_objects")),
        "archive_probe_gap": any(entry.get("status") == 404 for entry in report.get("tarball_probes", [])),
    }
    return report


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="directory tree to scan")
    parser.add_argument("--packument", help="path or URL to a npm packument JSON snapshot")
    parser.add_argument("--probe-tarballs", action="store_true", help="probe known tarball URLs with HEAD requests")
    parser.add_argument("--out", default=f"hp-{CANDIDATE_ID}-scope", help="output directory for JSON artifacts")
    args = parser.parse_args(argv)

    scan_root = Path(args.root).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report = build_report(scan_root, args.packument, args.probe_tarballs)
    write_text(out_dir / "report.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_text(out_dir / "selectors.txt", "\n".join([*PACKAGE_FAMILY_NAMES, *LOADER_MARKERS]) + "\n")

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Sources

1. [Sonatype: Lazarus Group's Latest: Brandjacking Campaign on npm](https://www.sonatype.com/blog/lazarus-groups-latest-brandjacking-campaign-on-npm) — **Role:** PRIMARY_RESEARCH — **Impact:** Names the campaign, the brandjacking tactic, and the `buffer-utilities` focal package.
2. [JFrog Security Research: easy-day-js: Supply Chain Campaign Targets Mastra npm Packages](https://research.jfrog.com/post/easy-day-js/) — **Role:** PRIMARY_RESEARCH — **Impact:** Provides the install-time loader behavior, host-collection details, and second-stage execution pattern for `buffer-utilities`.
3. [npm registry packument for buffer-utilities](https://registry.npmjs.org/buffer-utilities) — **Role:** PRIMARY_SOURCE — **Impact:** Confirms the current security-holder state and historical publication timestamps for the package.
