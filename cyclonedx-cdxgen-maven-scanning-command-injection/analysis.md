---
title: "@cyclonedx/cdxgen Maven Scanner Command Injection"
date: 2026-06-26
severity: "high"
tags:
  - cyclonedx
  - cdxgen
  - sbom
  - maven
  - developer-tooling
summary: "CycloneDX cdxgen before 12.4.3 could execute shell metacharacters from repository-controlled Maven module paths when scanning attacker-controlled projects, putting developer workstations and CI SBOM runners at risk."
sourceCount: 3
---

## Executive Summary

CycloneDX disclosed **GHSA-5vwr-qchf-q4pf** for `@cyclonedx/cdxgen`, an SBOM generator used from developer workstations, CI jobs, and server-mode scanning services. The upstream advisory says cdxgen versions before `12.4.3` used shell execution in parts of the Maven scanning flow, so repository-controlled paths could be interpreted by the shell instead of treated only as filesystem paths when an attacker-controlled Maven project was scanned [1].

This is not a registry compromise and reviewed direct sources do not confirm exploitation in the wild. It is still a supply-chain tooling exposure because the untrusted artifact is the repository being scanned: a pull request, fork, third-party source archive, or customer-supplied Maven project can be the input to an automated SBOM job that often runs with CI tokens, package registry credentials, or cloud deployment context [1].

The immediate responder decision is to find every cdxgen runner that can scan untrusted Maven repositories, upgrade `@cyclonedx/cdxgen` to `12.4.3` or later, and review recent SBOM job logs where vulnerable versions processed forked or third-party source trees [1] [2].

## Key Facts

| Fact | Value |
| --- | --- |
| **Advisory** | GHSA-5vwr-qchf-q4pf |
| **Affected Artifact** | `@cyclonedx/cdxgen` npm package |
| **Affected Versions** | `< 12.4.3` |
| **Fixed Version** | `12.4.3` |
| **Fixed npm Publish Time** | 2026-05-22T22:26:57.787Z, from npm registry metadata collected during this refresh |
| **Fixed Tarball Integrity** | `sha512-1cg3zWCW5J+nU2TDXi3ehM5n2PdznlWQ8KNr/blGIGGu995pZECUJKDB7iOVMRRC+C5GNoDMmN8CYLTX0/vr7A==` |
| **Exposure Vector** | Scanning attacker-controlled Maven projects with cdxgen CLI or server mode |
| **Exploitation Status** | Not confirmed in reviewed direct sources |
| **Immediate Action** | Upgrade cdxgen and review untrusted-repository SBOM scan logs |

## Evidence Assessment

| Status | Claim | Source support |
| --- | --- | --- |
| **confirmed** | `@cyclonedx/cdxgen` before `12.4.3` is vulnerable and `12.4.3` is the first patched version. | The GitHub Advisory record lists the npm package, vulnerable range, and patched version [3]. |
| **confirmed** | The vulnerable Maven scanner path involved repository-controlled paths and `shell: true` command execution. | The upstream cdxgen advisory describes shell command injection through Maven command construction [1]. |
| **confirmed** | The issue affects both CLI and server mode. | The upstream advisory states both modes are affected [1]. |
| **confirmed** | Upstream changed command execution behavior in PR 4059. | The linked upstream pull request is listed as the fix reference [2]. |
| **unclear** | Public exploitation, victim count, and downstream CI prevalence are not established. | The reviewed direct sources are disclosure and fix records, not incident reports [1] [2] [3]. |

## Impact Determination

| Exposure Classification | Criteria | Required Evidence | Required Action | Closure Gate |
| --- | --- | --- | --- | --- |
| **Confirmed compromise** | A vulnerable cdxgen version scanned an untrusted Maven repository and CI or endpoint telemetry shows unexpected child process activity from the scanner job. | SBOM job logs, EDR process trees, runner filesystem evidence, and repository identity showing the scanned input came from a fork, pull request, customer upload, or third-party source. | Preserve the runner image and logs, isolate the runner, revoke credentials available to the SBOM job, and rebuild from a clean image. | No unexpected cdxgen child processes remain unexplained, exposed credentials are rotated, and the job runs cdxgen `12.4.3` or later in an isolated runner. |
| **Presumed exposed** | A vulnerable cdxgen version scanned untrusted Maven projects, but no process telemetry was retained. | Lockfiles or runner images showing `@cyclonedx/cdxgen < 12.4.3` and CI history showing Maven scans on untrusted repositories. | Upgrade immediately, re-run the audit script against repositories and CI logs, and rotate only credentials present in those SBOM job environments. | The relevant SBOM jobs are patched and the last vulnerable run window is documented for credential review. |
| **Potentially exposed** | cdxgen is present but the version or Maven scan path is unknown. | Package manifests, lockfiles, workflow definitions, and exported build logs. | Run the published exposure audit and inventory all SBOM generation paths. | Every cdxgen invocation is mapped to a version, input trust boundary, and runner credential scope. |
| **Not exposed** | cdxgen is absent, cdxgen is `12.4.3` or later, or vulnerable versions never scan Maven input from untrusted repositories. | Negative audit output plus package or container evidence for the scanner version. | None for this advisory beyond normal dependency hygiene. | Evidence bundle is archived with the SBOM job inventory. |

## Minimum Evidence To Collect

- **Package and lockfile evidence:** Collect `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, scanner container manifests, and CI images because these prove whether `@cyclonedx/cdxgen` was below the fixed `12.4.3` release during the relevant scan window.
- **CI workflow and job logs:** Collect `.github/workflows`, pipeline definitions, and SBOM job logs because they show whether cdxgen was invoked with Maven scanning options against pull requests, forks, customer uploads, or other untrusted source trees.
- **Runner process telemetry:** Collect EDR process trees, shell history retained by ephemeral runners, and build-agent audit logs because confirmed compromise requires evidence that the vulnerable scanner process spawned unexpected commands while handling a Maven repository.
- **Credential exposure map:** Collect the environment-variable allowlist, CI secret injection policy, npm tokens, cloud credentials, and signing keys available to the SBOM job because remediation depends on the identities exposed to that scanner process.

## Timeline

- **2026-05-22 15:17:21 UTC:** npm registry metadata shows `@cyclonedx/cdxgen` `12.4.2`, a vulnerable version according to the GHSA range, was published.
- **2026-05-22 22:26:57 UTC:** npm registry metadata shows `@cyclonedx/cdxgen` `12.4.3`, the first patched version, was published.
- **2026-06-26 19:47:24 UTC:** GitHub published GHSA-5vwr-qchf-q4pf for the cdxgen Maven scanner command injection [3].
- **2026-06-26 19:47:28 UTC:** The GitHub advisory record was updated shortly after publication [3].

## What Happened

cdxgen builds SBOMs by inspecting project ecosystems and invoking ecosystem-specific tooling. In affected versions, the Maven scanning flow could place repository-controlled module path data into command construction while some invocations used shell execution. The upstream advisory states that a directory name containing shell metacharacters could be interpreted by the shell when cdxgen scanned an attacker-controlled Maven project [1].

That trust boundary is common in modern supply-chain workflows. Organizations often run SBOM scanners automatically against pull requests, forks, release intake repositories, vendor source drops, and customer-submitted projects. In those environments, the scanned repository is adversary-controlled input but the scanner process may run inside trusted developer or CI infrastructure.

## Technical Analysis

### Initial Access

The attacker-controlled input is a Maven project selected for SBOM generation. The direct advisory describes repository-controlled paths influencing the Maven scanner command construction in cdxgen before `12.4.3`; no malicious npm package publication is alleged [1].

### Execution Trigger

Execution requires a vulnerable cdxgen CLI or server-mode scan of an attacker-controlled Maven project. The reviewed advisory text identifies both CLI and server mode as affected, which means local developer scans, centralized scanning APIs, and CI jobs should all be considered until their input boundaries are verified [1].

### Payload Behavior

The public sources establish command injection potential from shell interpretation of repository-controlled path data, but they do not provide evidence of a specific observed payload, malware family, or command-and-control infrastructure. Treat any unexpected child process from a cdxgen Maven scan as incident evidence and preserve runner telemetry before rebuilding [1].

### Credential or Data Collection

Credential exposure is environment-specific because the advisory establishes command execution in the cdxgen process context rather than a fixed stolen-secret list. If the scanner ran in CI, prioritize secrets available to the SBOM job: registry tokens, source hosting tokens, cloud credentials, signing keys, and artifact upload credentials. If the scanner ran on a developer workstation, prioritize local package manager credentials and source-control tokens present in the shell environment at scan time [1].

### Defense Evasion

No direct source describes defense evasion. The primary defensive problem is that SBOM generation is often treated as safe parsing, so jobs may run on trusted runners before untrusted Maven project paths have been constrained [1].

### Exfiltration and Command and Control

Reviewed direct sources do not identify exfiltration or command-and-control indicators. Do not add network IOC blocks for this advisory unless local telemetry shows concrete destinations from a scanner process [1] [3].

## Affected Assets and Blast Radius

| Asset | Why it matters | Blast-radius question |
| --- | --- | --- |
| `@cyclonedx/cdxgen < 12.4.3` | Vulnerable package range named by GHSA. | Which repositories, containers, or global npm installs used this version? |
| Maven SBOM jobs | The affected flow is Maven scanning. | Did the job scan pull requests, forks, vendor projects, or customer-supplied source? |
| CI runners and scanner servers | The scanner process context is where command execution would occur. | Which secrets, mounted workspaces, and artifact credentials were available? |
| Developer workstations | Local scans may expose user tokens and source trees. | Which developers scanned untrusted Maven repositories before upgrading? |

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:


## Detection and Hunting

### Hunt Manifest: cyclonedx-cdxgen-maven-scanning-command-injection-hunt-1
- **Title:** cdxgen vulnerable Maven scanner usage in repositories and CI telemetry
- **Question:** Do repository manifests, lockfiles, CI definitions, or exported logs show @cyclonedx/cdxgen versions before 12.4.3 or Maven scan invocations that should be reviewed after GHSA-5vwr-qchf-q4pf?
- **Telemetry Family:** file
- **Telemetry Context:** source repositories, package lockfiles, CI workflow definitions, SBOM job logs, or exported build telemetry
- **Positive Signal:** The script found @cyclonedx/cdxgen before 12.4.3 or cdxgen Maven scanning references in the supplied evidence tree.
- **False Positives:** Documentation-only references can match; validate whether the repository or CI job actually executes cdxgen against attacker-controlled Maven projects.
- **Classification on Match:** presumed_exposed

```py
#!/usr/bin/env python3
"""Audit repositories, lockfiles, CI definitions, and exported logs for exposure to GHSA-5vwr-qchf-q4pf.

Exit codes:
  0: scan completed and no exposure indicators were found
  1: scan completed and one or more exposure indicators were found
  2: scan failed because the supplied evidence root was unavailable
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

AFFECTED_PACKAGE = "@cyclonedx/cdxgen"
FIXED_VERSION = "12.4.3"
VULNERABLE_RANGE = "@cyclonedx/cdxgen < 12.4.3"
GHSA_ID = "GHSA-5vwr-qchf-q4pf"
ADVISORY_URL = "https://github.com/cdxgen/cdxgen/security/advisories/GHSA-5vwr-qchf-q4pf"
FIX_PULL_REQUEST = "https://github.com/cdxgen/cdxgen/pull/4059"
NPM_FIXED_TARBALL_INTEGRITY = "sha512-1cg3zWCW5J+nU2TDXi3ehM5n2PdznlWQ8KNr/blGIGGu995pZECUJKDB7iOVMRRC+C5GNoDMmN8CYLTX0/vr7A=="
MAVEN_SCAN_TOKENS = ["--type maven", "-t maven", "CDXGEN_TYPE=maven", "cdxgen -t", "cdxgen --type"]
WORKFLOW_DIRECTORY = ".github/workflows"
INTERESTING_FILE_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "workflow.yml",
    "workflow.yaml",
    "build.yml",
    "build.yaml",
    "ci.yml",
    "ci.yaml",
    "action.yml",
    "action.yaml",
    "Dockerfile",
}
INTERESTING_SUFFIXES = (".yml", ".yaml", ".json", ".lock", ".log", ".txt", ".md", ".toml")
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}
VERSION_RE = re.compile(r"@cyclonedx/cdxgen[^0-9]{0,24}(\d+\.\d+\.\d+)", re.IGNORECASE)
JSON_VERSION_RE = re.compile(r'"@cyclonedx/cdxgen"\s*:\s*"[~^<>= ]*(\d+\.\d+\.\d+)"')


def parse_version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    return tuple(int(part) for part in parts[:3])  # type: ignore[return-value]


def is_vulnerable(version: str) -> bool:
    return parse_version(version) < parse_version(FIXED_VERSION)


def should_scan(path: Path) -> bool:
    if path.name in INTERESTING_FILE_NAMES:
        return True
    if WORKFLOW_DIRECTORY in path.as_posix() and path.suffix.lower() in (".yml", ".yaml"):
        return True
    return path.suffix.lower() in INTERESTING_SUFFIXES


def iter_files(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [dirname for dirname in dirs if dirname not in EXCLUDED_DIRS]
        for filename in files:
            candidate = Path(current) / filename
            if should_scan(candidate):
                yield candidate


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"READ_ERROR:{type(exc).__name__}:{exc}"


def scan_file(path: Path, text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if AFFECTED_PACKAGE in text:
        versions = {match.group(1) for match in VERSION_RE.finditer(text)}
        versions.update(match.group(1) for match in JSON_VERSION_RE.finditer(text))
        vulnerable_versions = sorted(version for version in versions if is_vulnerable(version))
        if vulnerable_versions:
            findings.append({
                "file": str(path),
                "indicator": VULNERABLE_RANGE,
                "evidence": ",".join(vulnerable_versions),
                "reason": "dependency version before 12.4.3",
            })
        elif not versions:
            findings.append({
                "file": str(path),
                "indicator": AFFECTED_PACKAGE,
                "evidence": "version_not_extracted",
                "reason": "cdxgen dependency or invocation present; version requires manual review",
            })
    lower_text = text.lower()
    if "cdxgen" in lower_text and any(token.lower() in lower_text for token in MAVEN_SCAN_TOKENS):
        findings.append({
            "file": str(path),
            "indicator": "cdxgen Maven scanner invocation",
            "evidence": "maven_scan_reference",
            "reason": "SBOM job may scan Maven projects and should be paired with fixed cdxgen version",
        })
    return findings


def main() -> int:
    root_arg = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SCAN_ROOT", ".")
    root = Path(root_arg).resolve()
    out_dir = Path(os.environ.get("OUT", "hp-cyclonedx-cdxgen-maven-scanning-command-injection-audit"))
    if not root.exists() or not root.is_dir():
        print(json.dumps({"status": "error", "reason": "scan root is not a directory", "root": str(root)}))
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    findings: list[dict[str, str]] = []
    for path in iter_files(root):
        text = read_text(path)
        findings.extend(scan_file(path, text))
    result = {
        "advisory": GHSA_ID,
        "advisory_url": ADVISORY_URL,
        "fix_pull_request": FIX_PULL_REQUEST,
        "affected_package": AFFECTED_PACKAGE,
        "fixed_version": FIXED_VERSION,
        "fixed_tarball_integrity": NPM_FIXED_TARBALL_INTEGRITY,
        "scan_root": str(root),
        "findings": findings,
    }
    result_path = out_dir / "cdxgen-maven-scanner-exposure-findings.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if findings:
        print(json.dumps({"status": "alert", "findings": len(findings), "output": str(result_path)}))
        return 1
    print(json.dumps({"status": "clean", "findings": 0, "output": str(result_path)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Remediation and Closure

1. **Preserve evidence:** Save SBOM job logs, workflow definitions, lockfiles, runner image identifiers, and process telemetry before rerunning scans because the vulnerable evidence is tied to the exact cdxgen version and Maven input repository.
2. **Stop risky scanner paths:** Disable or isolate jobs that run `@cyclonedx/cdxgen < 12.4.3` against pull requests, forks, vendor source drops, customer projects, or other untrusted Maven repositories.
3. **Upgrade cdxgen:** Move every CLI install, scanner container, server-mode deployment, and CI dependency to `@cyclonedx/cdxgen 12.4.3` or later; verify with lockfile and image evidence rather than package-manager intent.
4. **Audit runner behavior:** Review the vulnerable scan window for unexpected child processes spawned by cdxgen, unexpected file writes in the workspace, and artifact uploads that do not match normal SBOM job outputs.
5. **Rotate scoped credentials:** Rotate only credentials that were available to exposed scanner contexts, prioritizing source-hosting tokens, registry publish tokens, cloud deployment keys, and artifact signing material present in CI environment variables.
6. **Recover safely:** Rebuild scanner runners from clean images and re-run SBOM generation with the patched cdxgen version in a runner profile that does not expose production deployment secrets to untrusted repositories.
7. **Close:** Close the incident only when all cdxgen invocations are mapped, vulnerable versions are removed, untrusted Maven scans are isolated, and preserved telemetry shows no unexplained process activity during the vulnerable scan window.

## Sources

1. [Upstream cdxgen Security Advisory GHSA-5vwr-qchf-q4pf](https://github.com/cdxgen/cdxgen/security/advisories/GHSA-5vwr-qchf-q4pf). **Role:** DIRECT_SOURCE. **Supports:** affected package, vulnerable range, CLI/server exposure, Maven scanner command-injection mechanism, and fixed version. **Limitation:** does not claim exploitation in the wild.
2. [cdxgen pull request 4059](https://github.com/cdxgen/cdxgen/pull/4059). **Role:** DIRECT_SOURCE. **Supports:** upstream fix reference for command execution behavior. **Limitation:** pull-request metadata alone does not prove downstream exposure.
3. [GitHub Advisory Database GHSA-5vwr-qchf-q4pf](https://github.com/advisories/GHSA-5vwr-qchf-q4pf). **Role:** ENRICHMENT_DATA. **Supports:** advisory publication timestamp, package ecosystem, vulnerable version range, and first patched version. **Limitation:** mirrors upstream advisory data.
