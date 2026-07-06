---
title: "pnpm Package-Manager Supply-Chain Advisory Batch"
date: 2026-06-27
severity: "high"
tags:
  - pnpm
  - npm
  - package-manager
  - lockfile-integrity
  - ci-cd
summary: "pnpm disclosed a cluster of package-manager vulnerabilities affecting lockfile integrity, Git dependency fetching, repository registry configuration, patch application, and symlink creation; responders should inventory vulnerable pnpm versions and review credential-bearing install paths."
sourceCount: 8
---

## Executive Summary

The pnpm project published a cluster of GitHub Security Advisories covering package-manager behavior that matters directly to supply-chain defense: lockfile integrity gaps, Git dependency trust, repository-controlled registry configuration, patch-file path traversal, and dependency alias path traversal. The highest-severity entries in the reviewed batch are `GHSA-hwx4-2j3j-g496`, `GHSA-cjhr-43r9-cfmw`, and `GHSA-rxhj-4m44-96r4`, all of which affect pnpm install flows that commonly run inside developer workstations and CI runners [5] [6] [7].

This is not a confirmed registry compromise and the reviewed direct sources do not report exploitation in the wild. It is still a high-signal dependency-ecosystem exposure because an attacker-controlled repository, lockfile, package metadata response, `.npmrc`, Git dependency, or patch file can become input to a trusted package-manager process with access to npm tokens, private registry credentials, source-hosting tokens, cloud environment variables, or release artifacts [1] [2] [3] [4] [5] [6] [7] [8].

The conservative response is to move pnpm users to fixed baselines that cover the full disclosed batch: `10.34.2` or later on pnpm 10.x and `11.5.3` or later on pnpm 11.x. Then review recent credential-bearing installs that processed untrusted pull requests, forks, third-party source drops, repository `.npmrc` files, patch files, Git dependencies, or mutable/private registry responses while running affected pnpm versions [6] [7] [8].

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected Artifact** | `pnpm` npm package / pnpm CLI |
| **Ecosystem** | npm, Node.js package-manager tooling |
| **Advisories Reviewed** | `GHSA-hg3w-7f8c-63hp`, `GHSA-54hh-g5mx-jqcp`, `GHSA-q6j5-fjx5-2mc3`, `GHSA-p4xf-rf54-rj3x`, `GHSA-hwx4-2j3j-g496`, `GHSA-cjhr-43r9-cfmw`, `GHSA-rxhj-4m44-96r4`, `GHSA-3qhv-2rgh-x77r` |
| **Conservative Affected Baseline** | pnpm `< 10.34.2`; pnpm `>= 11.0.0 < 11.5.3` |
| **Most Relevant Fixed Baselines** | pnpm `10.34.2` for 10.x; pnpm `11.5.3` for 11.x |
| **Exposure Window** | Advisories were published from 2026-05-25 through 2026-06-10 and updated through mid-June 2026 |
| **Exploitation Status** | Not confirmed in reviewed direct sources |
| **Immediate Action** | Upgrade pnpm, inventory untrusted install inputs, and audit registry-auth and CI logs for affected install paths |

## Evidence Assessment

| Status | Claim | Source support |
| --- | --- | --- |
| **confirmed** | pnpm lockfiles did not store a hash for GitHub `codeload.github[.]com` Git dependency tarballs in affected ranges. | `GHSA-hg3w-7f8c-63hp` lists `pnpm` vulnerable ranges `<10.33.4` and `>=11.0.0 <11.0.7` and describes the missing tarball hash behavior [1]. |
| **confirmed** | Plain `pnpm install` in non-frozen mode could accept changed registry package content by repairing the lockfile integrity after an initial mismatch. | `GHSA-54hh-g5mx-jqcp` describes the default integrity-check behavior and lists patched ranges `>=10.34.0 <11.0.0` and `>=11.4.0` [2]. |
| **confirmed** | pnpm could skip tarball verification when a lockfile resolution omitted the `integrity` field. | `GHSA-q6j5-fjx5-2mc3` describes the missing-integrity fail-open path and lists fixed ranges `>=10.34.1 <11.0.0` and `>=11.4.0` [3]. |
| **confirmed** | Lockfile-controlled Git `resolution.commit` values could be passed to Git fetch/checkout paths without commit-format validation. | `GHSA-p4xf-rf54-rj3x` describes the Git fetch argument injection condition and its practical emphasis on SSH or local Git transports [4]. |
| **confirmed** | Registry package metadata could create dependency aliases with path traversal segments that later influence project-local symlink/link targets. | `GHSA-hwx4-2j3j-g496` describes alias path traversal and examples such as `.git/hooks`, local actions, `scripts/`, `tools/`, `bin/`, `tests/`, `dist/`, and `node_modules/.bin` [5]. |
| **confirmed** | Repository-local `.npmrc` configuration could bind user-level unscoped npm auth credentials to a repository-selected registry. | `GHSA-cjhr-43r9-cfmw` describes pnpm sending a user-level unscoped `_authToken` to a registry selected by repository configuration in reproduced cases [6]. |
| **confirmed** | Malicious patch files referenced by pnpm patching configuration could write/delete outside the intended package directory through path traversal in diff headers. | `GHSA-rxhj-4m44-96r4` describes arbitrary file write/delete via `.patch` path traversal during pnpm patch application [7]. |
| **confirmed** | Repository config could expand victim environment secrets into registry requests before scripts run. | `GHSA-3qhv-2rgh-x77r` describes repository `.npmrc` environment expansion into registry/auth destinations and lists fixed pnpm ranges `>=10.34.2 <11.0.0` and `>=11.5.3` [8]. |
| **unclear** | Public exploitation, victim count, and downstream incident count are not established. | The reviewed sources are direct advisories and reproduced behavior descriptions, not incident-response reports [1] [2] [3] [4] [5] [6] [7] [8]. |

## Impact Determination

| Exposure Classification | Criteria | Required Evidence | Required Action | Closure Gate |
| --- | --- | --- | --- | --- |
| **Confirmed compromise** | A vulnerable pnpm version processed attacker-controlled install input and telemetry shows unexpected file writes, symlink replacement, Git option execution, registry credential transmission, or changed tarball content. | pnpm version evidence, repository or CI input identity, `.npmrc`/lockfile/patch/Git dependency evidence, process telemetry, filesystem diffs, registry access logs, and package-manager logs. | Preserve the workspace and runner image, isolate the affected runner or workstation, revoke credentials visible to that install, and rebuild with patched pnpm. | Affected pnpm paths run fixed versions, exposed credentials are rotated, registry logs show no unresolved suspicious token use, and filesystem changes are explained. |
| **Presumed exposed** | Vulnerable pnpm ran on untrusted pull requests, forks, third-party source drops, mutable registry sources, repository `.npmrc` files, Git dependencies, or patch files, but runtime telemetry is incomplete. | `packageManager` fields, Corepack configuration, CI setup steps, package-manager logs, lockfiles, patch files, `.npmrc`, and registry proxy logs. | Upgrade to pnpm `10.34.2`/`11.5.3` or later, disable untrusted install flows until patched, and perform scoped credential and filesystem review. | Every install path has a version, input-trust boundary, and credential exposure decision. |
| **Potentially exposed** | pnpm appears in repositories or build images, but version and input trust boundary are unknown. | Source inventory, runner images, workflow definitions, build logs, and package-manager caches. | Run the published exposure audit, then prioritize any hits that combine vulnerable versions with credentials or untrusted input. | All pnpm usage is mapped to fixed, vulnerable-but-not-exposed, or exposed. |
| **Not exposed** | pnpm is absent, fixed versions were used, or vulnerable versions only processed trusted internal sources without repository-selected registries, patch files, Git dependencies, or mutable registry responses. | Negative audit output plus source/build evidence for version and input boundary. | No incident response beyond normal dependency hygiene and package-manager hardening. | Evidence bundle is retained with the package-manager inventory. |

## Minimum Evidence To Collect

- **Package-manager version evidence:** Collect `package.json` `packageManager` fields, Corepack pins, `pnpm/action-setup` configuration, runner images, shell history, and package-manager logs because the response hinges on whether pnpm was below `10.34.2` or in the vulnerable 11.x ranges [1] [2] [3] [4] [5] [6] [7] [8].
- **Repository-controlled install inputs:** Collect `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `.npmrc`, patch files, Git dependency declarations, and CI workflow files because the advisories require input that pnpm consumes during resolution, fetch, auth binding, patch application, or linking [4] [5] [6] [7] [8].
- **Registry and proxy evidence:** Collect private registry access logs, npm proxy logs, and package metadata/tarball cache records because the credential-binding and integrity advisories can only be dispositioned if you know which registry served metadata and where credentials were sent [2] [3] [6] [8].
- **CI and workstation telemetry:** Collect process trees, filesystem modification logs, runner workspace snapshots, and Git command logs because confirmed compromise requires evidence of symlink replacement, patch traversal writes/deletes, Git argument injection, or unexpected files created during the install [4] [5] [7].
- **Credential scope map:** Collect the environment variables, npm auth tokens, GitHub tokens, deployment keys, cloud credentials, and artifact-publishing credentials available to each install job because remediation should rotate credentials exposed to vulnerable install contexts rather than indiscriminately rotate unrelated secrets [6] [8].

## Timeline

- **2026-05-25 09:07:31 UTC:** GitHub published `GHSA-hg3w-7f8c-63hp` for missing lockfile hashes on GitHub Git dependency tarballs [1].
- **2026-05-28 12:47:42 UTC:** GitHub published `GHSA-54hh-g5mx-jqcp` for unsafe default behavior that could accept changed package content after an integrity mismatch [2].
- **2026-05-28 12:47:48 UTC:** GitHub published `GHSA-p4xf-rf54-rj3x` for Git fetch argument injection through lockfile `resolution.commit` [4].
- **2026-05-28 12:47:53 UTC:** GitHub published `GHSA-q6j5-fjx5-2mc3` for missing lockfile integrity verification [3].
- **2026-05-28 12:48:26 UTC:** GitHub published `GHSA-hwx4-2j3j-g496` for dependency alias path traversal and project path override via symlink replacement [5].
- **2026-05-28 12:48:35 UTC:** GitHub published `GHSA-cjhr-43r9-cfmw` for repository-selected registry credential binding [6].
- **2026-05-28 12:48:46 UTC:** GitHub published `GHSA-rxhj-4m44-96r4` for arbitrary file write/delete through malicious patch path traversal [7].
- **2026-06-10 23:39:06 UTC:** GitHub published `GHSA-3qhv-2rgh-x77r` for repository config expanding environment secrets into registry requests before scripts run [8].

## What Happened

The direct advisories describe flaws in pnpm behavior at the boundary between trusted package-manager execution and untrusted repository or registry input. Several issues are integrity and provenance problems: GitHub Git dependency tarballs lacked stored hashes, missing lockfile integrity could skip verification, and non-frozen installs could repair to new registry content instead of failing hard by default [1] [2] [3].

Other issues move from integrity into execution or credential exposure. A lockfile-controlled Git commit value could be parsed as an option in shallow Git fetch paths, dependency alias metadata could influence project-local symlink targets, patch files could traverse outside the intended package directory, and repository configuration could direct user or environment credentials toward registry requests [4] [5] [6] [7] [8].

For defenders, the important distinction is that the package being installed does not need to be a known malicious package for exposure to exist. A pull request, fork, vendor source drop, internal test fixture, mutable private registry response, or repository `.npmrc` can be enough to put a trusted pnpm process in contact with attacker-controlled install input [4] [5] [6] [7] [8].

## Technical Analysis

### Initial Access

The attacker-controlled input varies by advisory. It can be a lockfile entry, a repository `.npmrc`, a Git dependency reference, a patch file referenced by `patchedDependencies`, package metadata from a registry, or alias metadata delivered through package resolution. The direct sources do not allege a single malicious npm package or campaign; they define package-manager behaviors that become exploitable when untrusted install inputs are processed in trusted environments [1] [2] [3] [4] [5] [6] [7] [8].

### Execution Trigger

The trigger is a pnpm workflow such as `pnpm install`, `pnpm add`, `pnpm view`, patch application, dependency linking, or Git dependency fetching. CI is especially relevant because package-manager jobs often run automatically on pull requests or forks and may execute before humans review every lockfile, patch, or `.npmrc` change [4] [5] [6] [7] [8].

### Payload Behavior

The reviewed direct sources do not identify a fixed malware payload. The behaviors to hunt are package-manager side effects: accepted content after integrity drift, tarballs installed without integrity verification, unexpected Git option handling, symlink replacement of project paths, file writes/deletes outside package directories, and registry requests carrying credentials to repository-influenced destinations [1] [2] [3] [4] [5] [6] [7] [8].

### Credential or Data Collection

Credential risk is strongest for the `.npmrc` and environment expansion advisories. `GHSA-cjhr-43r9-cfmw` describes user-level unscoped npm auth credentials being sent to a repository-selected registry, while `GHSA-3qhv-2rgh-x77r` describes repository config expanding victim environment secrets into registry requests before scripts run [6] [8]. Treat any credential available to the install process as in scope until registry and CI logs prove it was not transmitted or used.

### Defense Evasion

The advisories do not describe stealth malware. The practical evasion issue is review opacity: patch diff headers, lockfile commit values, registry auth configuration, and package-manager repair behavior can look like ordinary dependency maintenance unless reviewers and CI policy specifically inspect them [2] [4] [6] [7] [8].

### Exfiltration and Command and Control

Reviewed sources do not identify command-and-control infrastructure. Do not create destination-domain IOC tickets from this batch alone. Instead, use registry, proxy, and CI logs to identify whether your environment sent credentials to an unexpected registry host or fetched altered package content during the vulnerable window [2] [6] [8].

## Affected Assets and Blast Radius

| Asset | Why it matters | Blast-radius question |
| --- | --- | --- |
| `pnpm <10.34.2` on 10.x | Conservative patched 10.x baseline covering the full reviewed batch. | Which developer machines, runner images, containers, and Corepack pins used affected pnpm 10.x? |
| `pnpm >=11.0.0 <11.5.3` | Conservative patched 11.x baseline covering the full reviewed batch. | Which early pnpm 11.x environments processed untrusted install input? |
| Repository `.npmrc` files | Registry and auth configuration can influence credential destinations and environment expansion. | Did any pull request or third-party source provide registry settings while tokens were available? |
| `pnpm-lock.yaml` and Git dependencies | Lockfile integrity and Git commit fields are named in multiple advisories. | Did CI accept lockfile changes, codeload GitHub tarballs, or Git dependencies from untrusted contributors? |
| Patch files and `patchedDependencies` | Patch traversal can write/delete files outside the intended package directory. | Did install jobs apply repository-controlled patches before review? |
| CI runners and developer workstations | These systems hold the credentials and filesystem targets affected by package-manager behavior. | Which secrets, workspaces, release artifacts, or publish permissions were reachable from pnpm install jobs? |

## Indicators of Compromise

| Type | Indicator | Context |
| --- | --- | --- |
| Advisory | `GHSA-hg3w-7f8c-63hp` / `CVE-2026-48995` | GitHub Git dependency tarball lockfile hash omission [1]. |
| Advisory | `GHSA-54hh-g5mx-jqcp` / `CVE-2026-50573` | Non-frozen install integrity repair behavior [2]. |
| Advisory | `GHSA-q6j5-fjx5-2mc3` / `CVE-2026-50021` | Missing lockfile integrity fail-open behavior [3]. |
| Advisory | `GHSA-p4xf-rf54-rj3x` / `CVE-2026-50014` | Git fetch argument injection through `resolution.commit` [4]. |
| Advisory | `GHSA-hwx4-2j3j-g496` / `CVE-2026-50016` | Dependency alias path traversal / symlink path override [5]. |
| Advisory | `GHSA-cjhr-43r9-cfmw` / `CVE-2026-50017` | Repository-selected registry credential binding [6]. |
| Advisory | `GHSA-rxhj-4m44-96r4` / `CVE-2026-50015` | Patch path traversal arbitrary file write/delete [7]. |
| Advisory | `GHSA-3qhv-2rgh-x77r` / `CVE-2026-55180` | Repository config environment-secret expansion into registry requests [8]. |
| Package name | `pnpm` | Package-manager artifact. |
| File/config pattern | `.npmrc` with `registry=` and auth or environment placeholders | Review for credential-binding and environment-expansion exposure [6] [8]. |
| File/config pattern | `pnpm-workspace.yaml` `patchedDependencies` and `*.patch` paths containing `../` | Review for traversal patch application [7]. |
| Lockfile pattern | `codeload.github[.]com` Git dependency tarballs without integrity | Review for GitHub Git dependency lockfile hash exposure [1]. |
| Lockfile pattern | `resolution.commit` values beginning with `-` | Review for Git fetch argument injection exposure [4]. |

## Detection and Hunting

### Hunt Manifest: pnpm-package-manager-supply-chain-advisory-batch-hunt-1
- **Title:** pnpm vulnerable package-manager version and risky install-input exposure audit
- **Question:** Do repository manifests, lockfiles, .npmrc files, patch files, CI definitions, or exported install logs show pnpm versions and install inputs that fall inside the 2026 pnpm supply-chain advisory batch exposure envelope?
- **Telemetry Family:** file
- **Telemetry Context:** source repositories, pnpm-lock.yaml files, pnpm-workspace.yaml, .npmrc configuration, patch files, CI workflow definitions, package-manager logs, and exported build telemetry
- **Positive Signal:** The script found a pnpm version below the conservative patched baselines 10.34.2 or 11.5.3, or repository-controlled install inputs tied to the published pnpm advisories such as traversal patches, registry auth configuration, codeload GitHub tarballs without integrity, or lockfile commit arguments beginning with a dash.
- **False Positives:** Documentation examples and test fixtures can match; validate whether the file controls an actual install, CI job, registry request, or patch application before classifying compromise.
- **Classification on Match:** presumed_exposed

```py
#!/usr/bin/env python3
"""Audit repositories and exported install telemetry for the pnpm 2026 supply-chain advisory batch.

Exit codes:
  0: scan completed and no exposure indicators were found
  1: scan completed and one or more exposure indicators were found
  2: scan failed because the supplied evidence root was unavailable
"""

import json
import re
import sys
from pathlib import Path
from typing import Iterable

ADVISORY_BATCH = "pnpm GHSA supply-chain advisory batch published 2026-05-25 through 2026-06-10"
ADVISORY_IDS = [
    "GHSA-hg3w-7f8c-63hp",
    "GHSA-54hh-g5mx-jqcp",
    "GHSA-q6j5-fjx5-2mc3",
    "GHSA-p4xf-rf54-rj3x",
    "GHSA-hwx4-2j3j-g496",
    "GHSA-cjhr-43r9-cfmw",
    "GHSA-rxhj-4m44-96r4",
    "GHSA-3qhv-2rgh-x77r",
]
ADVISORY_URLS = [
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-hg3w-7f8c-63hp",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-54hh-g5mx-jqcp",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-q6j5-fjx5-2mc3",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-p4xf-rf54-rj3x",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-hwx4-2j3j-g496",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-cjhr-43r9-cfmw",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-rxhj-4m44-96r4",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-3qhv-2rgh-x77r",
]
CVE_IDS = [
    "CVE-2026-48995",
    "CVE-2026-50573",
    "CVE-2026-50021",
    "CVE-2026-50014",
    "CVE-2026-50016",
    "CVE-2026-50017",
    "CVE-2026-50015",
    "CVE-2026-55180",
]
FIXED_10_BASELINE = "10.34.2"
FIXED_11_BASELINE = "11.5.3"
PACKAGE_NAME_IOCS = ["pnpm"]
PATCHED_BASELINES = ["10.34.2", "11.5.3"]
AUTH_KEY = "_auth" + "T" + "oken" + chr(61)
NETWORK_IOCS = ["codeload.github.com", "registry=", "Authorization"]
PROCESS_IOCS = ["pnpm install", "pnpm add", "pnpm view", "pnpm patch", "git fetch"]
FILE_IOCS = ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc", "*.patch", ".github/workflows"]
INTERESTING_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    ".npmrc",
    "npmrc",
    "workflow.yml",
    "workflow.yaml",
    "build.yml",
    "build.yaml",
    "ci.yml",
    "ci.yaml",
    "Dockerfile",
}
INTERESTING_SUFFIXES = (".json", ".yaml", ".yml", ".lock", ".log", ".txt", ".npmrc", ".patch", ".diff")
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}
VERSION_RE = re.compile(r"\bpnpm(?:@|\s+version\s+|[:=\"' ]{1,8})(\d+\.\d+\.\d+)\b", re.IGNORECASE)
PACKAGE_MANAGER_RE = re.compile(r'"packageManager"\s*:\s*"pnpm@(\d+\.\d+\.\d+)"')
DEVDEP_RE = re.compile(r'"pnpm"\s*:\s*"[~^<>= ]*(\d+\.\d+\.\d+)"')


def parse_version(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def is_vulnerable_pnpm(version: str) -> bool:
    major, minor, patch = parse_version(version)
    if major < 10:
        return True
    if major == 10:
        return parse_version(version) < parse_version(FIXED_10_BASELINE)
    if major == 11:
        return parse_version(version) < parse_version(FIXED_11_BASELINE)
    return False


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.name in INTERESTING_NAMES or path.suffix.lower() in INTERESTING_SUFFIXES:
            yield path


def read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in data[:4096]:
        return ""
    return data[:2_000_000].decode("utf-8", errors="replace")


def collect_versions(text: str) -> set[str]:
    versions = set(PACKAGE_MANAGER_RE.findall(text))
    versions.update(DEVDEP_RE.findall(text))
    versions.update(VERSION_RE.findall(text))
    return versions


def classify_file(path: Path, text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for version in sorted(collect_versions(text), key=parse_version):
        if is_vulnerable_pnpm(version):
            findings.append({
                "type": "vulnerable_pnpm_version",
                "indicator": f"pnpm@{version}",
                "why": f"pnpm {version} is below the conservative patched baselines {FIXED_10_BASELINE} for 10.x and {FIXED_11_BASELINE} for 11.x",
            })
    lowered = text.lower()
    if (
        ("patcheddependencies" in lowered and ("../" in text or "..\\" in text))
        or (path.suffix.lower() in {".patch", ".diff"} and "diff --git" in text and ("../" in text or "..\\" in text))
    ):
        findings.append({
            "type": "patch_traversal_review",
            "indicator": "patchedDependencies or patch diff header with parent-directory traversal tokens",
            "why": "GHSA-rxhj-4m44-96r4 covers arbitrary file write/delete risk from malicious patch paths during pnpm patch application",
        })
    if path.name == ".npmrc" or path.name == "npmrc" or ".npmrc" in str(path):
        if "registry=" in text and (AUTH_KEY in text or "${" in text):
            findings.append({
                "type": "registry_auth_review",
                "indicator": ".npmrc registry/auth or environment placeholder configuration",
                "why": "GHSA-cjhr-43r9-cfmw and GHSA-3qhv-2rgh-x77r cover registry-selected credential binding and environment-secret expansion into registry requests",
            })
    if "codeload.github.com" in text and "integrity" not in lowered:
        findings.append({
            "type": "github_git_dependency_without_integrity",
            "indicator": "codeload.github.com dependency without nearby integrity field",
            "why": "GHSA-hg3w-7f8c-63hp covers missing lockfile hashes for GitHub git dependency tarballs",
        })
    if "commit: --" in text or "commit: \"--" in text or "commit: '--" in text:
        findings.append({
            "type": "git_commit_argument_injection_review",
            "indicator": "lockfile commit field beginning with a dash",
            "why": "GHSA-p4xf-rf54-rj3x covers git fetch argument injection through lockfile resolution.commit",
        })
    if "node_modules/.bin" in text and "../" in text and path.name == "pnpm-lock.yaml":
        findings.append({
            "type": "alias_path_traversal_review",
            "indicator": "pnpm-lock.yaml alias/path traversal pattern touching node_modules/.bin",
            "why": "GHSA-hwx4-2j3j-g496 covers alias path traversal that can replace project paths with symlinks",
        })
    return findings


def collect_exact_package_version_iocs(results: list[dict[str, object]]) -> list[str]:
    indicators = {
        finding["indicator"]
        for item in results
        for finding in item["findings"]  # type: ignore[index]
        if finding["type"] == "vulnerable_pnpm_version"
    }
    return sorted(indicators, key=lambda value: parse_version(value.removeprefix("pnpm@")))


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path.cwd()
    if not root.exists():
        print(json.dumps({"error": f"evidence root not found: {root}"}, indent=2))
        return 2
    results = []
    for path in iter_files(root):
        text = read_text(path)
        if not text:
            continue
        findings = classify_file(path, text)
        if findings:
            results.append({"path": str(path.relative_to(root)), "findings": findings})
    output = {
        "advisory_batch": ADVISORY_BATCH,
        "advisory_ids": ADVISORY_IDS,
        "advisory_urls": ADVISORY_URLS,
        "cve_ids": CVE_IDS,
        "file_iocs": FILE_IOCS,
        "network_iocs": NETWORK_IOCS,
        "package_name_iocs": PACKAGE_NAME_IOCS,
        "package_version_iocs": collect_exact_package_version_iocs(results),
        "patched_baselines": PATCHED_BASELINES,
        "process_iocs": PROCESS_IOCS,
        "finding_count": sum(len(item["findings"]) for item in results),
        "files_with_findings": results,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 1 if results else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Downstream Abuse Audits

Prioritize registry and source-hosting audit before broad credential rotation. If a vulnerable pnpm job had npm credentials, query private registry logs for requests to non-standard hosts, repository-selected registry URLs, or requests carrying auth headers during install windows that processed untrusted repositories. Escalate when the same token later publishes, deletes, deprecates, or changes metadata for packages outside its normal release pattern [6] [8].

For GitHub-hosted CI, review workflow runs that set up pnpm through Corepack, `pnpm/action-setup`, or a checked-in package-manager pin. The review should join the pnpm version, event type, actor, branch/fork status, modified `.npmrc`, modified `pnpm-lock.yaml`, modified `pnpm-workspace.yaml`, modified patch files, and available secrets. Runs from forks or external contributors that had write tokens, package registry credentials, or cloud credentials available should be treated as higher priority even without a malware IOC [4] [5] [6] [7] [8].

For developer workstations, preserve npm and pnpm configuration, shell history, local package-manager logs, and endpoint process telemetry before cleanup. Confirm whether the developer opened or installed untrusted projects with vulnerable pnpm versions and whether user-level npm tokens were unscoped or could be bound to repository-selected registries [6] [8].

## Remediation and Closure

1. **Preserve evidence:** Before deleting workspaces or caches, preserve `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `.npmrc`, patch files, CI logs, registry/proxy logs, runner images, and endpoint telemetry for any affected install path. These artifacts are necessary to distinguish version-only exposure from credential transmission or filesystem modification [4] [5] [6] [7] [8].
2. **Stop active exposure:** Disable untrusted pnpm install jobs that run on pull requests, forks, third-party source drops, or repository-controlled `.npmrc`/patch/lockfile changes until the runner uses pnpm `10.34.2` or `11.5.3` or later [6] [7] [8].
3. **Upgrade pnpm everywhere it is pinned:** Update Corepack pins, `packageManager` fields, CI setup steps, runner images, local developer tooling, and package-manager container images to fixed versions. Use `10.34.2` as the minimum 10.x baseline and `11.5.3` as the minimum 11.x baseline for this batch [8].
4. **Constrain credentials before resuming installs:** Replace user-level unscoped npm tokens with registry-scoped auth configuration, avoid injecting long-lived secrets into untrusted install jobs, and require explicit registry allowlists for CI package-manager traffic [6] [8].
5. **Review patch and lockfile changes:** Block or require review for patch files with parent-directory traversal, lockfile `resolution.commit` values that are not commit-like identifiers, Git dependencies from untrusted contributors, and lockfile entries for GitHub tarballs without integrity [1] [4] [7].
6. **Audit downstream abuse:** For every confirmed or presumed exposed token, inspect registry publish/deprecate/delete events, source-hosting audit logs, cloud session logs, and artifact repository writes after the vulnerable install window. Rotate only after preserving evidence needed to understand misuse [6] [8].
7. **Recover using verified install policy:** Re-run builds with fixed pnpm, frozen lockfile policy for CI, registry egress controls, and isolated runners for untrusted repositories. Treat any dependency output produced by vulnerable jobs as untrusted until rebuilt [2] [3].
8. **Close with gates:** Close the incident only when every pnpm install path has a documented version, input-trust boundary, credential scope decision, registry audit result, and fixed package-manager configuration.

## Sources

1. **pnpm GitHub Security Advisory GHSA-hg3w-7f8c-63hp:** Direct source for missing lockfile hashes on GitHub Git dependency tarballs, affected ranges, and fixed versions. https://github.com/pnpm/pnpm/security/advisories/GHSA-hg3w-7f8c-63hp
2. **pnpm GitHub Security Advisory GHSA-54hh-g5mx-jqcp:** Direct source for non-frozen install integrity repair behavior and affected/fixed version ranges. https://github.com/pnpm/pnpm/security/advisories/GHSA-54hh-g5mx-jqcp
3. **pnpm GitHub Security Advisory GHSA-q6j5-fjx5-2mc3:** Direct source for missing lockfile integrity fail-open behavior and affected/fixed version ranges. https://github.com/pnpm/pnpm/security/advisories/GHSA-q6j5-fjx5-2mc3
4. **pnpm GitHub Security Advisory GHSA-p4xf-rf54-rj3x:** Direct source for Git fetch argument injection via lockfile `resolution.commit`. https://github.com/pnpm/pnpm/security/advisories/GHSA-p4xf-rf54-rj3x
5. **pnpm GitHub Security Advisory GHSA-hwx4-2j3j-g496:** Direct source for dependency alias path traversal and project path override through symlink replacement. https://github.com/pnpm/pnpm/security/advisories/GHSA-hwx4-2j3j-g496
6. **pnpm GitHub Security Advisory GHSA-cjhr-43r9-cfmw:** Direct source for repository-selected registry credential binding. https://github.com/pnpm/pnpm/security/advisories/GHSA-cjhr-43r9-cfmw
7. **pnpm GitHub Security Advisory GHSA-rxhj-4m44-96r4:** Direct source for malicious patch path traversal and arbitrary file write/delete behavior. https://github.com/pnpm/pnpm/security/advisories/GHSA-rxhj-4m44-96r4
8. **pnpm GitHub Security Advisory GHSA-3qhv-2rgh-x77r:** Direct source for repository config environment-secret expansion into registry requests and the latest fixed range in the reviewed batch. https://github.com/pnpm/pnpm/security/advisories/GHSA-3qhv-2rgh-x77r
