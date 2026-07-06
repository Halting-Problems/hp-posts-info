---
title: "Immobiliare Labs Backstage npm Packages Hit by Phantom Gyp"
date: 2026-06-26
severity: "critical"
tags:
  - npm
  - backstage
  - node-gyp
  - supply-chain
  - credential-theft
summary: "On June 26, 2026, multiple @immobiliarelabs Backstage plugin versions were published to npm with a binding.gyp node-gyp hook and a new 5 MB index.js payload. Treat affected Backstage builds and developer or CI installs as credential exposure until lockfiles, package caches, and downstream audits are clean."
sourceCount: 6
---

## Executive Summary

On **2026-06-26**, StepSecurity reported that multiple npm packages in the `@immobiliarelabs` scope were compromised with install-time execution through a `binding.gyp` / `node-gyp` path rather than a normal `postinstall` script [1]. The affected packages are open-source Backstage plugins for GitLab and LDAP authentication maintained by Immobiliare Labs: `@immobiliarelabs/backstage-plugin-gitlab`, `@immobiliarelabs/backstage-plugin-gitlab-backend`, `@immobiliarelabs/backstage-plugin-ldap-auth`, and `@immobiliarelabs/backstage-plugin-ldap-auth-backend` [1] [2].

This is a **credential-exposure incident**, not just dependency hygiene. StepSecurity reports that the payload targets GitHub Actions secrets, cloud provider credentials, package registry tokens, and attempts persistence in AI coding assistant configuration files [1]. The public GitHub issue opened against `immobiliare/backstage-plugin-gitlab` lists the affected versions and records same-day notification to the maintainers [2]. npm registry metadata independently confirms new patch releases for the affected packages on 2026-06-26 [3] [4] [5] [6].

Halting Problems performed static, non-executing artifact comparison for `@immobiliarelabs/backstage-plugin-gitlab@2.1.2` against `2.1.1`. The compromised tarball adds `package/binding.gyp` and a `package/index.js` file of 4,991,856 bytes; the clean `2.1.1` tarball has neither file. This matches StepSecurity's public description of a new 5 MB `index.js` and `binding.gyp` added to compromised releases [1] [3].

### Source-Watcher Candidate Queue

**Candidate Id**: immobiliarelabs-backstage-npm-phantom-gyp-2026-06-26

**First Seen**: 2026-06-26T16:12:03Z

**Decision**: publish_ready

**Relationship**: child event of Phantom Gyp / node-gyp build-hook abuse

**Dedupe Keys**:
- npm:@immobiliarelabs/backstage-plugin-gitlab
- npm:@immobiliarelabs/backstage-plugin-gitlab-backend
- npm:@immobiliarelabs/backstage-plugin-ldap-auth
- npm:@immobiliarelabs/backstage-plugin-ldap-auth-backend
- github:immobiliare/backstage-plugin-gitlab:issue:1052
- technique:phantom-gyp

**Starting Sources**:
- StepSecurity primary research
- Immobiliare Labs GitHub issue #1052
- npm registry metadata for the four affected packages

## Key Facts

**Threat Type**: malicious npm package install-time execution and credential theft

**Ecosystem**: npm

**Affected Project Context**: Backstage plugins used by platform engineering teams running internal developer portals [1]

**Execution Trigger**: `binding.gyp` invokes `node index.js` through node-gyp shell expansion during package installation [1]

**Known Affected Packages**:
- `@immobiliarelabs/backstage-plugin-gitlab`
- `@immobiliarelabs/backstage-plugin-gitlab-backend`
- `@immobiliarelabs/backstage-plugin-ldap-auth`
- `@immobiliarelabs/backstage-plugin-ldap-auth-backend`

**Credential Risk**:
- GitHub Actions secrets
- cloud provider credentials
- npm and other package registry tokens
- Backstage deployment credentials
- developer workstation secrets
- AI coding assistant configuration secrets [1]

**Confidence**: high

**Canonical Source**: https://www.stepsecurity.io/blog/immobiliarelabs-npm-packages-compromised

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| Multiple `@immobiliarelabs` Backstage npm packages were published with malicious install-time behavior on 2026-06-26. | confirmed | StepSecurity's primary analysis names the affected package family and describes the binding.gyp / node-gyp install-time hook; GitHub issue #1052 lists the affected versions [1] [2]. |
| The affected package set includes GitLab and LDAP Backstage plugins. | confirmed | StepSecurity lists all four packages, and the npm registry endpoints resolve each package identity [1] [3] [4] [5] [6]. |
| The compromised versions include a new `binding.gyp` and a large `index.js` payload. | confirmed | StepSecurity reports both files; Halting Problems' static tarball comparison of `backstage-plugin-gitlab@2.1.2` versus `2.1.1` confirms `package/binding.gyp` and a 4,991,856-byte `package/index.js` in `2.1.2` [1] [3]. |
| All affected versions were published in a compressed same-day release window. | confirmed | StepSecurity reports simultaneous patch releases; npm registry `time` metadata confirms affected package publishes between `2026-06-26T15:00:49Z` and `2026-06-26T15:08:37Z` across the four package families [1] [3] [4] [5] [6]. |
| Public evidence proves which Immobiliare Labs credential or account was initially compromised. | unclear | The reviewed public sources identify malicious npm releases and notification to maintainers, but do not prove the initial access path used to publish them [1] [2]. |
| Public evidence proves downstream victim count or confirmed cloud-control-plane abuse. | not_observed | StepSecurity describes credential-theft capability and targets, but the reviewed public sources do not publish a verified victim list or confirmed downstream cloud-abuse count [1]. |

## Impact Determination

| Classification | Criteria | Required evidence | Handling decision | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | A listed package version was installed and telemetry shows `binding.gyp`, `node-gyp`, `node index.js`, or payload execution during install/build. | Lockfile or cache hit plus npm/pnpm/yarn logs, endpoint process telemetry, CI logs, or artifact inventory showing the malicious files. | Isolate the host or runner, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected packages are removed, systems rebuilt or cleaned, credentials rotated, and downstream audits show no unauthorized activity after 2026-06-26T15:00:49Z. |
| Presumed exposed | A listed package version was present in dependency resolution on a credential-bearing workstation, CI runner, package mirror, builder, or Backstage deployment, but execution telemetry is incomplete. | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, npm cache, container layer, package mirror, or build log with an affected package version. | Keep GitHub, npm, cloud, registry, Backstage, and developer secrets in scope until rotation or complete negative telemetry closes the gap. | Owners provide negative runtime telemetry or complete credential rotation and clean rebuild evidence. |
| Potentially exposed | An affected package name appears but the resolved version is unknown. | Manifest or dependency inventory naming one of the packages without a resolved version. | Reconstruct dependency resolution from lockfiles, package-manager logs, internal mirrors, and CI caches. | Each package-name hit is dispositioned as affected, clean, or unknown with owner acceptance. |
| Not exposed | Complete source, lockfile, cache, build, endpoint, and deployment evidence contains no affected package versions or payload indicators. | Negative repository, package-cache, build-log, endpoint, and deployment searches. | Preserve evidence and keep lifecycle-script controls in place. | Evidence covers developer endpoints, CI runners, internal package mirrors, and Backstage deployments for the exposure window. |
| Unknown | Dependency, endpoint, CI, cache, or audit telemetry is missing. | A named gap with owner, system, and retention window. | Treat reachable credentials conservatively until evidence or rotation closes the gap. | Missing evidence is recovered or risk owner accepts residual exposure. |

### Minimum Evidence To Collect

- Full dependency inventory for Backstage repositories, templates, plugins, deployment charts, package mirrors, build images, and developer workstations.
- Lockfiles and package-manager caches covering `2026-06-26T15:00:49Z` onward.
- npm, pnpm, yarn, and CI logs showing whether `node-gyp rebuild`, `binding.gyp`, or `node index.js` ran during installation.
- Endpoint process telemetry for developer machines and runners that build Backstage plugins.
- GitHub, npm, package registry, cloud, and Backstage deployment audit logs for downstream use of exposed credentials.

## Timeline

- **2026-06-26T15:00:49Z:** npm registry metadata shows `@immobiliarelabs/backstage-plugin-gitlab-backend@3.0.3` published, the earliest affected publish time confirmed in this review [4].
- **2026-06-26T15:01:13Z to 2026-06-26T15:01:43Z:** npm registry metadata shows seven affected `@immobiliarelabs/backstage-plugin-gitlab` versions published across supported major release lines [3].
- **2026-06-26T15:07:57Z to 2026-06-26T15:08:37Z:** npm registry metadata shows affected LDAP plugin releases published [5] [6].
- **2026-06-26T15:18:01Z:** GitHub issue #1052 is opened to notify Immobiliare Labs of malicious npm releases in the `@immobiliarelabs` scope [2].
- **2026-06-26:** StepSecurity publishes public analysis of the affected packages, binding.gyp execution path, affected versions, and credential-theft behavior [1].

## What Happened

Attackers published new patch versions across several supported major lines for four Immobiliare Labs Backstage npm packages [1] [2]. The releases were inserted as patch updates, which means dependency ranges that allowed those patch lines could resolve the malicious artifact during normal Backstage builds or developer installs [1] [3] [4] [5] [6].

The malicious packages did not rely on a visible `scripts.postinstall` entry. StepSecurity reports that each compromised package includes a `binding.gyp` file whose source expression causes node-gyp to execute `node index.js` during installation [1]. This matters operationally because controls that only inspect `package.json` lifecycle script fields can miss the execution path [1].

Static artifact comparison supports the reported package manipulation. In `@immobiliarelabs/backstage-plugin-gitlab@2.1.1`, the tarball has 15 files, no `binding.gyp`, and no top-level `index.js`. In `@immobiliarelabs/backstage-plugin-gitlab@2.1.2`, the tarball has 17 files, adds `package/binding.gyp`, and adds a 4,991,856-byte `package/index.js`; the `2.1.2` tarball SHA-256 captured for this analysis is `7a879ed69a8191df5c68535f6ac41b830577b698de943c66ff40e51482d90d79` [1] [3].

## Technical Analysis

### Initial Access

The reviewed public sources do not prove the initial access path used to publish the npm releases. Responders should avoid assuming a specific maintainer phishing, token theft, or CI compromise scenario until Immobiliare Labs or npm publishes further detail [1] [2].

### Package or Artifact Manipulation

The manipulation pattern is the addition of a native-addon build manifest and large JavaScript payload to packages that did not previously need that build path [1]. StepSecurity reports that `binding.gyp` invokes `node index.js` through node-gyp shell expansion; local static inspection of `backstage-plugin-gitlab@2.1.2` confirms the new `binding.gyp` and `index.js` files [1] [3].

### Execution and Credential Access

The execution path is npm installation or build resolution that invokes node-gyp. StepSecurity reports that the payload uses obfuscation and a Bun runtime stage before credential harvesting, and targets GitHub Actions secrets, cloud credentials, and package registry tokens [1]. Because these packages are Backstage plugins, the most important exposure surfaces are developer workstations, platform-engineering CI runners, internal package mirrors, Backstage build containers, and deployment pipelines.

### Downstream Risk

Any environment that installed the affected versions could expose credentials available to the package-manager process because StepSecurity reports credential harvesting from GitHub Actions secrets, cloud provider keys, and package registry tokens [1]. That includes CI job environment variables, npm tokens, GitHub tokens, cloud service-account keys, registry publish credentials, SSH deploy keys, and Backstage deployment secrets. A clean dependency rollback does not close the incident unless downstream credential and audit checks are complete.

## Indicators of Compromise

### Package Versions

- `@immobiliarelabs/backstage-plugin-gitlab@1.0.1`
- `@immobiliarelabs/backstage-plugin-gitlab@2.1.2`
- `@immobiliarelabs/backstage-plugin-gitlab@3.0.3`
- `@immobiliarelabs/backstage-plugin-gitlab@4.0.2`
- `@immobiliarelabs/backstage-plugin-gitlab@5.2.1`
- `@immobiliarelabs/backstage-plugin-gitlab@6.13.1`
- `@immobiliarelabs/backstage-plugin-gitlab@7.0.2`
- `@immobiliarelabs/backstage-plugin-gitlab-backend@3.0.3`
- `@immobiliarelabs/backstage-plugin-gitlab-backend@4.0.2`
- `@immobiliarelabs/backstage-plugin-gitlab-backend@5.2.1`
- `@immobiliarelabs/backstage-plugin-gitlab-backend@6.13.1`
- `@immobiliarelabs/backstage-plugin-gitlab-backend@7.0.2`
- `@immobiliarelabs/backstage-plugin-ldap-auth@1.1.4`
- `@immobiliarelabs/backstage-plugin-ldap-auth@2.0.5`
- `@immobiliarelabs/backstage-plugin-ldap-auth@3.0.2`
- `@immobiliarelabs/backstage-plugin-ldap-auth@4.3.2`
- `@immobiliarelabs/backstage-plugin-ldap-auth@5.2.1`
- `@immobiliarelabs/backstage-plugin-ldap-auth-backend@1.1.3`
- `@immobiliarelabs/backstage-plugin-ldap-auth-backend@2.0.5`
- `@immobiliarelabs/backstage-plugin-ldap-auth-backend@3.0.2`
- `@immobiliarelabs/backstage-plugin-ldap-auth-backend@4.3.2`
- `@immobiliarelabs/backstage-plugin-ldap-auth-backend@5.2.1`

### File and Process Selectors

- `binding.gyp`
- `package/binding.gyp`
- `index.js` when added to one of the affected npm tarballs
- `package/index.js`
- `node-gyp rebuild`
- `node index.js`

### Artifact Hashes

- `@immobiliarelabs/backstage-plugin-gitlab@2.1.2` npm shasum: `7ae466337c9f0951feae7b30d6f4b8afc8066bf8` [3]
- `@immobiliarelabs/backstage-plugin-gitlab@2.1.2` tarball SHA-256 captured during this review: `7a879ed69a8191df5c68535f6ac41b830577b698de943c66ff40e51482d90d79` [3]

## Detection and Hunting

### Hunt Manifest: immobiliarelabs-backstage-npm-phantom-gyp-hunt-1
- **Title:** Immobiliare Labs Backstage npm exposure scope
- **Question:** Do repositories, lockfiles, npm cache exports, or install/build logs show installation of the compromised @immobiliarelabs Backstage package versions from June 26, 2026?
- **Telemetry Family:** package-manager
- **Telemetry Context:** source tree, dependency lockfiles, package-cache export, and optional LOG_ROOT containing npm/pnpm/yarn/CI logs
- **Positive Signal:** A compromised @immobiliarelabs Backstage package version, tarball hash, binding.gyp hook, or node index.js execution pattern is present in scoped evidence.
- **False Positives:** Package names without one of the listed compromised versions need follow-up version resolution before incident classification.
- **Classification on Match:** Treat hosts, runners, builders, and Backstage deployment pipelines that installed matching versions as presumed credential exposure until runtime telemetry and downstream audits are clean.

```py
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
```

## Downstream Abuse Audits

### GitHub and CI/CD

1. Export GitHub audit logs and workflow-run records for organizations whose Backstage builds, developer portal repositories, or plugin publishing pipelines could have installed the affected versions after `2026-06-26T15:00:49Z`.
2. Search for new or modified repository secrets, deploy keys, environments, workflow files, self-hosted runner registrations, and package publishes following any affected install.
3. Treat any match from the hunt script as a trigger to rotate GitHub tokens and inspect private repositories for unexpected commits, branches, and package-publishing activity.

### npm and Package Registries

1. Review npm access tokens, automation tokens, provenance settings, and recent publishes for packages owned by teams whose machines or runners installed affected versions.
2. Search internal package mirrors and caches for the exact affected versions and tarball shasums. A mirror hit should be handled as a redistribution risk until all consuming builds are enumerated.
3. Revoke or rotate registry tokens from a clean workstation before rebuilding Backstage deployment images.

### Cloud and Backstage Deployment

1. Identify cloud roles, Kubernetes credentials, deployment keys, and service-account material available to Backstage build and deployment jobs.
2. Review cloud audit logs for new access keys, service-account key creation, policy attachment, unusual token use, and new CI/CD identities after the first possible install time.
3. Rebuild Backstage containers or hosts from clean dependency state before returning rotated credentials to service.

### Developer Endpoints and AI Assistant Configs

1. Search developer workstations that build Backstage plugins for affected lockfile entries, npm caches, `binding.gyp`, `node-gyp rebuild`, and `node index.js` execution logs.
2. Preserve and review AI coding assistant configuration directories for unexpected persistence entries, because StepSecurity reports attempted persistence in those configs [1].
3. If endpoint telemetry is missing, keep developer GitHub, npm, SSH, package registry, and cloud credentials in rotation scope.

## Remediation and Closure

### Containment

- Remove or pin away from every affected `@immobiliarelabs` version in manifests, lockfiles, internal templates, Backstage app repositories, and deployment definitions.
- Disable or quarantine Backstage CI jobs, package-mirror pulls, and build images that resolved affected versions until dependency evidence is collected.
- Preserve package-locks, pnpm/yarn locks, npm cache entries, tarballs, CI logs, and endpoint process records before deleting artifacts.

### Eradication

- Clear affected versions from npm caches, internal package mirrors, container layers, and Backstage build images.
- Rebuild affected runners and developer machines from trusted baselines when execution is confirmed or telemetry is insufficient.
- Remove unexpected AI assistant configuration entries found on exposed developer endpoints.

### Credential Rotation

- Rotate GitHub tokens, GitHub Actions secrets, deploy keys, npm tokens, package registry tokens, cloud keys, SSH deploy keys, and Backstage deployment secrets reachable from affected installs.
- Rotate from a clean workstation or privileged access path, not from a host that may have run the payload.
- Validate revocation by confirming old tokens cannot authenticate and by checking downstream audit logs for use after revocation.

### Recovery and Closure

- Rebuild Backstage applications with clean package versions or remove the affected plugins until maintainers publish confirmed fixed releases.
- Confirm all positive hunt hits are dispositioned and all affected environments have clean rebuild or rotation evidence.
- Close only after downstream GitHub, npm, cloud, registry, endpoint, and Backstage deployment audits show no unauthorized follow-on use.

### Open Questions

- Which npm credential, session, or publishing workflow was used to publish the malicious releases?
- Which versions were removed, deprecated, or republished by maintainers after the public issue?
- Are there confirmed downstream victims or credential-abuse cases beyond the package payload capability described by StepSecurity?

## Sources

1. [StepSecurity: Multiple @immobiliarelabs Backstage Plugins Compromised on npm](https://www.stepsecurity.io/blog/immobiliarelabs-npm-packages-compromised) - **Role:** PRIMARY_RESEARCH - **Impact:** Affected package list, compromised versions, binding.gyp execution path, payload behavior, credential-risk scope.
2. [GitHub issue #1052: Malicious npm releases found in @immobiliarelabs scope](https://github.com/immobiliare/backstage-plugin-gitlab/issues/1052) - **Role:** DIRECT_SOURCE - **Impact:** Maintainer notification, affected package/version table, disclosure timeline.
3. [npm registry: @immobiliarelabs/backstage-plugin-gitlab](https://registry.npmjs.org/@immobiliarelabs%2Fbackstage-plugin-gitlab) - **Role:** REGISTRY_METADATA - **Impact:** Publish timestamps, tarball URLs, shasums, artifact comparison source.
4. [npm registry: @immobiliarelabs/backstage-plugin-gitlab-backend](https://registry.npmjs.org/@immobiliarelabs%2Fbackstage-plugin-gitlab-backend) - **Role:** REGISTRY_METADATA - **Impact:** Publish timestamps, affected version metadata, shasums.
5. [npm registry: @immobiliarelabs/backstage-plugin-ldap-auth](https://registry.npmjs.org/@immobiliarelabs%2Fbackstage-plugin-ldap-auth) - **Role:** REGISTRY_METADATA - **Impact:** Publish timestamps, affected version metadata, shasums.
6. [npm registry: @immobiliarelabs/backstage-plugin-ldap-auth-backend](https://registry.npmjs.org/@immobiliarelabs%2Fbackstage-plugin-ldap-auth-backend) - **Role:** REGISTRY_METADATA - **Impact:** Publish timestamps, affected version metadata, shasums.
