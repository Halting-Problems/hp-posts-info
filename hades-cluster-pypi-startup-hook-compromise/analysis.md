---
title: "Hades Cluster PyPI Worm Abuses Python Startup Hooks"
date: 2026-06-07
severity: "critical"
tags:
  - pypi
  - startup-hook
  - supply-chain
  - credential-theft
  - hades-cluster
summary: "Socket disclosed 37 malicious PyPI wheels on June 7, 2026 and 23 additional malicious release artifacts on June 8, while StepSecurity's June 16 report independently re-corroborated the Hades cluster through mflux-streamlit and mrbios coverage. Hades-linked loaders abuse Python startup hooks or native extensions to execute Bun-launched credential stealers."
sourceCount: 5
---

## Executive Summary

On **2026-06-07**, Socket disclosed 37 malicious PyPI wheels across 19 established scientific, bioinformatics, and developer-tool packages. The wheels used `*-setup.pth` startup hooks to execute `_index.js` through Bun whenever Python initialized in the affected environment, without requiring an explicit import [1].

On **2026-06-08**, Socket published a second set of 23 malicious PyPI release artifacts. The newer wave added MCP-themed packages and bioinformatics packages and used three delivery branches: the existing `.pth` startup hook, trojanized native `.abi3.so` extensions that execute on import, and packages carrying payload components intended to combine with another compromised dependency [2]. Treat any installation of a listed version as presumed credential exposure because the payload targets source-control, package-registry, cloud, Kubernetes, Vault, SSH, Docker, CI/CD, and developer-tool secrets.

On **2026-06-16**, StepSecurity republished the Hades campaign with explicit coverage for `mflux-streamlit` and `mrbios`. PyPI simple-index snapshots for both projects now show `pypi:project-status=quarantined`, and the version-specific JSON endpoints return 404, so the update strengthens registry-removal confidence without introducing a new delivery branch [3][4].

## Key Facts

**Threat Type**: malicious PyPI package startup-time execution

**Ecosystem**: pypi, python

**Technique**: Python *.pth startup hook abuse

**Campaign Name**: Hades Cluster

**Related Family**: Miasma / Mini Shai-Hulud

**Disclosed**: 2026-06-07

**Expanded Disclosure**: 2026-06-08

**Update / Registry Corroboration**: 2026-06-16

**Execution Trigger**:
- Python startup execution via *.pth files
- Any Python execution in environment containing compromised packages
- Import of a trojanized native extension in the newer bioinformatics subcluster

**Known Affected Packages**:
- bramin
- cmd2func
- coolbox
- dynamo-release
- executor-engine
- executor-http
- funcdesc
- magique
- magique-ai
- mrbios
- napari-ufish
- nucbox
- okite
- pantheon-agents
- pantheon-toolsets
- spateo-release
- synago
- ufish
- uprobe
- dreamgen
- embiggen
- ensmallen
- gpsea
- instructor-mcp
- langchain-core-mcp
- mem8
- mflux-streamlit
- openai-mcp
- orchestr8-platform
- phenopacket-store-toolkit
- ppkt2synergy
- pyphetools
- ray-mcp-server
- rlask
- rsquests
- tiktoken-mcp
- tlask

**Credential Risk**:
- pypi tokens
- npm tokens
- GitHub tokens
- cloud credentials
- SSH keys
- CI/CD secrets

**Last Verified**: 2026-06-16

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| Socket identified 37 malicious wheels in the initial Hades PyPI wave. | confirmed | The June 7 report lists every package version and three payload hashes [1]. |
| The initial wave executes automatically through `*-setup.pth` startup hooks. | confirmed | Socket deobfuscated the hook and `_index.js` execution path [1]. |
| A June 8 wave added 23 malicious release artifacts and native-extension delivery. | confirmed | Socket lists all 23 versions and identifies trojanized `ensmallen_haswell.abi3.so` and `ensmallen_core2.abi3.so` files [2]. |
| The June 16 StepSecurity update explicitly covers `mflux-streamlit` and `mrbios`. | confirmed | StepSecurity names `mflux-streamlit` 0.0.3/0.0.4 and `mrbios` 0.1.1/0.1.2 in the campaign table [3]. |
| PyPI simple-index snapshots for the two added packages are quarantined and have no release links. | confirmed | Live simple-index responses show `pypi:project-status=quarantined` and no package links for both projects [4]. |
| The accessible update adds new hashes or a new delivery branch for `mflux-streamlit` or `mrbios`. | not_observed | The StepSecurity update corroborates the package coverage but does not surface new hashes or a distinct branch beyond the existing Hades reporting [1][2][3][4]. |
| The `api[.]anthropic[.]com/v1/api` path was a functioning exfiltration endpoint. | not_observed | Socket tested the path and received Anthropic's normal `404 not_found_error`; its report says there is no indication Anthropic systems were compromised [1]. |
| The complete account-compromise path and every downstream victim are known. | unclear | Public reporting does not enumerate all compromised publisher identities, victims, or successful exfiltration repositories. |

## Impact Determination

| Classification | Criteria | Required evidence | Handling decision | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | Affected version was installed and `_index.js`, a malicious `.pth` hook, a trojanized native extension, Bun execution, or exfiltration behavior is observed. | Process telemetry, site-packages capture, wheel hash, network telemetry, or GitHub repository evidence. | Isolate the host or runner and rotate all reachable secrets from a clean system. | The environment is rebuilt, secrets are replaced, and downstream access is dispositioned. |
| Presumed exposed | A listed version is present in a lockfile, package cache, environment, image, CI job, or build record even when execution telemetry is unavailable. | Requirements and lockfiles, pip cache, site-packages inventory, image layers, and build logs. | Assume secrets available to the Python environment were exposed. | Clean artifacts are deployed and credential rotation is complete. |
| Potentially exposed | Dependency matches names of affected bioinformatics/deep-learning packages, but version is clean. | Manifest check showing clean versions installed. | Verify that no cached wheels or local modifications were pulled. | Version verification shows clean tags. |
| Not exposed | No affected package names or indicators found in environment or network log. | Registry logs, package caches, and system process history search. | Document negative result and monitor for registry-level changes. | Environment and registry verification. |
| Unknown | Package manager logs or system history are missing. | Gap in local logging or endpoint agent telemetry. | Retain standard scoping and execute proactive rotation on high-value tokens. | Restoration of logs or fallback to presumptive handling. |

## Minimum Evidence To Collect

- Preserve the original wheel files, `site-packages` directories, and pip cache entries because `.pth` startup hooks and trojanized native extensions can disappear during cleanup, and those artifacts prove whether the environment ever had an executable path into the campaign.
- Export lockfiles, `pip freeze` outputs, and build manifests because matching an affected package version in a transitive dependency chain is enough to show the Python environment could have executed the hook before the application import chain ran.
- Capture PyPI simple-index snapshots and mirror exports because the quarantined registry view distinguishes live takedown state from historic exposure, which helps prove whether a clean current registry state masks prior installation risk.
- Collect process trees, job logs, and runner telemetry from the first interpreter startup after install because this campaign triggers at Python initialization, so the relevant signal can exist even when the application never explicitly imports the package.

## Timeline

- **2026-06-07:** Socket publishes the initial 37-wheel Hades analysis [1].
- **2026-06-08:** Socket publishes 23 additional malicious release artifacts and documents `.pth`, native-extension, and split-component delivery branches [2].
- **2026-06-16:** StepSecurity publishes a campaign update covering `mflux-streamlit` and `mrbios`, and live PyPI simple-index snapshots show both projects quarantined [3][4].
- **2026-06-16:** Version-specific PyPI JSON endpoints for `mflux-streamlit` and `mrbios` return `404`, which is consistent with removed or quarantined release artifacts [4].

## What Happened

The initial wave inserted a small Python startup hook and a large obfuscated `_index.js` payload into otherwise legitimate wheels. Python processes the `.pth` file while initializing `site`, so the malicious loader can run even when application code never imports the compromised package. The loader downloads Bun `1.3.13` from GitHub Releases and executes `_index.js` [1].

The June 8 wave broadened delivery. `langchain-core-mcp` retained the startup-hook approach, some bioinformatics packages carried trojanized `.abi3.so` extensions that execute when imported, and other packages carried payload components designed to locate `_index.js` elsewhere on `sys.path` [2].

The June 16 StepSecurity update matters as corroboration rather than a new payload branch. It explicitly names `mflux-streamlit` and `mrbios`, and the live PyPI simple-index snapshots now show both projects as quarantined, which is consistent with takedown or removal but not sufficient to prove when a particular host last synchronized the package cache [3][4].

## Technical Analysis

The recovered JavaScript uses layered obfuscation, including a rotated string table, PBKDF2/SHA-256-backed decoding, AES-256-GCM, and gzip. It searches developer environments for GitHub, package-registry, cloud, Kubernetes, Vault, SSH, Docker, CI/CD, Anthropic, CircleCI, Claude/MCP, wallet, and shell-history material [1].

The payload includes GitHub-based exfiltration and propagation logic, workflow persistence, Docker and SSH propagation paths, and anti-analysis checks. The hardcoded Anthropic route `hxxps://api[.]anthropic[.]com/v1/api` is not a valid Anthropic API path and should be treated as a behavioral selector, not as evidence that Anthropic infrastructure was compromised. [1]

## Affected Assets and Blast Radius

**Affected Assets**:
- Developer workstations with a listed PyPI version installed
- CI runners, notebooks, containers, and virtual environments containing affected wheels
- Package publishing and GitHub accounts reachable from affected environments
- Cloud, Kubernetes, Vault, Docker, SSH, and AI-tooling identities available to Python processes
- Internal mirrors and cache layers that synchronized the affected wheels before quarantine

**Delivery Branches**:
- Python startup execution through *-setup.pth
- Import-time execution through trojanized .abi3.so native extensions
- Split-component loader searches for _index.js on sys.path

**Registry Status**:
- PyPI simple-index snapshots for `mflux-streamlit` and `mrbios` are quarantined
- Version-specific JSON endpoints for the two packages return 404

**Scope Limitations**:
- Public sources do not enumerate all successful victims or exfiltration repositories
- Registry quarantine makes it harder to recover historical release artifacts from live endpoints

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe
- e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d
- c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c
- 6d332f814f15f19758d65026bbfd0a8c49671b319ec77b8fa1b27fc48afff7d9
- 6506d31707a39949f89534bf9705bcf889f1ecae3dbc6f4ff88d67a8be3d01b2

### Domains
- setup.pth
- abi3.so


## Detection and Hunting

### Hunt Manifest: hades-cluster-pypi-startup-hook-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Hades Cluster PyPI Worm Abuses Python Startup Hooks?
- **Telemetry Family:** network
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
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
HASHES = {
  "dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe",
  "e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d",
  "c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c",
  "6d332f814f15f19758d65026bbfd0a8c49671b319ec77b8fa1b27fc48afff7d9",
  "6506d31707a39949f89534bf9705bcf889f1ecae3dbc6f4ff88d67a8be3d01b2",
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
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Remediation and Closure

### Containment

1. Isolate hosts, runners, notebooks, and images containing any listed version after preserving the Python environment, pip cache, process tree, and network telemetry.
2. Disable affected CI jobs and package-publishing workflows until they are rebuilt from clean dependencies.
3. Revoke active GitHub, package-registry, cloud, Kubernetes, Vault, SSH, Docker, and CI/CD sessions reachable from affected environments.

### Eradication

1. Rebuild affected virtual environments, containers, and runners; do not rely on uninstalling the package because `.pth`, native-extension, workflow, and follow-on artifacts can remain.
2. Remove unauthorized GitHub repositories, workflows, deploy keys, self-hosted runners, and package publications only after preserving evidence.
3. Replace cached wheels and internal mirrors containing the listed versions and hashes.
4. Quarantine any mirror or cache path that still shows `mflux-streamlit`, `mrbios`, or the startup-hook files before those artifacts are reintroduced into a build pipeline.

### Recovery

1. Reissue secrets from a clean administrative system with least privilege and short expiry.
2. Restore builds from pinned, reviewed artifacts and verify wheel contents before re-enabling publishing.
3. Monitor source-control, registry, cloud, and deployment audit logs for post-exposure use of revoked identities.
4. Keep the PyPI quarantine snapshots with the case record so future reviewers can prove the affected packages were removed rather than merely absent from a later mirror sync.

### Closure Gates

- Every listed package/version hit is dispositioned across developer endpoints, CI runners, containers, notebooks, and internal package caches.
- No listed hash, `.pth` hook, `_index.js`, trojanized native extension, or Hades repository marker remains in retained environments.
- All secrets reachable from presumed or confirmed exposed environments are revoked and replaced.
- GitHub, registry, cloud, Kubernetes, Vault, and deployment audits show no unexplained follow-on activity through 2026-06-16.
- Archived quarantine snapshots for `mflux-streamlit` and `mrbios` are attached to the incident record.

## Sources
1. [Socket: Shai-Hulud Descends to Hades](https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave) - **Role:** PRIMARY_RESEARCH - **Impact:** Initial 37 wheels, startup-hook mechanism, payload behavior, hashes, and credential targets.
2. [Socket: Mini Shai-Hulud, Miasma, and Hades Target Bioinformatics and MCP Developers](https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious) - **Role:** PRIMARY_RESEARCH - **Impact:** June 8 expansion, 23 release artifacts, native-extension delivery, and newer hashes.
3. [StepSecurity: The Hades Campaign PyPI Packages](https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages) - **Role:** PRIMARY_RESEARCH - **Impact:** June 16 campaign update that explicitly names `mflux-streamlit` and `mrbios`.
4. [PyPI simple-index snapshots for mflux-streamlit and mrbios](https://pypi.org/simple/mflux-streamlit/) and [mrbios](https://pypi.org/simple/mrbios/) - **Role:** DIRECT_SOURCE - **Impact:** Live registry snapshots show `pypi:project-status=quarantined` and no package links for both projects; version-specific JSON endpoints returned 404 during collection.
