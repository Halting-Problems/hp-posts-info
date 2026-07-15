---
title: "Lightning PyPI Bun-Based Credential Stealer"
date: 2026-04-30
severity: "critical"
tags:
  - pypi
  - package-compromise
  - supply-chain
  - credential-theft
  - shai-hulud
summary: "On April 30, 2026, malicious `lightning` PyPI releases 2.6.2 and 2.6.3 shipped an import-time loader that bootstrapped Bun and executed a large obfuscated JavaScript credential stealer."
sourceCount: 4
draftStatus: "packet-draft"
---

## Executive Summary
On April 30, 2026, two malicious releases of the legitimate PyPI package `lightning` were published as versions `2.6.2` and `2.6.3` [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). The package is the modern distribution name for the PyTorch Lightning deep learning framework, making the compromise materially different from a lookalike or typosquat [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

The malicious wheels added a hidden `_runtime` directory that executed when Python code imported `lightning`, downloaded the Bun JavaScript runtime from GitHub, and used it to run an approximately 11 MB obfuscated JavaScript credential stealer named `router_runtime.js` [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). The payload targeted GitHub tokens, npm tokens, cloud credentials, metadata services, local environment variables, and developer credential files [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). Snyk tracks the incident as `SNYK-PYTHON-LIGHTNING-16323121` and `CVE-2026-44484` with critical severity [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-LIGHTNING-16323121).

## Key Facts
```yaml
threat_type: "legitimate package compromise, import-time credential stealer"
ecosystem: "pypi, python"
registry: "PyPI"
affected_packages:
  - "lightning"
malicious_versions:
  - "2.6.2"
  - "2.6.3"
known_good_versions:
  - "2.6.1"
execution_trigger: "import lightning"
primary_impact: "Developer, CI/CD, npm, GitHub, and cloud credential theft"
campaign_context: "Mini Shai-Hulud-style Bun payload reuse; exact attribution remains vendor-disputed"
known_iocs:
  - "lightning/_runtime/start.py"
  - "lightning/_runtime/router_runtime.js"
  - "github.com/oven-sh/bun/releases/download/bun-v1.3.13"
  - "api.github.com/user"
  - "registry.npmjs.org/-/whoami"
confidence: "high"
canonical_source: "https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/"
```

## Source Confidence & Evidence Mapping
* **confirmed:** `lightning` versions `2.6.2` and `2.6.3` were malicious and are covered by Snyk advisory `SNYK-PYTHON-LIGHTNING-16323121` / `CVE-2026-44484` [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-LIGHTNING-16323121).
* **confirmed:** The malicious execution chain runs automatically on module import and launches a background process with suppressed output [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).
* **confirmed:** The payload uses Bun to execute a large obfuscated JavaScript credential stealer that targets cloud and developer credentials [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).
* **likely:** The publishing path involved compromised long-lived PyPI publishing credentials rather than a normal source-controlled release workflow [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).
* **unclear:** Vendors differ on whether the operator is the original Shai-Hulud actor, a copycat, or a related cluster reusing the same payload family [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

## Timeline
- **2026-01-30T00:00:00Z** `lightning==2.6.1` is identified by Snyk as the last clean release before the compromise [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).
- **2026-04-30T00:00:00Z** Malicious `lightning==2.6.2` and `lightning==2.6.3` releases are published to PyPI [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).
- **2026-04-30T00:00:00Z** Snyk publishes advisory coverage for the affected releases [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-LIGHTNING-16323121).
- **2026-05-01T00:00:00Z** Sonatype updates its public analysis to include additional packages connected to the wider wave [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).

## What Happened
Attackers published malicious versions of the legitimate `lightning` package, preserving the expected framework code while adding a hidden runtime directory [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/). When an affected environment imported `lightning`, the modified initialization path launched a background thread that invoked `_runtime/start.py` with output redirected away from the console [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

The Python bootstrapper fetched Bun from GitHub releases and used it to execute `router_runtime.js`, a large obfuscated JavaScript payload [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). That design let the attackers reuse JavaScript supply-chain malware inside a Python ecosystem package instead of rewriting the stealer in Python [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

## Technical Analysis
### Initial Access
The available evidence points to a compromised package publishing path for the real `lightning` project rather than a typosquat [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/). Snyk notes that `2.6.3` did not correspond to a normal GitHub release or tag, which supports a registry-side upload using stolen publishing authority [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

### Execution Trigger
Execution begins when Python imports the package [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). This is more dangerous than a CLI-only path because notebooks, smoke tests, version checks, and CI import probes can all trigger the background payload.

### Payload Behavior
The payload searches for GitHub tokens, npm tokens, cloud provider credentials, environment variables, local credential files, and cloud metadata service material [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). Snyk also reports repository poisoning and npm tarball mutation logic consistent with a worm-capable supply-chain payload [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

## Detection and Hunting
```yaml
hunt_queries:
  dependency_lockfiles:
    - "lightning==2.6.2"
    - "lightning==2.6.3"
  filesystem:
    - "lightning/_runtime/start.py"
    - "lightning/_runtime/router_runtime.js"
    - ".claude/router_runtime.js"
    - ".vscode/setup.mjs"
    - ".github/workflows/format-check.yml"
  process_and_network:
    - "unexpected bun execution spawned by python"
    - "github.com/oven-sh/bun/releases/download/bun-v1.3.13"
    - "api.github.com/user from build runners after importing lightning"
    - "registry.npmjs.org/-/whoami from non-npm automation"
```

## Remediation Workflow
* **Immediate:** Remove `lightning==2.6.2` and `lightning==2.6.3`; pin to `2.6.1` or remove the dependency until a confirmed clean release is available [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).
* **Immediate:** Treat any machine or runner that installed and imported the affected versions as compromised; rotate GitHub, npm, PyPI, cloud, and CI/CD credentials from a clean environment [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).
* **Short-term:** Audit GitHub repositories for unauthorized branches, commits, workflow changes, `.claude` files, `.vscode` task changes, and unexpected commit identities [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).
* **Long-term:** Require package provenance checks, block newly published high-risk versions with a cooldown policy, and prefer PyPI Trusted Publishing over long-lived API tokens.

## Open Questions
- Was the PyPI publisher credential stolen from a developer workstation, a service account, or CI/CD secrets?
- Which downstream organizations imported the malicious versions before quarantine or removal?
- Is the operator the same actor behind earlier Shai-Hulud waves or a payload-reuse copycat?

## Sources
1. [Snyk: lightning PyPI Compromise](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) - **Role:** PRIMARY_RESEARCH - **Impact:** Package versions, import-time execution chain, Bun loader, payload behavior, publishing-path analysis.
2. [Snyk Vulnerability Database: SNYK-PYTHON-LIGHTNING-16323121](https://security.snyk.io/vuln/SNYK-PYTHON-LIGHTNING-16323121) - **Role:** ENRICHMENT_DATA - **Impact:** Advisory ID, CVE, affected versions, critical severity.
3. [Sonatype: Malicious PyTorch Lightning Packages Found on PyPI](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true) - **Role:** PRIMARY_RESEARCH - **Impact:** Cross-vendor corroboration, affected versions, credential theft and propagation behavior.
4. [PyPI project page: lightning](https://pypi.org/project/lightning/) - **Role:** DIRECT_SOURCE - **Impact:** Registry context and package identity.

---
### Machine-Readable Event Profile (Format B)
```json
[
  {
    "event_id": "lightning-pypi-bun-stealer-2026-04-30",
    "event_name": "Lightning PyPI Bun-Based Credential Stealer",
    "parent_campaign_id": "mini-shai-hulud-2026-04",
    "is_campaign_level": false,
    "confidence": "high",
    "confidence_reason": "Affected versions and malicious behavior are corroborated by Snyk advisory data, Snyk technical analysis, and Sonatype research.",
    "attack_types": ["malicious package", "maintainer account compromise", "package registry compromise", "credential theft", "token exfiltration", "self-replicating worm"],
    "direct_sources": [
      { "name": "PyPI project page: lightning", "url": "https://pypi.org/project/lightning/" }
    ],
    "correlated_sources": [
      { "name": "Snyk lightning PyPI Compromise", "url": "https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/", "role": "PRIMARY_RESEARCH", "contribution": "technical analysis and timeline" },
      { "name": "Snyk Vulnerability Database", "url": "https://security.snyk.io/vuln/SNYK-PYTHON-LIGHTNING-16323121", "role": "ENRICHMENT_DATA", "contribution": "advisory identifiers and affected versions" },
      { "name": "Sonatype Security Research", "url": "https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true", "role": "PRIMARY_RESEARCH", "contribution": "cross-vendor corroboration" }
    ],
    "affected_assets": {
      "ecosystems": ["pypi", "python"],
      "packages": ["lightning"],
      "versions": ["2.6.2", "2.6.3"],
      "repositories": ["Lightning-AI/pytorch-lightning"],
      "vendors": ["Lightning AI"],
      "CI_CD_systems": ["GitHub Actions", "developer CI runners"],
      "container_images": [],
      "developer_tools": ["Python notebooks", "developer workstations"]
    },
    "timeline": {
      "first_seen": "2026-04-30T00:00:00Z",
      "malicious_publish_time": "2026-04-30T00:00:00Z",
      "discovery_time": "2026-04-30T00:00:00Z",
      "removal_time": "N/A",
      "disclosure_time": "2026-04-30T00:00:00Z",
      "patch_or_fix_time": "N/A"
    },
    "matching_signals": {
      "package_names": ["lightning"],
      "affected_versions": ["2.6.2", "2.6.3"],
      "identifiers": { "cve": "CVE-2026-44484", "ghsa": "N/A", "osv": "N/A" },
      "shared_claims": "Import-time Bun loader runs obfuscated router_runtime.js credential stealer.",
      "shared_root_cause": "Compromised package publishing authority.",
      "shared_affected_parties": "Python ML developers, CI/CD runners, and projects importing lightning."
    },
    "iocs": {
      "domains": ["github.com", "api.github.com", "registry.npmjs.org"],
      "ips": [],
      "urls": ["https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/", "https://api.github.com/user", "https://registry.npmjs.org/-/whoami"],
      "hashes": ["8046a11187c135da6959862ff3846e99ad15462d2ec8a2f77a30ad53ebd5dcf2", "5f5852b5f604369945118937b058e49064612ac69826e0adadca39a357dfb5b1"],
      "scripts": ["lightning/_runtime/start.py", "lightning/_runtime/router_runtime.js"]
    },
    "defender_takeaways": {
      "detection": "Block and alert on lightning 2.6.2 and 2.6.3, unexpected Bun downloads from Python processes, and large obfuscated runtime files in Python wheels.",
      "hunting": "Search for import-time Python subprocesses, Bun execution, GitHub repository mutations, npm token validation, and affected dependency locks.",
      "remediation": "Remove bad versions, rotate exposed credentials, audit repositories for unauthorized commits, and rebuild affected runners.",
      "prevention": "Use provenance checks, dependency cooldown policies, PyPI Trusted Publishing, and runtime egress controls for CI/CD."
    }
  }
]
```
