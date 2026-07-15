---
title: "intercom-client npm Mini Shai-Hulud Compromise"
date: 2026-04-30
severity: "critical"
tags:
  - npm
  - package-compromise
  - supply-chain
  - credential-theft
  - shai-hulud
summary: "On April 30, 2026, `intercom-client@7.0.4` on npm introduced a first-ever `preinstall` hook that executed a Bun-launched obfuscated credential stealer and exfiltrated secrets through GitHub APIs."
sourceCount: 5
draftStatus: "packet-draft"
---

## Executive Summary
On April 30, 2026, `intercom-client@7.0.4`, the official Node.js SDK for Intercom, was published to npm with a malicious `preinstall` hook and two undocumented files: `setup.mjs` and `router_runtime.js` [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack). StepSecurity reports that the package had roughly 361,510 weekly downloads at the time and that the malicious version was published through an OIDC-backed GitHub Actions publisher path [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).

The malicious release preserved the legitimate SDK while adding `"preinstall": "node setup.mjs"` to `package.json` [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack). `setup.mjs` bootstrapped Bun and executed an approximately 11.7 MB obfuscated JavaScript payload, `router_runtime.js`, designed to harvest GitHub, npm, and multi-cloud credentials [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack). Both StepSecurity and Upwind associate the activity with the Mini Shai-Hulud campaign pattern targeting CI/CD and developer credentials [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack).

## Key Facts
```yaml
threat_type: "npm package compromise, preinstall credential stealer"
ecosystem: "npm, javascript"
registry: "npm"
affected_packages:
  - "intercom-client"
malicious_versions:
  - "7.0.4"
known_good_versions:
  - "7.0.3"
execution_trigger: "npm install lifecycle preinstall hook"
primary_impact: "GitHub, npm, AWS, GCP, Azure, and CI/CD secret theft"
campaign_context: "Mini Shai-Hulud wave"
known_iocs:
  - "setup.mjs"
  - "router_runtime.js"
  - "\"preinstall\": \"node setup.mjs\""
  - "api.github.com/user"
  - "private repository creation under victim GitHub account"
confidence: "high"
canonical_source: "https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked"
```

## Source Confidence & Evidence Mapping
* **confirmed:** `intercom-client@7.0.4` introduced a `preinstall` hook that was absent from prior releases [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack).
* **confirmed:** The malicious release added `setup.mjs` and `router_runtime.js`, which did not exist in prior releases or the upstream GitHub repository [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack).
* **confirmed:** The package unpacked size increased from roughly 6 MB to 17.8 MB, with the payload file accounting for the bulk of the anomaly [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).
* **confirmed:** StepSecurity reports that `7.0.3` had SLSA provenance attestations while `7.0.4` did not, making provenance absence a strong artifact-integrity signal [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).
* **likely:** The package compromise is part of the same Mini Shai-Hulud wave as nearby SAP npm, Lightning PyPI, and Intercom PHP events, based on payload structure and GitHub-based exfiltration behavior [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack).

## Timeline
- **2026-04-30T14:41:00Z** `intercom-client@7.0.4` is published to npm with the malicious changes [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).
- **2026-04-30T00:00:00Z** Upwind detects the malicious version through scanning of newly published npm versions [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack).
- **2026-04-30T00:00:00Z** Intercom status pages report investigation of a malicious `intercom-client` version and later note related `intercom-php` compromise activity [IsDown mirror of Intercom status](https://isdown.app/status/intercom-eu/incidents/579611-investigating-compromised-version-of-intercom-client-npm-package).
- **2026-05-01T00:00:00Z** Snyk advisory coverage for the related Composer package `intercom/intercom-php` confirms the same Bun-plus-`router_runtime.js` malicious behavior in the adjacent ecosystem [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PHP-INTERCOMINTERCOMPHP-16329836).

## What Happened
Attackers published a malicious patch version of the official `intercom-client` package. The SDK remained functional, but package installation now triggered `setup.mjs` before normal install completion through npm's `preinstall` lifecycle hook [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack).

The loader acquired or reused Bun and executed `router_runtime.js`, a single-line obfuscated payload of roughly 11.7 MB [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack). Exfiltration used the victim's own GitHub access: the payload authenticated to `api.github.com/user`, created a private repository, encrypted harvested secrets, and committed them there [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).

## Technical Analysis
### Initial Access
StepSecurity reports that `intercom-client@7.0.4` was published through a GitHub Actions OIDC publisher path, but the artifact lost the SLSA attestations present in `7.0.3` [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked). That combination points to compromise or abuse of the publishing path, not a normal tagged release.

### Package or Artifact Manipulation
The malicious diff centered on one lifecycle hook and two new files: `"preinstall": "node setup.mjs"`, `setup.mjs`, and `router_runtime.js` [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack). The package size tripled in a single patch bump, a reliable anomaly for an SDK with no historical install hook [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).

### Payload Behavior
The stealer targets GitHub, npm, and multi-cloud credentials [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack). StepSecurity reports token regex patterns for GitHub and npm tokens and a GitHub-only C2 path that creates private repositories under victim accounts [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).

## Detection and Hunting
```yaml
hunt_queries:
  package_locks:
    - "intercom-client@7.0.4"
  package_json:
    - "\"preinstall\": \"node setup.mjs\""
  filesystem:
    - "node_modules/intercom-client/setup.mjs"
    - "node_modules/intercom-client/router_runtime.js"
  artifact_anomalies:
    - "intercom-client unpackedSize around 17.8 MB"
    - "intercom-client release without SLSA provenance attestation"
  github:
    - "new private repositories created shortly after npm install"
    - "api.github.com/user requests from package install contexts"
  network:
    - "unexpected Bun download during npm install"
```

## Remediation Workflow
* **Immediate:** Remove `intercom-client@7.0.4` and pin to `7.0.3` or a later maintainer-confirmed clean version [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).
* **Immediate:** Rotate GitHub, npm, cloud provider, CI/CD, and environment secrets reachable from machines or runners that installed the malicious version [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Upwind](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack).
* **Short-term:** Audit GitHub accounts for unexpected private repositories, suspicious branch/commit activity, and repository mutations after dependency installation [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).
* **Short-term:** Search package locks, npm cache, artifact registries, and CI logs for `intercom-client@7.0.4`, `setup.mjs`, `router_runtime.js`, and Bun execution.
* **Long-term:** Enforce provenance attestation checks, `npm ci --ignore-scripts` where feasible, dependency cooldowns, package size anomaly gates, and release approval on registry publishing workflows.

## Open Questions
- Which upstream credential or publishing workflow allowed the malicious npm version to be published?
- How many victim GitHub private repositories were created for exfiltration?
- Should the Intercom npm and Composer compromises be modeled as one campaign-level event or separate registry-specific events for remediation tracking?

## Sources
1. [StepSecurity: Shai-Hulud Worm Pivots to Multi-Cloud](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) - **Role:** PRIMARY_RESEARCH - **Impact:** Timeline, package diff, provenance signal, GitHub exfiltration behavior.
2. [Upwind: intercom-client 7.0.4 Supply Chain Attack](https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack) - **Role:** PRIMARY_RESEARCH - **Impact:** Independent detection, loader description, payload files.
3. [Intercom incident status mirror](https://isdown.app/status/intercom-eu/incidents/579611-investigating-compromised-version-of-intercom-client-npm-package) - **Role:** DIRECT_SOURCE - **Impact:** Vendor-status evidence of investigation and related PHP compromise timing.
4. [Snyk Vulnerability Database: intercom/intercom-php](https://security.snyk.io/vuln/SNYK-PHP-INTERCOMINTERCOMPHP-16329836) - **Role:** ENRICHMENT_DATA - **Impact:** Adjacent ecosystem corroboration for the same Bun and `router_runtime.js` behavior.
5. [Kodem: Mini Shai-Hulud Cross-Ecosystem Attack](https://www.kodemsecurity.com/resources/mini-shai-hulud-strikes-pytorch-lightning-and-intercom-client-inside-the-cross-ecosystem-supply-chain-attack) - **Role:** SECONDARY_ANALYSIS - **Impact:** Cross-ecosystem campaign framing across Lightning and Intercom.

---
### Machine-Readable Event Profile (Format B)
```json
[
  {
    "event_id": "intercom-client-npm-shai-hulud-2026-04-30",
    "event_name": "intercom-client npm Mini Shai-Hulud Compromise",
    "parent_campaign_id": "mini-shai-hulud-2026-04",
    "is_campaign_level": false,
    "confidence": "high",
    "confidence_reason": "StepSecurity and Upwind independently confirm the malicious package diff, affected version, loader files, and credential theft behavior.",
    "attack_types": ["malicious package", "CI/CD compromise", "poisoned release", "credential theft", "token exfiltration", "self-replicating worm"],
    "direct_sources": [
      { "name": "Intercom incident status mirror", "url": "https://isdown.app/status/intercom-eu/incidents/579611-investigating-compromised-version-of-intercom-client-npm-package" }
    ],
    "correlated_sources": [
      { "name": "StepSecurity Intercom analysis", "url": "https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked", "role": "PRIMARY_RESEARCH", "contribution": "version diff, publish metadata, and exfiltration behavior" },
      { "name": "Upwind Intercom analysis", "url": "https://www.upwind.io/feed/intercom-client-7-0-4-supply-chain-attack", "role": "PRIMARY_RESEARCH", "contribution": "independent detection and payload description" },
      { "name": "Snyk intercom/intercom-php advisory", "url": "https://security.snyk.io/vuln/SNYK-PHP-INTERCOMINTERCOMPHP-16329836", "role": "ENRICHMENT_DATA", "contribution": "related Composer ecosystem payload corroboration" }
    ],
    "affected_assets": {
      "ecosystems": ["npm", "javascript"],
      "packages": ["intercom-client"],
      "versions": ["7.0.4"],
      "repositories": ["intercom/intercom-node"],
      "vendors": ["Intercom"],
      "CI_CD_systems": ["GitHub Actions", "npm publishing pipeline"],
      "container_images": [],
      "developer_tools": ["Node.js package managers", "CI runners"]
    },
    "timeline": {
      "first_seen": "2026-04-30T14:41:00Z",
      "malicious_publish_time": "2026-04-30T14:41:00Z",
      "discovery_time": "2026-04-30T00:00:00Z",
      "removal_time": "N/A",
      "disclosure_time": "2026-04-30T00:00:00Z",
      "patch_or_fix_time": "N/A"
    },
    "matching_signals": {
      "package_names": ["intercom-client"],
      "affected_versions": ["7.0.4"],
      "identifiers": { "cve": "N/A", "ghsa": "N/A", "osv": "N/A" },
      "shared_claims": "First-ever preinstall hook launches setup.mjs and router_runtime.js credential stealer.",
      "shared_root_cause": "Compromised or abused npm publishing path.",
      "shared_affected_parties": "Node.js developers, CI/CD runners, and Intercom SDK consumers."
    },
    "iocs": {
      "domains": ["api.github.com"],
      "ips": [],
      "urls": ["https://api.github.com/user"],
      "hashes": [],
      "scripts": ["setup.mjs", "router_runtime.js", "package.json preinstall hook"]
    },
    "defender_takeaways": {
      "detection": "Alert on intercom-client 7.0.4, first-seen install hooks, large package-size jumps, absent SLSA attestations, and Bun execution during npm install.",
      "hunting": "Search dependency locks, npm caches, CI logs, and GitHub accounts for malicious install artifacts and exfiltration repositories.",
      "remediation": "Remove the bad version, rotate exposed credentials, inspect GitHub account activity, and rebuild affected runners.",
      "prevention": "Enforce provenance checks, dependency cooldowns, lifecycle-script restrictions, package-size anomaly review, and least-privilege publish workflows."
    }
  }
]
```
