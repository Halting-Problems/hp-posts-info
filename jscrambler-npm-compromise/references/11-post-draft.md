---
title: "Jscrambler npm compromise drops cross-platform credential stealer"
date: 2026-07-11
summary: "Five interleaved malicious jscrambler releases executed a bundled native infostealer on developer and CI hosts."
---

## Executive Summary

Five interleaved malicious jscrambler releases executed a bundled native infostealer on developer and CI hosts. The cited researchers identify the execution trigger as npm preinstall in 8.14.0/8.16.0/8.17.0; import or CLI execution in 8.18.0/8.20.0 and the observed behavior as: drops a detached native Linux, Windows, or macOS credential and wallet stealer from dist/intro.js. [1] [2]

Responders should treat a matching malicious version as exposure and seek execution or egress evidence before asserting data theft. Secrets at risk include browser credentials, cloud credentials, developer tokens, AI-tool/MCP secrets, and cryptocurrency wallets. No public victim count is treated as verified. [1] [2]

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected artifacts** | jscrambler |
| **Ecosystem** | npm |
| **Malicious versions** | jscrambler@8.14.0, jscrambler@8.16.0, jscrambler@8.17.0, jscrambler@8.18.0, jscrambler@8.20.0 |
| **Disclosure** | 2026-07-11 |
| **Verified recovery direction** | jscrambler@8.22.0 |

## Evidence Assessment

| Assessment | Claim | Evidence |
| --- | --- | --- |
| Confirmed | Listed package versions carried or transitively resolved malicious code. | Static package analysis and version comparison by the cited researchers. [1] [2] |
| Confirmed | Trigger: npm preinstall in 8.14.0/8.16.0/8.17.0; import or CLI execution in 8.18.0/8.20.0. | Source-level or compiled-artifact analysis. [1] [2] |
| Confirmed | drops a detached native Linux, Windows, or macOS credential and wallet stealer from dist/intro.js. | Decompiled/static analysis and reported telemetry where available. [1] [2] |
| Unclear | Number of affected organizations or successful thefts. | Neither source establishes a verified victim count. |

## Impact Determination

| Classification | Criteria | Required evidence | Action | Closure gate |
| --- | --- | --- | --- | --- |
| Exposure | Malicious selector in a lockfile, cache, or inventory | Preserve dependency graph and cache metadata | Isolate affected workload and determine whether trigger ran | Every matching host classified |
| Likely execution | Install/load logs or files align with the trigger | Process, file, CI, application, and egress timeline | Rebuild and rotate reachable secrets | Negative rescan and completed rotations |
| Confirmed compromise | IOC egress, payload hash, or theft/abuse evidence | Proxy/EDR evidence with UTC timestamps | Incident response and downstream abuse review | Abuse review, recovery monitoring, and evidence sign-off |

## Minimum Evidence To Collect

- **Dependency evidence:** preserve lockfiles, SBOMs, package-manager caches, and CI restore/install logs; they identify exact versions and resolve exposure classification.
- **Execution evidence:** collect EDR process/file events and application or assembly-load logs around dependency use; they determine whether npm preinstall in 8.14.0/8.16.0/8.17.0; import or CLI execution in 8.18.0/8.20.0 occurred.
- **Network evidence:** retain DNS, proxy, firewall, and TLS metadata for check.torproject.org, archive.torproject.org, 37.27.122.124, 57.128.246.79; a matching outbound event materially raises confidence.
- **Identity evidence:** export audit logs for identities holding browser credentials, cloud credentials, developer tokens, AI-tool/MCP secrets, and cryptocurrency wallets; these decide credential rotation scope and whether downstream abuse occurred.

## Timeline

- **2026-07-11 (UTC; exact time varies by artifact):** malicious publication/discovery activity documented by the cited researchers. [1] [2]
- **2026-07-11:** public technical reporting and defensive guidance published. [1] [2]
- **Current registry removal status:** unknown after this source-only review; validate through metadata-only registry queries before publication.

## What Happened

The incident abused trusted package distribution or a deceptive package identity to deliver code that looked compatible with expected developer workflows. It then used npm preinstall in 8.14.0/8.16.0/8.17.0; import or CLI execution in 8.18.0/8.20.0 to activate and drops a detached native Linux, Windows, or macOS credential and wallet stealer from dist/intro.js. [1] [2]

## Technical Analysis

### Initial Access
The affected artifacts were distributed through npm package channels. This folder does not infer an actor identity beyond source-supported account or publishing-path facts. [1] [2]

### Execution Trigger
Npm preinstall in 8.14.0/8.16.0/8.17.0; import or cli execution in 8.18.0/8.20.0. [1] [2]

### Payload Behavior
The observed payload drops a detached native Linux, Windows, or macOS credential and wallet stealer from dist/intro.js. [1] [2]

### Credential or Data Collection
The defensible exposure set is browser credentials, cloud credentials, developer tokens, AI-tool/MCP secrets, and cryptocurrency wallets. Rotate only after preserving evidence and mapping which secrets were available to the affected process. [1] [2]

### Defense Evasion
The source reporting describes deceptive naming, silent failure, obfuscation, or trigger placement intended to reduce discovery. Do not generalize beyond the specific files and selectors in this packet. [1] [2]

### Exfiltration and Command and Control
Observed network selectors are check.torproject.org, archive.torproject.org, 37.27.122.124, 57.128.246.79. Human-readable prose is defanged where shown; raw values remain in `iocs.json`. [1] [2]

## Affected Assets and Blast Radius

| Asset | Exposure path | Priority |
| --- | --- | --- |
| Developer workstations | dependency installed, imported, or loaded | High |
| CI/build runners | package restore plus secrets in job context | Critical |
| Production applications | runtime trigger or assembly use | Critical |
| Downstream identities | secrets reachable by affected process | Critical |

## Indicators of Compromise

| Type | Values |
| --- | --- |
| Package versions | jscrambler@8.14.0, jscrambler@8.16.0, jscrambler@8.17.0, jscrambler@8.18.0, jscrambler@8.20.0 |
| Files | dist/setup.js, dist/intro.js |
| Domains (defanged) | check[.]torproject[.]org, archive[.]torproject[.]org |
| IPs (defanged) | 37[.]27[.]122[.]124, 57[.]128[.]246[.]79 |
| SHA-256 | a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60, a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86, fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd, b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903, c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd |

## Detection and Hunting

Run [`scripts/hunt.py`](scripts/hunt.py) against exported lockfiles, SBOMs, restore/install logs, proxy/DNS logs, or file inventories. It answers whether exact package versions, file selectors, hashes, domains, or IPs are present. A match is a triage lead; package-only matches may be false positives from documentation or cleanly quarantined caches. Escalate by preserving the matching record and correlating it with process and identity audit logs.

## Downstream Abuse Audits

Review source-control, registry, cloud, payment, wallet, and CI identity logs only where the affected process could access those services. Search from the earliest package acquisition through credential rotation for new tokens, unusual sessions, publishing, transaction changes, secret reads, and deployment activity. The reason is specific: the payload targeted browser credentials, cloud credentials, developer tokens, AI-tool/MCP secrets, and cryptocurrency wallets. [1] [2]

## Remediation and Closure

1. Preserve lockfiles, caches, process/file telemetry, and egress evidence before cleanup.
2. Stop package execution and isolate hosts with runtime or egress evidence.
3. Remove the listed versions and invalidate internal caches.
4. Rotate browser credentials, cloud credentials, developer tokens, AI-tool/MCP secrets, and cryptocurrency wallets from a clean host, prioritizing secrets present during execution.
5. Rebuild likely or confirmed hosts from verified images rather than trusting package removal alone.
6. Apply the recovery direction: jscrambler@8.22.0.
7. Audit downstream identity and transaction activity from first exposure through rotation.
8. Rescan lockfiles, caches, files, and egress exports with the tested hunter.
9. Close only after every exposed host is classified, required rotations and abuse reviews are complete, and post-recovery monitoring is clean.

## Open Questions

- How many organizations actually executed the malicious code?
- Is additional attacker infrastructure or campaign-linked packaging still active?
- What is the current registry availability/deprecation status of every listed version?

## Sources

1. **Socket**: https://socket.dev/blog/jscrambler-supply-chain-attack — primary technical research supporting package, behavior, timeline, and IOC claims; it does not prove the number of affected organizations.
2. **StepSecurity**: https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary — primary technical research supporting package, behavior, timeline, and IOC claims; it does not prove the number of affected organizations.
