---
title: "Paysafe, Skrill, and Neteller npm/PyPI typosquats steal developer secrets"
date: 2026-07-07
summary: "Seventeen coordinated payment-brand typosquats across npm and PyPI impersonated SDKs and exfiltrated environment secrets to an ngrok host."
severity: high
sourceCount: 1
tags: ["software-supply-chain", "malicious-package", "credential-theft"]
---

## Executive Summary

Seventeen coordinated payment-brand typosquats across npm and PyPI impersonated SDKs and exfiltrated environment secrets to an ngrok host. The cited researchers identify the execution trigger as npm SDK method use when an API key is configured; PyPI package import and the observed behavior as: fingerprints hosts and exfiltrates environment variables whose names contain key, secret, token, pass, auth, or api. [1]

Responders should treat a matching malicious version as exposure and seek execution or egress evidence before asserting data theft. Secrets at risk include payment API keys, cloud secrets, source-control tokens, registry tokens, passwords, and CI credentials. No public victim count is treated as verified. [1]

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected artifacts** | paysafe-checkout, paysafe-vault, neteller, skrill-payments, paysafe-js, paysafe-api, paysafe-node, paysafe-cards, paysafe-fraud, paysafe-kyc, skrill, skrill-sdk, paysafe-payments, pypi:paysafe-kyc, pypi:paysafe-payments, pypi:paysafe-sdk, pypi:paysafe-api |
| **Ecosystem** | npm,pypi |
| **Malicious versions** | paysafe-checkout@1.0.0, paysafe-checkout@1.0.1, paysafe-checkout@1.0.2, paysafe-checkout@1.0.3, paysafe-vault@1.0.0, paysafe-vault@1.0.1, paysafe-vault@1.0.2, paysafe-vault@1.0.3, neteller@1.0.0, neteller@1.0.1, neteller@1.0.2, neteller@1.0.3, skrill-payments@1.0.0, skrill-payments@1.0.1, skrill-payments@1.0.2, skrill-payments@1.0.3, paysafe-js@1.0.0, paysafe-js@1.0.1, paysafe-js@1.0.2, paysafe-js@1.0.3, paysafe-api@1.0.0, paysafe-api@1.0.1, paysafe-api@1.0.2, paysafe-api@1.0.3, paysafe-node@1.0.0, paysafe-node@1.0.1, paysafe-node@1.0.2, paysafe-node@1.0.3, paysafe-cards@1.0.0, paysafe-cards@1.0.1, paysafe-cards@1.0.2, paysafe-cards@1.0.3, paysafe-fraud@1.0.0, paysafe-fraud@1.0.1, paysafe-fraud@1.0.2, paysafe-fraud@1.0.3, paysafe-kyc@1.0.0, paysafe-kyc@1.0.1, paysafe-kyc@1.0.2, paysafe-kyc@1.0.3, skrill@1.0.0, skrill@1.0.1, skrill@1.0.2, skrill@1.0.3, skrill-sdk@1.0.0, skrill-sdk@1.0.1, skrill-sdk@1.0.2, skrill-sdk@1.0.3, paysafe-payments@1.0.0, paysafe-payments@1.0.1, paysafe-payments@1.0.2, paysafe-payments@1.0.3, pypi:paysafe-kyc@1.0.0, pypi:paysafe-payments@1.0.0, pypi:paysafe-sdk@1.0.0, pypi:paysafe-api@1.0.0 |
| **Disclosure** | 2026-07-07 |
| **Verified recovery direction** | remove campaign packages and replace only with vendor-verified SDKs |

## Evidence Assessment

| Assessment | Claim | Evidence |
| --- | --- | --- |
| Confirmed | Listed package versions carried or transitively resolved malicious code. | Static package analysis and version comparison by the cited researchers. [1] |
| Confirmed | Trigger: npm SDK method use when an API key is configured; PyPI package import. | Source-level or compiled-artifact analysis. [1] |
| Confirmed | fingerprints hosts and exfiltrates environment variables whose names contain key, secret, token, pass, auth, or api. | Decompiled/static analysis and reported telemetry where available. [1] |
| Unclear | Number of affected organizations or successful thefts. | Neither source establishes a verified victim count. |

## Impact Determination

| Classification | Criteria | Required evidence | Action | Closure gate |
| --- | --- | --- | --- | --- |
| Exposure | Malicious selector in a lockfile, cache, or inventory | Preserve dependency graph and cache metadata | Isolate affected workload and determine whether trigger ran | Every matching host classified |
| Likely execution | Install/load logs or files align with the trigger | Process, file, CI, application, and egress timeline | Rebuild and rotate reachable secrets | Negative rescan and completed rotations |
| Confirmed compromise | IOC egress, payload hash, or theft/abuse evidence | Proxy/EDR evidence with UTC timestamps | Incident response and downstream abuse review | Abuse review, recovery monitoring, and evidence sign-off |

## Minimum Evidence To Collect

- **Dependency evidence:** preserve lockfiles, SBOMs, package-manager caches, and CI restore/install logs; they identify exact versions and resolve exposure classification.
- **Execution evidence:** collect EDR process/file events and application or assembly-load logs around dependency use; they determine whether npm SDK method use when an API key is configured; PyPI package import occurred.
- **Network evidence:** retain DNS, proxy, firewall, and TLS metadata for caliber-spinner-finishing.ngrok-free.dev; a matching outbound event materially raises confidence.
- **Identity evidence:** export audit logs for identities holding payment API keys, cloud secrets, source-control tokens, registry tokens, passwords, and CI credentials; these decide credential rotation scope and whether downstream abuse occurred.

## Timeline

- **2026-07-07 (UTC; exact time varies by artifact):** malicious publication/discovery activity documented by the cited researchers. [1]
- **2026-07-07:** public technical reporting and defensive guidance published. [1]
- **Current registry removal status:** unknown after this source-only review; validate through metadata-only registry queries before publication.

## What Happened

The incident abused trusted package distribution or a deceptive package identity to deliver code that looked compatible with expected developer workflows. It then used npm SDK method use when an API key is configured; PyPI package import to activate and fingerprints hosts and exfiltrates environment variables whose names contain key, secret, token, pass, auth, or api. [1]

## Technical Analysis

### Initial Access
The affected artifacts were distributed through npm,pypi package channels. This folder does not infer an actor identity beyond source-supported account or publishing-path facts. [1]

### Execution Trigger
Npm sdk method use when an api key is configured; pypi package import. [1]

### Payload Behavior
The observed payload fingerprints hosts and exfiltrates environment variables whose names contain key, secret, token, pass, auth, or api. [1]

### Credential or Data Collection
The defensible exposure set is payment API keys, cloud secrets, source-control tokens, registry tokens, passwords, and CI credentials. Rotate only after preserving evidence and mapping which secrets were available to the affected process. [1]

### Defense Evasion
The source reporting describes deceptive naming, silent failure, obfuscation, or trigger placement intended to reduce discovery. Do not generalize beyond the specific files and selectors in this packet. [1]

### Exfiltration and Command and Control
Observed network selectors are caliber-spinner-finishing.ngrok-free.dev. Human-readable prose is defanged where shown; raw values remain in `iocs.json`. [1]

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
| Package versions | paysafe-checkout@1.0.0, paysafe-checkout@1.0.1, paysafe-checkout@1.0.2, paysafe-checkout@1.0.3, paysafe-vault@1.0.0, paysafe-vault@1.0.1, paysafe-vault@1.0.2, paysafe-vault@1.0.3, neteller@1.0.0, neteller@1.0.1, neteller@1.0.2, neteller@1.0.3, skrill-payments@1.0.0, skrill-payments@1.0.1, skrill-payments@1.0.2, skrill-payments@1.0.3, paysafe-js@1.0.0, paysafe-js@1.0.1, paysafe-js@1.0.2, paysafe-js@1.0.3, paysafe-api@1.0.0, paysafe-api@1.0.1, paysafe-api@1.0.2, paysafe-api@1.0.3, paysafe-node@1.0.0, paysafe-node@1.0.1, paysafe-node@1.0.2, paysafe-node@1.0.3, paysafe-cards@1.0.0, paysafe-cards@1.0.1, paysafe-cards@1.0.2, paysafe-cards@1.0.3, paysafe-fraud@1.0.0, paysafe-fraud@1.0.1, paysafe-fraud@1.0.2, paysafe-fraud@1.0.3, paysafe-kyc@1.0.0, paysafe-kyc@1.0.1, paysafe-kyc@1.0.2, paysafe-kyc@1.0.3, skrill@1.0.0, skrill@1.0.1, skrill@1.0.2, skrill@1.0.3, skrill-sdk@1.0.0, skrill-sdk@1.0.1, skrill-sdk@1.0.2, skrill-sdk@1.0.3, paysafe-payments@1.0.0, paysafe-payments@1.0.1, paysafe-payments@1.0.2, paysafe-payments@1.0.3, pypi:paysafe-kyc@1.0.0, pypi:paysafe-payments@1.0.0, pypi:paysafe-sdk@1.0.0, pypi:paysafe-api@1.0.0 |
| Files | index.js, __init__.py |
| Domains (defanged) | caliber-spinner-finishing[.]ngrok-free[.]dev |
| IPs (defanged) | None published |
| SHA-256 | See source; no compact hash set included here |

## Detection and Hunting

Run [`scripts/hunt.py`](scripts/hunt.py) against exported lockfiles, SBOMs, restore/install logs, proxy/DNS logs, or file inventories. It answers whether exact package versions, file selectors, hashes, domains, or IPs are present. A match is a triage lead; package-only matches may be false positives from documentation or cleanly quarantined caches. Escalate by preserving the matching record and correlating it with process and identity audit logs.

## Downstream Abuse Audits

Review source-control, registry, cloud, payment, wallet, and CI identity logs only where the affected process could access those services. Search from the earliest package acquisition through credential rotation for new tokens, unusual sessions, publishing, transaction changes, secret reads, and deployment activity. The reason is specific: the payload targeted payment API keys, cloud secrets, source-control tokens, registry tokens, passwords, and CI credentials. [1]

## Remediation and Recovery Gates

1. Preserve lockfiles, caches, process/file telemetry, and egress evidence before cleanup.
2. Stop package execution and isolate hosts with runtime or egress evidence.
3. Remove the listed versions and invalidate internal caches.
4. Rotate payment API keys, cloud secrets, source-control tokens, registry tokens, passwords, and CI credentials from a clean host, prioritizing secrets present during execution.
5. Rebuild likely or confirmed hosts from verified images rather than trusting package removal alone.
6. Apply the recovery direction: remove campaign packages and replace only with vendor-verified SDKs.
7. Audit downstream identity and transaction activity from first exposure through rotation.
8. Rescan lockfiles, caches, files, and egress exports with the tested hunter.
9. Close only after every exposed host is classified, required rotations and abuse reviews are complete, and post-recovery monitoring is clean.

## Open Questions

- How many organizations actually executed the malicious code?
- Is additional attacker infrastructure or campaign-linked packaging still active?
- What is the current registry availability/deprecation status of every listed version?

## Sources

1. https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps — **Socket** — primary technical research supporting package, behavior, timeline, and IOC claims; it does not prove the number of affected organizations.
