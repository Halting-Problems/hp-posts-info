---
title: "Braintree.Net NuGet typosquat skims cards and merchant credentials"
date: 2026-07-09
summary: "A fake Braintree-compatible NuGet package used production-only payment hooks and a companion module initializer to steal card and host secrets."
severity: high
sourceCount: 1
tags: ["software-supply-chain", "malicious-package", "credential-theft"]
---

## Executive Summary

A fake Braintree-compatible NuGet package used production-only payment hooks and a companion module initializer to steal card and host secrets. The cited researchers identify the execution trigger as .NET module initialization, production gateway configuration, and payment API calls and the observed behavior as: intercepts PAN/CVV, steals Braintree merchant keys, and harvests environment, config, cloud, and container secrets. [1]

Responders should treat a matching malicious version as exposure and seek execution or egress evidence before asserting data theft. Secrets at risk include payment card data, Braintree merchant credentials, connection strings, cloud credentials, and CI tokens. No public victim count is treated as verified. [1]

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected artifacts** | Braintree.Net, DependencyInjector.Core, SipNet, SipNet.OpenAI.Realtime |
| **Ecosystem** | nuget |
| **Malicious versions** | Braintree.Net@3.35.8, Braintree.Net@3.35.9, Braintree.Net@3.36.0, Braintree.Net@3.36.1, DependencyInjector.Core@1.0.0, DependencyInjector.Core@1.3.0, DependencyInjector.Core@1.4.0, DependencyInjector.Core@1.4.1, SipNet@12.8.4, SipNet@12.8.5, SipNet@12.8.6, SipNet@12.8.7; conditional transitive exposure: SipNet.OpenAI.Realtime@12.8.3 |
| **Disclosure** | 2026-07-09 |
| **Verified recovery direction** | replace Braintree.Net with official Braintree package; verify every companion dependency separately |

## Evidence Assessment

| Assessment | Claim | Evidence |
| --- | --- | --- |
| Confirmed | Listed package versions carried or transitively resolved malicious code. | Static package analysis and version comparison by the cited researchers. [1] |
| Confirmed | Trigger: .NET module initialization, production gateway configuration, and payment API calls. | Source-level or compiled-artifact analysis. [1] |
| Confirmed | intercepts PAN/CVV, steals Braintree merchant keys, and harvests environment, config, cloud, and container secrets. | Decompiled/static analysis and reported telemetry where available. [1] |
| Unclear | Number of affected organizations or successful thefts. | Neither source establishes a verified victim count. |

## Impact Determination

| Classification | Criteria | Required evidence | Action | Closure gate |
| --- | --- | --- | --- | --- |
| Exposure | Malicious selector in a lockfile, cache, or inventory | Preserve dependency graph and cache metadata | Isolate affected workload and determine whether trigger ran | Every matching host classified |
| Likely execution | Install/load logs or files align with the trigger | Process, file, CI, application, and egress timeline | Rebuild and rotate reachable secrets | Negative rescan and completed rotations |
| Confirmed compromise | IOC egress, payload hash, or theft/abuse evidence | Proxy/EDR evidence with UTC timestamps | Incident response and downstream abuse review | Abuse review, recovery monitoring, and evidence sign-off |

## Minimum Evidence To Collect

- **Dependency evidence:** preserve lockfiles, SBOMs, package-manager caches, and CI restore/install logs; they identify exact versions and resolve exposure classification.
- **Execution evidence:** collect EDR process/file events and application or assembly-load logs around dependency use; they determine whether .NET module initialization, production gateway configuration, and payment API calls occurred.
- **Network evidence:** retain DNS, proxy, firewall, and TLS metadata for api.348672-shakepay.com, 104.21.89.51, 172.67.188.32; a matching outbound event materially raises confidence.
- **Identity evidence:** export audit logs for identities holding payment card data, Braintree merchant credentials, connection strings, cloud credentials, and CI tokens; these decide credential rotation scope and whether downstream abuse occurred.

## Timeline

- **2026-07-09 (UTC; exact time varies by artifact):** malicious publication/discovery activity documented by the cited researchers. [1]
- **2026-07-09:** public technical reporting and defensive guidance published. [1]
- **Current registry removal status:** unknown after this source-only review; validate through metadata-only registry queries before publication.

## What Happened

The incident abused trusted package distribution or a deceptive package identity to deliver code that looked compatible with expected developer workflows. It then used .NET module initialization, production gateway configuration, and payment API calls to activate and intercepts PAN/CVV, steals Braintree merchant keys, and harvests environment, config, cloud, and container secrets. [1]

## Technical Analysis

### Initial Access
The affected artifacts were distributed through nuget package channels. This folder does not infer an actor identity beyond source-supported account or publishing-path facts. [1]

### Execution Trigger
.net module initialization, production gateway configuration, and payment api calls. [1]

### Payload Behavior
The observed payload intercepts PAN/CVV, steals Braintree merchant keys, and harvests environment, config, cloud, and container secrets. [1]

### Credential or Data Collection
The defensible exposure set is payment card data, Braintree merchant credentials, connection strings, cloud credentials, and CI tokens. Rotate only after preserving evidence and mapping which secrets were available to the affected process. [1]

### Defense Evasion
The source reporting describes deceptive naming, silent failure, obfuscation, or trigger placement intended to reduce discovery. Do not generalize beyond the specific files and selectors in this packet. [1]

### Exfiltration and Command and Control
Observed network selectors are api.348672-shakepay.com, 104.21.89.51, 172.67.188.32. Human-readable prose is defanged where shown; raw values remain in `iocs.json`. [1]

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
| Package versions | Braintree.Net@3.35.8, Braintree.Net@3.35.9, Braintree.Net@3.36.0, Braintree.Net@3.36.1, DependencyInjector.Core@1.0.0, DependencyInjector.Core@1.3.0, DependencyInjector.Core@1.4.0, DependencyInjector.Core@1.4.1, SipNet@12.8.4, SipNet@12.8.5, SipNet@12.8.6, SipNet@12.8.7; conditional transitive exposure: SipNet.OpenAI.Realtime@12.8.3 |
| Files | Braintree.dll, DependencyInjector.Core.dll |
| Domains (defanged) | api[.]348672-shakepay[.]com |
| IPs (defanged) | 104[.]21[.]89[.]51, 172[.]67[.]188[.]32 |
| SHA-256 | See source; no compact hash set included here |

## Detection and Hunting

Run [`scripts/hunt.py`](scripts/hunt.py) against exported lockfiles, SBOMs, restore/install logs, proxy/DNS logs, or file inventories. It answers whether exact package versions, file selectors, hashes, domains, or IPs are present. A match is a triage lead; package-only matches may be false positives from documentation or cleanly quarantined caches. Escalate by preserving the matching record and correlating it with process and identity audit logs.

## Downstream Abuse Audits

Review source-control, registry, cloud, payment, wallet, and CI identity logs only where the affected process could access those services. Search from the earliest package acquisition through credential rotation for new tokens, unusual sessions, publishing, transaction changes, secret reads, and deployment activity. The reason is specific: the payload targeted payment card data, Braintree merchant credentials, connection strings, cloud credentials, and CI tokens. [1]

## Remediation and Recovery Gates

1. Preserve lockfiles, caches, process/file telemetry, and egress evidence before cleanup.
2. Stop package execution and isolate hosts with runtime or egress evidence.
3. Remove the listed versions and invalidate internal caches.
4. Rotate payment card data, Braintree merchant credentials, connection strings, cloud credentials, and CI tokens from a clean host, prioritizing secrets present during execution.
5. Rebuild likely or confirmed hosts from verified images rather than trusting package removal alone.
6. Apply the recovery direction: replace Braintree.Net with official Braintree package; verify every companion dependency separately.
7. Audit downstream identity and transaction activity from first exposure through rotation.
8. Rescan lockfiles, caches, files, and egress exports with the tested hunter.
9. Close only after every exposed host is classified, required rotations and abuse reviews are complete, and post-recovery monitoring is clean.

## Open Questions

- How many organizations actually executed the malicious code?
- Is additional attacker infrastructure or campaign-linked packaging still active?
- What is the current registry availability/deprecation status of every listed version?

## Sources

1. https://socket.dev/blog/braintree-nuget-typosquat-skims-credit-cards — **Socket** — primary technical research supporting package, behavior, timeline, and IOC claims; it does not prove the number of affected organizations.
