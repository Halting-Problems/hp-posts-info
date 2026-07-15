---
title: "Cavern Manticore abuse of SysAid software deployment"
date: 2026-07-06
summary: "Defender-focused assessment of SysAid software update deployment feature."
severity: high
sourceCount: 1
tags: ["rmm-abuse", "software-deployment-abuse", "post-exploitation"]
---

## Executive Summary

Check Point Research explicitly states that SysAid was not compromised and no SysAid vulnerability was involved. After gaining access to victim environments, Cavern Manticore abused the legitimate SysAid software-update feature to deploy a WinDirStat DLL-sideloading package. WinDirStat.exe loaded a trojanized uxtheme.dll Cavern Agent, which loaded n-HTCommp.dll for command and control and operator-selected modules. CPR also observed initial footholds through existing RMM software in multiple intrusions. [1]

The public evidence supports a **high-confidence incident**, but does not support filling every missing artifact, actor, victim, or infrastructure field. Unknown values below remain explicit. [1]

## Key Facts

| Fact | Value |
| --- | --- |
| Affected artifact | SysAid software update deployment feature |
| Ecosystem | enterprise-rmm |
| Malicious versions/reference | SysAid deployment feature version unknown |
| Disclosure | 2026-07-06 |
| Immediate action | Preserve evidence, disable the affected path, revoke exposed identities, and audit downstream use |

## Evidence Assessment

| Assessment | Claim |
| --- | --- |
| Confirmed | Check Point Research explicitly states that SysAid was not compromised and no SysAid vulnerability was involved. After gaining access to victim environments, Cavern Manticore abused the legitimate SysAid software-update feature to deploy a WinDirStat DLL-sideloading package. WinDirStat.exe loaded a trojanized uxtheme.dll Cavern Agent, which loaded n-HTCommp.dll for command and control and operator-selected modules. CPR also observed initial footholds through existing RMM software in multiple intrusions. [1] |
| Unclear | Exact full victim scope, complete exposure window, and any indicators not listed in `iocs.json`. |
| Not observed | No additional attacker infrastructure is asserted beyond the source-backed values. |

## Impact Determination

| Classification | Criteria | Required action | Closure gate |
| --- | --- | --- | --- |
| Confirmed compromise | Matching deployment/artifact plus unauthorized downstream activity | Isolate, preserve, revoke, investigate | No persistence or unauthorized follow-on activity; affected identities rotated |
| Exposed | Matching vendor/update/browser path without confirmed execution | Collect deployment and access history | Complete inventory and negative evidence review |
| Not observed | Verified clean deployment outside the evidenced window/path | Document evidence | Independent validation recorded |

## Minimum Evidence To Collect

- Collect deployment/update and administrative audit logs from the affected control plane; they establish who changed or delivered the artifact.
- Collect endpoint, application, proxy, and identity-provider telemetry from affected systems; they resolve execution and downstream access.
- Preserve suspect files, bundles, caches, and configuration with hashes and UTC timestamps before remediation.
- Record credential and session revocation evidence because exposed tokens or user signing context may remain useful after containment.

## Timeline

- **2026-07-06**: Public source disclosure or reporting. [1]
- Other exact timestamps not stated in the supplied sources remain unknown; incident teams should build a UTC timeline from their own logs.

## What Happened

Check Point Research explicitly states that SysAid was not compromised and no SysAid vulnerability was involved. After gaining access to victim environments, Cavern Manticore abused the legitimate SysAid software-update feature to deploy a WinDirStat DLL-sideloading package. WinDirStat.exe loaded a trojanized uxtheme.dll Cavern Agent, which loaded n-HTCommp.dll for command and control and operator-selected modules. CPR also observed initial footholds through existing RMM software in multiple intrusions. [1]

## Technical Analysis

### Initial Access and Execution Trigger

Treat the vendor, deployment, update, or RMM control plane as an exposure boundary. Collect administrative audit logs, credential/token use, package or deployment history, target host inventories, and downstream access records; distinguish legitimate tool use from unauthorized deployment. [1]

### Payload Behavior, Credentials, and Data

The source-backed impact is limited to the facts stated above. The machine-readable profile does not add unsupported malware infrastructure or hashes. [1]

### Defense Evasion, Exfiltration, and Command and Control

Use only the source-backed selectors in `iocs.json`. Where those arrays are empty, hunt from deployment, identity, browser, and host telemetry instead of treating vendor or reporting domains as attacker infrastructure.

## Affected Assets and Blast Radius

Prioritize systems that consumed **SysAid software update deployment feature**, their administrative identities, and connected downstream data or funds. Scope should be evidence-driven rather than assuming every customer was compromised.

## Indicators of Compromise

See `iocs.json`. Confirmed selectors include: SysAid, Cavern Manticore, C:\ProgramData\WinDir\WinDirStat.exe, uxtheme.dll, n-HTCommp.dll, MYMUTEX123HELLP02, MYMUTEX123HELLP04. Empty IOC categories are intentionally omitted from this prose.

## Detection and Hunting

Run [`scripts/hunt_cavern-manticore-sysaid-supply-chain.py`](scripts/hunt_cavern-manticore-sysaid-supply-chain.py) against exported CSV, JSON, JSONL, text, log, YAML, XML, JavaScript, or HAR evidence. It answers whether source-backed incident selectors occur in the collected scope. A match is a triage lead, not proof by itself; expected false positives include documentation and legitimate product references. Escalate by preserving the matched evidence, correlating deployment and identity timestamps, and reviewing downstream activity.

## Downstream Abuse Audits

Review the identities at risk—SysAid/RMM administrative identities and victim-host credentials—for access after the earliest suspected exposure. Revoke active sessions/tokens first when continued misuse is plausible, then compare administrative, application, and transaction records to an approved baseline.

## Remediation and Recovery Gates

1. Preserve suspect artifacts, deployment metadata, logs, and UTC timestamps.
2. Stop the affected integration, update, RMM, or browser delivery path.
3. Isolate confirmed systems and disable compromised administrative identities.
4. Revoke and rotate SysAid/RMM administrative identities and victim-host credentials.
5. Remove malicious artifacts and persistence identified by evidence.
6. Rebuild from independently verified artifacts when execution occurred.
7. Audit downstream access and transactions for the full evidence-backed window.
8. Restore only after clean deployment and cache/update validation.
9. Close only when inventory is complete, tokens/sessions are invalidated, no persistence remains, and monitoring shows no follow-on activity.

## Open Questions

- What exact deployment, build, package, or vendor identity was altered?
- What are the first and last confirmed exposure timestamps?
- Which customers or systems have positive execution or downstream-abuse evidence?

## Sources

1. https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/ — **Source** — supports the incident facts cited above; limitations are noted where technical detail is absent.
