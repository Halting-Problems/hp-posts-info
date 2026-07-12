---
title: "Operation Muck and Load Uses a Malicious Go Module and a 222-Repository GitHub Lure Network"
date: 2026-07-08
summary: "A deceptive Go module exposed a Windows malware-staging chain and a high-confidence GitHub lure network of 222 repositories across 190 accounts."
severity: high
sourceCount: 1
tags: ["software-supply-chain", "developer-targeting"]
---

## Executive Summary

A deceptive Go module exposed a Windows malware-staging chain and a high-confidence GitHub lure network of 222 repositories across 190 accounts. [1]

Socket reports that github[.]com/kaleidora/dnsub-scanning-tool impersonated a DNS/subdomain scanner and launched hidden PowerShell. Socket conservatively validated 222 repositories across 190 accounts by requiring both a linked email and a synthetic GitHub Actions commit-farming workflow. The source says the Go team blocked the module from the module proxy and explicitly calls Muck and Load a tracking label, not an attribution boundary. [1]

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected Artifact** | github.com/kaleidora/dnsub-scanning-tool |
| **Ecosystem** | go, github |
| **Malicious Versions** | Public source inventory is dynamic or exact versions were not reproduced here |
| **Exposure Window** | Ongoing as of 2026-07-08 |
| **Immediate Action** | Preserve evidence, isolate systems where execution occurred, and rotate exposed secrets from a clean host |

## Evidence Assessment

| Assessment | Claim | Evidence |
| --- | --- | --- |
| Confirmed by reporting | use of the deceptive Go module leads to hidden PowerShell execution on Windows | Source 1 |
| Confirmed by reporting | public dead-drop resolution; protected archive delivery; RAT and infostealer staging; synthetic GitHub Actions commit farming | Source 1 |
| Unclear | Complete victim count, exact exposure per organization, and exhaustive version list | Not established by the supplied sources |

## Impact Determination

| Exposure Classification | Criteria | Required Evidence | Required Action | Closure Gate |
| --- | --- | --- | --- | --- |
| Confirmed compromise | Payload execution or matching malicious artifact/process/network evidence | Host timeline, dependency metadata, process and network logs | Isolate, preserve, rebuild, rotate exposed credentials | Known-good rebuild plus negative hunts and downstream identity audit |
| Exposure only | Affected selector present but no execution evidence | Lockfile/repository history and installation logs | Quarantine artifact and investigate | Documented non-execution determination |

## Minimum Evidence To Collect

- **Dependency and repository records:** collect lockfiles, package caches, Git history, release metadata, and CI logs to establish whether an affected selector reached the environment.
- **Endpoint evidence:** collect process trees, shell history, EDR telemetry, persistence records, and network logs to distinguish dependency presence from payload execution.
- **Identity evidence:** collect repository, registry, cloud, and secret-access audit logs because developer execution can expose tokens available to the process.

## Timeline

- **2026-07-08 UTC:** Supplied research was published or updated; exact malicious publication times remain in the source's evolving inventory. [1]

## What Happened

Socket reports that github[.]com/kaleidora/dnsub-scanning-tool impersonated a DNS/subdomain scanner and launched hidden PowerShell. Socket conservatively validated 222 repositories across 190 accounts by requiring both a linked email and a synthetic GitHub Actions commit-farming workflow. The source says the Go team blocked the module from the module proxy and explicitly calls Muck and Load a tracking label, not an attribution boundary. [1]

## Technical Analysis

### Initial Access
Socket reports that github[.]com/kaleidora/dnsub-scanning-tool impersonated a DNS/subdomain scanner and launched hidden PowerShell. Socket conservatively validated 222 repositories across 190 accounts by requiring both a linked email and a synthetic GitHub Actions commit-farming workflow. The source says the Go team blocked the module from the module proxy and explicitly calls Muck and Load a tracking label, not an attribution boundary. [1]

### Execution Trigger
Use of the deceptive go module leads to hidden powershell execution on windows. [1]

### Payload Behavior
Reported behaviors include public dead-drop resolution; protected archive delivery; RAT and infostealer staging; synthetic GitHub Actions commit farming. [1]

### Credential or Data Collection
Treat credentials accessible to an executed developer process as potentially exposed. This is a response assumption, not proof that every listed credential was collected.

### Defense Evasion
The supplied reporting describes techniques intended to hide malicious changes or execution in trusted developer workflows. [1]

### Exfiltration and Command and Control
Use the machine-readable profile only for sourced infrastructure. Absence of an IOC here does not establish absence of network activity.

## Affected Assets and Blast Radius

Prioritize developer workstations, CI runners, repositories, package caches, and credentials present during execution. Presence alone is exposure; execution evidence raises the case to confirmed compromise.

## Indicators of Compromise

See `iocs.json`; prose intentionally avoids presenting source/advisory URLs as attacker IOCs.

## Detection and Hunting

Run `scripts/hunt_operation_muck_and_load_github_go.py PATH`. It recursively scans exported text, JSON, CSV, lockfiles, and logs for the incident-specific selectors embedded in the script. A match is a triage lead, not proof. False positives include documentation or threat-intelligence records. Escalate matches by preserving the file and correlating timestamps with process/network telemetry.

## Downstream Abuse Audits

If execution is confirmed, audit repository token use, package publication, CI workflow changes, cloud sessions, and newly created credentials from the first possible exposure time. Rotate secrets from a clean host.

## Remediation and Recovery Gates

1. Preserve dependency, repository, endpoint, and identity evidence before cleanup.
2. Stop package installation and isolate systems with execution evidence.
3. Revoke active sessions and rotate process-accessible credentials from a clean machine.
4. Remove malicious artifacts, inspect persistence, and rebuild confirmed-compromised systems.
5. Restore only verified releases and lockfiles; require review of developer-task configuration and repository history.
6. Audit downstream repository, registry, CI, and cloud activity.
7. Close only after negative hunts, verified rebuilds, completed credential decisions, and a documented UTC incident timeline.

## Open Questions

- Which exact versions and release timestamps intersect the organization's dependency history?
- Did the payload execute, and which credentials were present?
- Are additional artifacts still being added to the source's live inventory?

## Sources

1. https://socket.dev/blog/malicious-go-module-exposes-github-malware-lure-network — **Source 1**
