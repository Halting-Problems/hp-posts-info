---
title: "Atomic Arch Hijacks Orphaned AUR Packages to Install Malicious npm Dependencies"
date: 2026-06-12
summary: "Attackers adopted orphaned AUR projects and changed PKGBUILDs to install malicious npm dependencies that execute a native Linux payload."
severity: critical
sourceCount: 3
tags: ["software-supply-chain", "developer-targeting"]
---

## Executive Summary

Attackers adopted orphaned AUR projects and changed PKGBUILDs to install malicious npm dependencies that execute a native Linux payload. [1]

Sonatype reports modified AUR PKGBUILDs invoking npm to install atomic-lockfile, with later js-digest and lockfile-js activity. Its update says early reporting may put affected AUR packages around 1,500, but the investigation and count remain fluid. The Arch Linux mailing-list thread and aur-malware-check repository provide ecosystem response and a static checking aid. [1]

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected Artifact** | atomic-lockfile, js-digest, lockfile-js |
| **Ecosystem** | aur, npm |
| **Malicious Versions** | Public source inventory is dynamic or exact versions were not reproduced here |
| **Exposure Window** | Ongoing as of 2026-06-12 |
| **Immediate Action** | Preserve evidence, isolate systems where execution occurred, and rotate exposed secrets from a clean host |

## Evidence Assessment

| Assessment | Claim | Evidence |
| --- | --- | --- |
| Confirmed by reporting | modified PKGBUILD installs an npm dependency; npm preinstall executes a bundled native Linux executable | Source 1 |
| Confirmed by reporting | modified AUR build instructions; npm preinstall execution; native Linux payload with eBPF/libbpf references | Source 1 |
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

- **2026-06-12 UTC:** Supplied research was published or updated; exact malicious publication times remain in the source's evolving inventory. [1]

## What Happened

Sonatype reports modified AUR PKGBUILDs invoking npm to install atomic-lockfile, with later js-digest and lockfile-js activity. Its update says early reporting may put affected AUR packages around 1,500, but the investigation and count remain fluid. The Arch Linux mailing-list thread and aur-malware-check repository provide ecosystem response and a static checking aid. [1]

## Technical Analysis

### Initial Access
Sonatype reports modified AUR PKGBUILDs invoking npm to install atomic-lockfile, with later js-digest and lockfile-js activity. Its update says early reporting may put affected AUR packages around 1,500, but the investigation and count remain fluid. The Arch Linux mailing-list thread and aur-malware-check repository provide ecosystem response and a static checking aid. [1]

### Execution Trigger
Modified pkgbuild installs an npm dependency; npm preinstall executes a bundled native linux executable. [1]

### Payload Behavior
Reported behaviors include modified AUR build instructions; npm preinstall execution; native Linux payload with eBPF/libbpf references. [1]

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

Run `scripts/hunt_atomic_arch_aur_compromise.py PATH`. It recursively scans exported text, JSON, CSV, lockfiles, and logs for the incident-specific selectors embedded in the script. A match is a triage lead, not proof. False positives include documentation or threat-intelligence records. Escalate matches by preserving the file and correlating timestamps with process/network telemetry.

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

1. https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency — **Source 1**
2. https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/ — **Source 2**
3. https://github.com/lenucksi/aur-malware-check — **Source 3**
