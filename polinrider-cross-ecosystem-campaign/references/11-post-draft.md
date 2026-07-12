---
title: "PolinRider Expands Across npm, Packagist, Go Modules, and Chrome Extensions"
date: 2026-07-01
summary: "Socket reports 162 malicious release artifacts across 108 packages and extensions, with hidden JavaScript loaders targeting developer environments across four ecosystems."
---

## Executive Summary

Socket reports 162 malicious release artifacts across 108 packages and extensions, with hidden JavaScript loaders targeting developer environments across four ecosystems. [1]

This is a campaign-level source-of-truth post, not one post per package. Socket links the activity to the broader North Korean Contagious Interview / Famous Chollima cluster; Halting Problems preserves that source wording and does not independently strengthen attribution. Socket reports traces in 80 Go modules, 10 Packagist packages, one Chrome extension, and additional npm artifacts, with 162 malicious releases across 108 packages/extensions. [1]

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected Artifact** | Campaign inventory maintained by Socket live tracking |
| **Ecosystem** | npm, packagist, go, chrome-extension |
| **Malicious Versions** | Public source inventory is dynamic or exact versions were not reproduced here |
| **Exposure Window** | Ongoing as of 2026-07-01 |
| **Immediate Action** | Preserve evidence, isolate systems where execution occurred, and rotate exposed secrets from a clean host |

## Evidence Assessment

| Assessment | Claim | Evidence |
| --- | --- | --- |
| Confirmed by reporting | obfuscated JavaScript loaders hidden in repositories or fake font files execute through developer tooling such as VS Code tasks | Source 1 |
| Confirmed by reporting | whitespace-padded JavaScript loaders; fake .woff2 payload hiding; VS Code task execution; force-pushed or anti-dated commits; blockchain/public RPC retrieval and XOR decryption | Source 1 |
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

- **2026-07-01 UTC:** Supplied research was published or updated; exact malicious publication times remain in the source's evolving inventory. [1]

## What Happened

This is a campaign-level source-of-truth post, not one post per package. Socket links the activity to the broader North Korean Contagious Interview / Famous Chollima cluster; Halting Problems preserves that source wording and does not independently strengthen attribution. Socket reports traces in 80 Go modules, 10 Packagist packages, one Chrome extension, and additional npm artifacts, with 162 malicious releases across 108 packages/extensions. [1]

## Technical Analysis

### Initial Access
This is a campaign-level source-of-truth post, not one post per package. Socket links the activity to the broader North Korean Contagious Interview / Famous Chollima cluster; Halting Problems preserves that source wording and does not independently strengthen attribution. Socket reports traces in 80 Go modules, 10 Packagist packages, one Chrome extension, and additional npm artifacts, with 162 malicious releases across 108 packages/extensions. [1]

### Execution Trigger
Obfuscated javascript loaders hidden in repositories or fake font files execute through developer tooling such as vs code tasks. [1]

### Payload Behavior
Reported behaviors include whitespace-padded JavaScript loaders; fake .woff2 payload hiding; VS Code task execution; force-pushed or anti-dated commits; blockchain/public RPC retrieval and XOR decryption. [1]

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

Run `scripts/hunt_polinrider_cross_ecosystem_campaign.py PATH`. It recursively scans exported text, JSON, CSV, lockfiles, and logs for the incident-specific selectors embedded in the script. A match is a triage lead, not proof. False positives include documentation or threat-intelligence records. Escalate matches by preserving the file and correlating timestamps with process/network telemetry.

## Downstream Abuse Audits

If execution is confirmed, audit repository token use, package publication, CI workflow changes, cloud sessions, and newly created credentials from the first possible exposure time. Rotate secrets from a clean host.

## Remediation and Closure

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

1. **Source 1**: https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
