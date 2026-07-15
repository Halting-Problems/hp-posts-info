---
title: "Polymarket frontend vendor compromise and malicious browser code"
date: 2026-06-25
summary: "Defender-focused assessment of Polymarket website frontend supplied through a third-party vendor."
severity: high
sourceCount: 3
tags: ["browser-supply-chain", "third-party-vendor-compromise", "cryptocurrency-theft"]
---

## Executive Summary

Polymarket said a compromise at a third-party vendor allowed malicious code to be injected into its website for some users, that it contained the incident, and that it was contacting and fully refunding affected users. TechCrunch independently obtained confirmation from a Polymarket spokesperson that user funds were stolen. PeckShield reported a related phishing campaign and approximately $3 million in losses; the exact technical injection path, vendor, code artifact, exposure window, and victim count remained publicly unclear. [1] [2] [3]

The public evidence supports a **high-confidence incident**, but does not support filling every missing artifact, actor, victim, or infrastructure field. Unknown values below remain explicit. [1] [2] [3]

## Key Facts

| Fact | Value |
| --- | --- |
| Affected artifact | Polymarket website frontend supplied through a third-party vendor |
| Ecosystem | browser-frontend |
| Malicious versions/reference | Polymarket frontend deployment version unknown |
| Disclosure | 2026-06-25 |
| Immediate action | Preserve evidence, disable the affected path, revoke exposed identities, and audit downstream use |

## Evidence Assessment

| Assessment | Claim |
| --- | --- |
| Confirmed | Polymarket said a compromise at a third-party vendor allowed malicious code to be injected into its website for some users, that it contained the incident, and that it was contacting and fully refunding affected users. TechCrunch independently obtained confirmation from a Polymarket spokesperson that user funds were stolen. PeckShield reported a related phishing campaign and approximately $3 million in losses; the exact technical injection path, vendor, code artifact, exposure window, and victim count remained publicly unclear. [1] [2] [3] |
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

- **2026-06-25**: Public source disclosure or reporting. [1] [2] [3]
- Other exact timestamps not stated in the supplied sources remain unknown; incident teams should build a UTC timeline from their own logs.

## What Happened

Polymarket said a compromise at a third-party vendor allowed malicious code to be injected into its website for some users, that it contained the incident, and that it was contacting and fully refunding affected users. TechCrunch independently obtained confirmation from a Polymarket spokesperson that user funds were stolen. PeckShield reported a related phishing campaign and approximately $3 million in losses; the exact technical injection path, vendor, code artifact, exposure window, and victim count remained publicly unclear. [1] [2] [3]

## Technical Analysis

### Initial Access and Execution Trigger

Because this was browser-delivered code, responders must map deployment IDs to built bundles, source maps, CDN objects, proxy/WAF logs, CSP reports, cache invalidation records, and wallet/session telemetry. Public reporting confirms serving to some users but does not identify the malicious bundle, dependency, vendor, or cache lifetime. [1] [2] [3]

### Payload Behavior, Credentials, and Data

The source-backed impact is limited to the facts stated above. The machine-readable profile does not add unsupported malware infrastructure or hashes. [1] [2] [3]

### Defense Evasion, Exfiltration, and Command and Control

Use only the source-backed selectors in `iocs.json`. Where those arrays are empty, hunt from deployment, identity, browser, and host telemetry instead of treating vendor or reporting domains as attacker infrastructure.

## Affected Assets and Blast Radius

Prioritize systems that consumed **Polymarket website frontend supplied through a third-party vendor**, their administrative identities, and connected downstream data or funds. Scope should be evidence-driven rather than assuming every customer was compromised.

## Indicators of Compromise

See `iocs.json`. Confirmed selectors include: Polymarket, third-party vendor, malicious code, frontend deployment, CSP report, CDN cache. Empty IOC categories are intentionally omitted from this prose.

## Detection and Hunting

Run [`scripts/hunt_polymarket-frontend-vendor-compromise.py`](scripts/hunt_polymarket-frontend-vendor-compromise.py) against exported CSV, JSON, JSONL, text, log, YAML, XML, JavaScript, or HAR evidence. It answers whether source-backed incident selectors occur in the collected scope. A match is a triage lead, not proof by itself; expected false positives include documentation and legitimate product references. Escalate by preserving the matched evidence, correlating deployment and identity timestamps, and reviewing downstream activity.

## Downstream Abuse Audits

Review the identities at risk—browser wallet approvals, sessions, and transaction-signing context—for access after the earliest suspected exposure. Revoke active sessions/tokens first when continued misuse is plausible, then compare administrative, application, and transaction records to an approved baseline.

## Remediation and Recovery Gates

1. Preserve suspect artifacts, deployment metadata, logs, and UTC timestamps.
2. Stop the affected integration, update, RMM, or browser delivery path.
3. Isolate confirmed systems and disable compromised administrative identities.
4. Revoke and rotate browser wallet approvals, sessions, and transaction-signing context.
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

1. https://x.com/polymarkettrade/status/2070155882906730671 — **Source** — supports the incident facts cited above; limitations are noted where technical detail is absent.
2. https://x.com/PeckShieldAlert/status/2070157742514618443 — **Source** — supports the incident facts cited above; limitations are noted where technical detail is absent.
3. https://techcrunch.com/2026/06/25/polymarket-says-hackers-stole-users-funds/ — **Source** — supports the incident facts cited above; limitations are noted where technical detail is absent.
