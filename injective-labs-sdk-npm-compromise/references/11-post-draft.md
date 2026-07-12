---
title: "Injective Labs SDK npm compromise steals wallet keys and mnemonics"
date: 2026-07-09
summary: "A compromised maintainer account pushed wallet-key exfiltration code through Injective’s trusted GitHub Actions publisher into 18 npm packages."
---

## Executive Summary

A compromised maintainer account pushed wallet-key exfiltration code through Injective’s trusted GitHub Actions publisher into 18 npm packages. The cited researchers identify the execution trigger as runtime calls to PrivateKey.fromMnemonic() or PrivateKey.fromHex() and the observed behavior as: base64-encodes wallet recovery material and sends it in X-Request-Id on a disguised gRPC-Web POST. [1] [2]

Responders should treat a matching malicious version as exposure and seek execution or egress evidence before asserting data theft. Secrets at risk include Injective wallet private keys, mnemonic phrases, and funds controlled by those keys. No public victim count is treated as verified. [1] [2]

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected artifacts** | @injectivelabs/sdk-ts, @injectivelabs/utils, @injectivelabs/networks, @injectivelabs/ts-types, @injectivelabs/exceptions, @injectivelabs/wallet-base, @injectivelabs/wallet-core, @injectivelabs/wallet-cosmos, @injectivelabs/wallet-private-key, @injectivelabs/wallet-evm, @injectivelabs/wallet-trezor, @injectivelabs/wallet-cosmostation, @injectivelabs/wallet-ledger, @injectivelabs/wallet-wallet-connect, @injectivelabs/wallet-magic, @injectivelabs/wallet-strategy, @injectivelabs/wallet-turnkey, @injectivelabs/wallet-cosmos-strategy |
| **Ecosystem** | npm |
| **Malicious versions** | @injectivelabs/sdk-ts@1.20.21, @injectivelabs/utils@1.20.21, @injectivelabs/networks@1.20.21, @injectivelabs/ts-types@1.20.21, @injectivelabs/exceptions@1.20.21, @injectivelabs/wallet-base@1.20.21, @injectivelabs/wallet-core@1.20.21, @injectivelabs/wallet-cosmos@1.20.21, @injectivelabs/wallet-private-key@1.20.21, @injectivelabs/wallet-evm@1.20.21, @injectivelabs/wallet-trezor@1.20.21, @injectivelabs/wallet-cosmostation@1.20.21, @injectivelabs/wallet-ledger@1.20.21, @injectivelabs/wallet-wallet-connect@1.20.21, @injectivelabs/wallet-magic@1.20.21, @injectivelabs/wallet-strategy@1.20.21, @injectivelabs/wallet-turnkey@1.20.21, @injectivelabs/wallet-cosmos-strategy@1.20.21 |
| **Disclosure** | 2026-07-09 |
| **Verified recovery direction** | all affected packages@1.20.23 |

## Evidence Assessment

| Assessment | Claim | Evidence |
| --- | --- | --- |
| Confirmed | Listed package versions carried or transitively resolved malicious code. | Static package analysis and version comparison by the cited researchers. [1] [2] |
| Confirmed | Trigger: runtime calls to PrivateKey.fromMnemonic() or PrivateKey.fromHex(). | Source-level or compiled-artifact analysis. [1] [2] |
| Confirmed | base64-encodes wallet recovery material and sends it in X-Request-Id on a disguised gRPC-Web POST. | Decompiled/static analysis and reported telemetry where available. [1] [2] |
| Unclear | Number of affected organizations or successful thefts. | Neither source establishes a verified victim count. |

## Impact Determination

| Classification | Criteria | Required evidence | Action | Closure gate |
| --- | --- | --- | --- | --- |
| Exposure | Malicious selector in a lockfile, cache, or inventory | Preserve dependency graph and cache metadata | Isolate affected workload and determine whether trigger ran | Every matching host classified |
| Likely execution | Install/load logs or files align with the trigger | Process, file, CI, application, and egress timeline | Rebuild and rotate reachable secrets | Negative rescan and completed rotations |
| Confirmed compromise | IOC egress, payload hash, or theft/abuse evidence | Proxy/EDR evidence with UTC timestamps | Incident response and downstream abuse review | Abuse review, recovery monitoring, and evidence sign-off |

## Minimum Evidence To Collect

- **Dependency evidence:** preserve lockfiles, SBOMs, package-manager caches, and CI restore/install logs; they identify exact versions and resolve exposure classification.
- **Execution evidence:** collect EDR process/file events and application or assembly-load logs around dependency use; they determine whether runtime calls to PrivateKey.fromMnemonic() or PrivateKey.fromHex() occurred.
- **Network evidence:** retain DNS, proxy, firewall, and TLS metadata for testnet.archival.chain.grpc-web.injective.network; a matching outbound event materially raises confidence.
- **Identity evidence:** export audit logs for identities holding Injective wallet private keys, mnemonic phrases, and funds controlled by those keys; these decide credential rotation scope and whether downstream abuse occurred.

## Timeline

- **2026-07-09 (UTC; exact time varies by artifact):** malicious publication/discovery activity documented by the cited researchers. [1] [2]
- **2026-07-09:** public technical reporting and defensive guidance published. [1] [2]
- **Current registry removal status:** unknown after this source-only review; validate through metadata-only registry queries before publication.

## What Happened

The incident abused trusted package distribution or a deceptive package identity to deliver code that looked compatible with expected developer workflows. It then used runtime calls to PrivateKey.fromMnemonic() or PrivateKey.fromHex() to activate and base64-encodes wallet recovery material and sends it in X-Request-Id on a disguised gRPC-Web POST. [1] [2]

## Technical Analysis

### Initial Access
The affected artifacts were distributed through npm package channels. This folder does not infer an actor identity beyond source-supported account or publishing-path facts. [1] [2]

### Execution Trigger
Runtime calls to privatekey.frommnemonic() or privatekey.fromhex(). [1] [2]

### Payload Behavior
The observed payload base64-encodes wallet recovery material and sends it in X-Request-Id on a disguised gRPC-Web POST. [1] [2]

### Credential or Data Collection
The defensible exposure set is Injective wallet private keys, mnemonic phrases, and funds controlled by those keys. Rotate only after preserving evidence and mapping which secrets were available to the affected process. [1] [2]

### Defense Evasion
The source reporting describes deceptive naming, silent failure, obfuscation, or trigger placement intended to reduce discovery. Do not generalize beyond the specific files and selectors in this packet. [1] [2]

### Exfiltration and Command and Control
Observed network selectors are testnet.archival.chain.grpc-web.injective.network. Human-readable prose is defanged where shown; raw values remain in `iocs.json`. [1] [2]

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
| Package versions | @injectivelabs/sdk-ts@1.20.21, @injectivelabs/utils@1.20.21, @injectivelabs/networks@1.20.21, @injectivelabs/ts-types@1.20.21, @injectivelabs/exceptions@1.20.21, @injectivelabs/wallet-base@1.20.21, @injectivelabs/wallet-core@1.20.21, @injectivelabs/wallet-cosmos@1.20.21, @injectivelabs/wallet-private-key@1.20.21, @injectivelabs/wallet-evm@1.20.21, @injectivelabs/wallet-trezor@1.20.21, @injectivelabs/wallet-cosmostation@1.20.21, @injectivelabs/wallet-ledger@1.20.21, @injectivelabs/wallet-wallet-connect@1.20.21, @injectivelabs/wallet-magic@1.20.21, @injectivelabs/wallet-strategy@1.20.21, @injectivelabs/wallet-turnkey@1.20.21, @injectivelabs/wallet-cosmos-strategy@1.20.21 |
| Files | src/utils/key-derivation-telemetry.ts, dist/esm/accounts-jQ1GSgaW.js, dist/cjs/accounts-Cy0p4lLW.cjs |
| Domains (defanged) | testnet[.]archival[.]chain[.]grpc-web[.]injective[.]network |
| IPs (defanged) | None published |
| SHA-256 | 103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0, 9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9 |

## Detection and Hunting

Run [`scripts/hunt.py`](scripts/hunt.py) against exported lockfiles, SBOMs, restore/install logs, proxy/DNS logs, or file inventories. It answers whether exact package versions, file selectors, hashes, domains, or IPs are present. A match is a triage lead; package-only matches may be false positives from documentation or cleanly quarantined caches. Escalate by preserving the matching record and correlating it with process and identity audit logs.

## Downstream Abuse Audits

Review source-control, registry, cloud, payment, wallet, and CI identity logs only where the affected process could access those services. Search from the earliest package acquisition through credential rotation for new tokens, unusual sessions, publishing, transaction changes, secret reads, and deployment activity. The reason is specific: the payload targeted Injective wallet private keys, mnemonic phrases, and funds controlled by those keys. [1] [2]

## Remediation and Closure

1. Preserve lockfiles, caches, process/file telemetry, and egress evidence before cleanup.
2. Stop package execution and isolate hosts with runtime or egress evidence.
3. Remove the listed versions and invalidate internal caches.
4. Rotate Injective wallet private keys, mnemonic phrases, and funds controlled by those keys from a clean host, prioritizing secrets present during execution.
5. Rebuild likely or confirmed hosts from verified images rather than trusting package removal alone.
6. Apply the recovery direction: all affected packages@1.20.23.
7. Audit downstream identity and transaction activity from first exposure through rotation.
8. Rescan lockfiles, caches, files, and egress exports with the tested hunter.
9. Close only after every exposed host is classified, required rotations and abuse reviews are complete, and post-recovery monitoring is clean.

## Open Questions

- How many organizations actually executed the malicious code?
- Is additional attacker infrastructure or campaign-linked packaging still active?
- What is the current registry availability/deprecation status of every listed version?

## Sources

1. **Socket**: https://socket.dev/blog/compromised-injective-sdk-npm-package — primary technical research supporting package, behavior, timeline, and IOC claims; it does not prove the number of affected organizations.
2. **StepSecurity**: https://www.stepsecurity.io/blog/injective-npm-supply-chain-attack-18-packages-backdoored-to-steal-crypto-wallet-keys — primary technical research supporting package, behavior, timeline, and IOC claims; it does not prove the number of affected organizations.
