---
title: "semantic-types PyPI Solana Keypair Monkey Patch"
date: 2025-01-26
severity: "high"
tags:
  - pypi
  - supply-chain
  - solana
  - cryptocurrency
  - monkey-patching
summary: "Socket reported that semantic-types became malicious at version 0.1.5 and 0.1.6, with five Solana-themed PyPI packages pulling it transitively. The payload monkey-patched solders[.]keypair[.]Keypair constructors, encrypted Solana private keys with an RSA-2048 public key, and exfiltrated ciphertext through Solana Devnet SPL memo transactions."
sourceCount: 1
---

## Executive Summary
Socket reported a PyPI campaign by the alias `cappership` in which `semantic-types` carried the malicious payload and five Solana-themed packages pulled it transitively: `solana-keypair`, `solana-publickey`, `solana-mev-agent-py`, `solana-trading-bot`, and `soltrade` [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].

The malicious `semantic-types` update landed at `0.1.5` on January 26, 2025; `0.1.6` repackaged the same payload on January 28, 2025 [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)]. The payload monkey-patched `solders.keypair.Keypair.from_seed`, `from_bytes`, and `from_base58_string`, encrypted captured private key bytes with a hardcoded RSA-2048 public key, and sent the ciphertext as an SPL memo transaction through Solana Devnet RPC at `api.devnet.solana.com` [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].

There is no conventional attacker C2 domain to block for the key theft path. The hard indicators are package names/versions, PyPI publisher metadata from the Socket report, the Solana Devnet RPC endpoint, the SPL Memo program ID, the actor public key `D782zqWjgSvy4hQoqzY1ySrGrotnXm1suJeXFur8sAko`, the RSA public-key fingerprint `5a4d8480c9d1e82ba102f200258882fb9e694e8fc0343b6982c5540beccdca62`, and code paths that generate Solana keypairs while the malicious package is present [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].

## Key Facts
**Event Type**: malicious PyPI package with transitive dependency delivery

**Ecosystem**: PyPI

**Publisher**:
  - **alias**: cappership
  - **email**: cappership@proton.me

**Malicious Payload Package**:
  - **name**: semantic-types
  - **malicious_versions**: 0.1.5,0.1.6

**Transitive Carrier Packages**:
- solana-keypair
- solana-publickey
- solana-mev-agent-py
- solana-trading-bot
- soltrade

**Execution Trigger**: Python import that registers monkey patches, followed by solders Keypair constructor use

**Patched Methods**:
- solders[.]keypair[.]Keypair.from_seed
- solders[.]keypair[.]Keypair.from_bytes
- solders[.]keypair[.]Keypair.from_base58_string

**Collection Window Utc**:
  - **start**: 2025-01-26T00:00:00Z
  - **end**: 2025-05-29T23:59:59Z

**Network Iocs**:
- api.devnet.solana[.]com

**Solana Iocs**:
  - **memo_program_id**: MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
  - **actor_public_key**: D782zqWjgSvy4hQoqzY1ySrGrotnXm1suJeXFur8sAko

**Crypto Iocs**:
  - **rsa_public_key_fingerprint_sha256**: 5a4d8480c9d1e82ba102f200258882fb9e694e8fc0343b6982c5540beccdca62

**Credentials At Risk**:
- Solana private keys created or imported through patched solders Keypair constructors

## Evidence Assessment
* **confirmed:** Socket identified `semantic-types` as the core malicious package and `solana-keypair`, `solana-publickey`, `solana-mev-agent-py`, `solana-trading-bot`, and `soltrade` as dependent carrier packages [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].
* **confirmed:** Socket states `semantic-types 0.1.5` introduced the malicious payload on January 26, 2025 and `0.1.6` repackaged it on January 28, 2025 [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].
* **confirmed:** Socket identified the monkey-patched methods `Keypair.from_seed`, `Keypair.from_bytes`, and `Keypair.from_base58_string`, the Solana Devnet RPC endpoint, the threat actor public key, the PyPI alias/email, and RSA public-key fingerprint [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].
* **unclear:** Public sources do not name victim wallets or prove which Devnet memo transactions correspond to real production keypairs.
* **not_observed:** No evidence indicates compromise of the legitimate `solders` package itself.

## Impact Determination
| Classification | Criteria | Evidence to collect | Handling decision |
| --- | --- | --- | --- |
| Confirmed compromise | A malicious package was installed and a patched `solders.keypair.Keypair` constructor generated or imported a real Solana keypair. | Installed package/version evidence, code path invoking `Keypair.from_seed`, `Keypair.from_bytes`, or `Keypair.from_base58_string`, Solana Devnet RPC `sendTransaction`, memo program use, actor public key `D782zqWjgSvy4hQoqzY1ySrGrotnXm1suJeXFur8sAko`. | Treat keypairs created or imported through the process as exposed; move funds and authority to keys generated in a clean environment. |
| Presumed exposed | `semantic-types==0.1.5` or `0.1.6`, or any carrier package, was installed in an environment that runs Solana key generation/import code, but runtime telemetry is missing. | `pip freeze`, lockfile, package cache, source grep for patched methods, notebook history, CI output. | Inventory all keypairs generated or imported by that environment after January 26, 2025 and replace them from clean tooling. |
| Potentially exposed | A carrier package appears in manifests or lockfiles, but installation or malicious dependency resolution is incomplete. | Dependency graph, package proxy records, lockfile history, virtualenv/container inventory. | Collect package-cache and environment evidence until the asset is classified. |
| Not exposed | No malicious package, carrier package, affected version, Solana keypair constructor, Devnet RPC, memo program, or actor key appears in source, environments, caches, or telemetry. | Negative repository search, package inventory, dependency lock, virtualenv/container search, and network telemetry search. | Keep negative evidence with the case record and close this event for the asset. |
| Unknown | Package inventory, dependency resolution history, endpoint data, source history, or Solana RPC telemetry is unavailable. | Named telemetry gap with system, owner, and retention status. | Keep Solana key material in scope until the missing evidence is recovered or key replacement is accepted as the closure path. |

### Minimum Evidence To Collect
**Package Evidence**:
- semantic-types==0.1.5
- semantic-types==0.1.6
- solana-keypair
- solana-publickey
- solana-mev-agent-py
- solana-trading-bot
- soltrade

**Code Evidence**:
- solders[.]keypair[.]Keypair.from_seed
- solders[.]keypair[.]Keypair.from_bytes
- solders[.]keypair[.]Keypair.from_base58_string

**Network Evidence**:
- api.devnet.solana[.]com
- sendTransaction
- MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
- D782zqWjgSvy4hQoqzY1ySrGrotnXm1suJeXFur8sAko

**Crypto Evidence**:
- 5a4d8480c9d1e82ba102f200258882fb9e694e8fc0343b6982c5540beccdca62

## Timeline
* **2024-12-22:** Socket reports benign `semantic-types 0.1.2` and `solana-trading-bot 0.1.0` were published [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].
* **2024-12-23:** Socket reports updates for `semantic-types 0.1.4`, `solana-trading-bot 0.1.1`, and `soltrade 0.1.1` with dependencies still benign [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].
* **2025-01-26:** Socket reports `semantic-types 0.1.5` introduced the malicious monkey-patching payload; `solana-mev-agent-py 0.1.0` and `solana-keypair 0.1.0` were also published [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].
* **2025-01-28:** Socket reports `semantic-types 0.1.6` repackaged the same malicious payload [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].
* **2025-02-04:** Socket reports `solana-keypair 0.2.1` and `solana-publickey 0.2.1` were released and imported `semantic-types` [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].
* **2025-05-29:** Socket published the public analysis with IOCs and the package cluster [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].

## What Happened
The actor used dependency relationships rather than a one-package-only lure. `semantic-types` contained the payload, while five Solana-themed packages depended on it and served as delivery paths [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].

Once imported, the payload modified methods on `solders.keypair.Keypair` at runtime. Calls to `from_seed`, `from_bytes`, and `from_base58_string` still returned a usable keypair, but the wrapper also sent key material to the attacker's collection path through a background thread [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].

The exfiltration path used normal Solana Devnet RPC. Captured private key bytes were encrypted with the actor's RSA public key, base64 encoded, embedded in an SPL Memo transaction, and broadcast to Devnet. The attacker could later read memo transactions associated with the actor public key and decrypt ciphertext offline [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].

## Technical Analysis
### Package Manipulation
**Payload Package**: semantic-types

**Malicious Versions**:
- 0.1.5
- 0.1.6

**Carrier Packages**:
- solana-keypair
- solana-publickey
- solana-mev-agent-py
- solana-trading-bot
- soltrade

**Dependency Trigger**: pip resolves semantic-types from carrier package dependencies

### Runtime Hook
The hook targets the `solders` keypair class object already used by Solana Python developers. Monkey patching means source code that imports `solders` can look normal while runtime method dispatch has changed inside the interpreter [[socket.dev](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys)].

### Exfiltration
**Transport**:
  - **protocol**: Solana JSON-RPC over HTTPS
  - **endpoint**: hxxps://api[.]devnet[.]solana[.]com
  - **rpc_method**: sendTransaction
  - **program**: SPL Memo
  - **memo_program_id**: MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
  - **actor_public_key**: D782zqWjgSvy4hQoqzY1ySrGrotnXm1suJeXFur8sAko

**Payload Encoding**:
  - **key_material**: 64-byte private key material from Keypair bytes
  - **encryption**: RSA-2048 public key
  - **encoding**: Base64 ciphertext in memo data [1]

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: PyPI
  - **packages**: semantic-types==0.1.5,semantic-types==0.1.6,solana-keypair,solana-publickey,solana-mev-agent-py,solana-trading-bot,soltrade
  - **environments**: developer virtualenvs,CI jobs,Jupyter notebooks,container images,Solana bots and trading tools
  - **secret_material**: Solana private keys generated by patched methods,Solana private keys imported through patched methods

**Not Currently Known To Affect**:
- the solders package itself
- Solana keypairs generated in clean environments without the malicious packages

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 5a4d8480c9d1e82ba102f200258882fb9e694e8fc0343b6982c5540beccdca62

### Domains
- api[.]devnet[.]solana[.]com

### Urls
- hxxps://api[.]devnet[.]solana[.]com


## Detection and Hunting

### Hunt Manifest: semantic-types-pypi-solana-monkey-patch-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with semantic-types PyPI Solana Keypair Monkey Patch?
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
OUT = Path(os.environ.get("OUT", "hp-semantic-types-pypi-solana-monkey-patch-scope"))
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "indicators.txt"

DOMAINS = ["api[.]devnet[.]solana[.]com","solders.keypair.Keypair"]
URLS = ["https://api.devnet.solana.com"]
HASHES = ["5a4d8480c9d1e82ba102f200258882fb9e694e8fc0343b6982c5540beccdca62"]

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
            print(f"[+] Querying pip index for {package}...")
            res = subprocess.run(["python3", "-m", "pip", "index", "versions", package], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"pypi-{safe_name}-versions.txt").write_text(res.stdout)
            subprocess.run(["python3", "-m", "pip", "download", "--no-deps", package, "-d", str(registry_dir)], capture_output=True)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [Socket: Monkey-Patched PyPI Packages Use Transitive Dependencies to Steal Solana Private Keys](https://socket.dev/blog/monkey-patched-pypi-packages-steal-solana-private-keys) - **Role:** PRIMARY_RESEARCH - **Impact:** Package cluster, malicious versions, payload behavior, patched methods, Solana Devnet exfiltration, actor key, RSA fingerprint, and PyPI publisher identity.
