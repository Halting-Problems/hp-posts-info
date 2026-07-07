---
title: "PyPI spellcheckpy Typosquatting RAT Campaign"
date: 2026-01-23
severity: "critical"
tags:
  - pypi
  - typosquatting
  - rat
  - malware
summary: "Attackers published typosquatted versions of the popular pyspellchecker library to deliver a Remote Access Trojan (RAT) hidden inside compressed Basque dictionary files."
sourceCount: 4
---
## Executive Summary
In January 2026, security researchers at **Aikido Security** discovered an evasive software supply chain attack campaign on the Python Package Index (PyPI) [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). Threat actors published two typosquatted packages, **`spellcheckerpy`** and **`spellcheckpy`**, designed to impersonate the highly popular and widely utilized spelling correction library **`pyspellchecker`** [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

To bypass automated registry security sandboxes and static code analysis tools, the attackers hid a base64-encoded, zlib-compressed Python Remote Access Trojan (RAT) downloader inside a benign Basque language frequency dictionary resource file (`resources/eu.json.gz`) [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). In early iterations, the malware remained dormant to establish registry trust, but with the release of `spellcheckpy` version `1.2.0` on January 21, 2026, the threat actors enabled an import-time execution trigger inside the class constructor [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

Once executed, the downloader establishes persistence, bypasses SSL verification, and beacons every 5 seconds to a malicious command-and-control (C2) server hosted on known bulletproof C2 infrastructure [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat) [Halcyon](https://www.halcyon.ai). Use the package inventory, import-time execution, and downstream audit recipes below to determine whether the typosquats executed and which identities were reachable.

---

## Key Facts
**Threat Type**: typosquatting, malicious package, Remote Access Trojan (RAT), credential theft

**Ecosystem**: pypi

**Registry**: PyPI

**Affected Packages**:
- spellcheckerpy
- spellcheckpy

**Malicious Versions**:
- spellcheckerpy@*
- spellcheckpy@1.2.0

**Fixed Versions**:
- none

**Safe Versions**:
- none (use pyspellchecker)

**Exposure Window**: 2026-01-20 to 2026-01-22

**Execution Trigger**: Import-time execution (`WordFrequency.__init__`)

**Primary Impact**: Remote Access Trojan (RAT) execution, credential theft, remote system access, files harvesting

**Known Iocs**:
- updatenet[.]work
- 172.86.73[.]139
- https://updatenet[.]work/update1.php
- https://updatenet[.]work/settings/history.php
- dothebest[.]store
- FD429DEABE
- resources/eu.json.gz

**Confidence**: high

**Canonical Source**: hxxps://www[.]aikido[.]dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat

---

## Evidence Assessment
*   **confirmed:**
    *   The discovery of malicious `spellcheckpy` and `spellcheckerpy` packages on PyPI that typosquatted `pyspellchecker` [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
    *   The payload evasion method of embedding zlib-compressed, base64-encoded Python scripts under the `"spellchecker"` key inside Basque dictionary files (`resources/eu.json.gz`) [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
    *   The import-time trigger added to `spellcheckpy` version `1.2.0` on January 21, 2026, within the `WordFrequency.__init__` class constructor [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
    *   The active beaconing to C2 domain `updatenet[.]work` at IP `172.86.73[.]139` using HTTPS POST requests [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
    *   An identical campaign discovered in November 2025 by HelixGuard under the package name `spellcheckers` communicating with C2 domain `dothebest[.]store` [HelixGuard](https://helixguard.ai/blog/malicious-spellcheckers-2025-11-19/).
*   **likely:**
    *   Threat actors targeted software developers working with spelling or linguistic modules to steal operational credentials (such as AWS keys, GitHub tokens, database logins) or cryptocurrency keys [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat) [HelixGuard](https://helixguard.ai/blog/malicious-spellcheckers-2025-11-19/).
    *   The use of RouterHosting LLC (Cloudzy) as a bulletproof host chosen specifically for its low-verification signup policies and cryptocurrency payment options [Halcyon](https://www.halcyon.ai).
*   **unclear:**
    *   The exact geographic location or definitive group attribution of the threat actors, though the C2 infrastructure utilized is heavily correlated with Iranian and Russian threat actors [Halcyon](https://www.halcyon.ai).
    *   The complete list of downstream victims, other than the registry-tracked download counts indicating approximately 1,000 installations [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
*   **not_observed:**
    *   Any self-propagating worm capabilities; the malware relies purely on targeted installation via typosquatting [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
    *   Exploitation of software bugs or zero-day vulnerabilities; this attack is a social engineering-centric registry supply chain injection [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

---

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `spellcheckpy==1.2.0` or related typosquat package is present and Python import decompresses and launches the hidden RAT loader or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing Python import decompresses and launches the hidden RAT loader or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `spellcheckpy==1.2.0` or related typosquat package was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but Python install, import, or interpreter-startup execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for spellcheckpy==1.2.0, spellcheckerpy.
- Execution evidence for Python import decompresses and launches the hidden RAT loader.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2025-10-28T00:00:00Z** The malicious C2 domain `updatenet[.]work` is registered. Source: [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat)
- **2025-11-19T00:00:00Z** HelixGuard documents a functionally identical campaign involving the typosquatted package `spellcheckers` communicating with C2 domain `dothebest[.]store`. Source: [HelixGuard](https://helixguard.ai/blog/malicious-spellcheckers-2025-11-19/)
- **2026-01-20T00:00:00Z** Aikido Security's automated malware detection pipeline identifies initial dormant uploads of `spellcheckerpy` and `spellcheckpy` on PyPI. Source: [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat)
- **2026-01-21T00:00:00Z** The threat actor publishes version `1.2.0` of `spellcheckpy`, switching the malware from dormant to active by embedding an execution trigger in the class constructor. Source: [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat)
- **2026-01-22T00:00:00Z** The packages are reported to PyPI security and removed from the registry after reaching approximately 1,000 downloads. Source: [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat)
- **2026-01-23T00:00:00Z** Aikido Security publishes a detailed threat analysis detailing the RAT extraction and payload behavior. Source: [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat)

---

## What Happened
In late January 2026, security analysts at **Aikido Security** flagged suspicious activity involving spelling correction libraries on PyPI [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). A threat actor had uploaded two packages—`spellcheckerpy` and `spellcheckpy`—which typosquatted the popular and legitimate `pyspellchecker` library [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

To bypass standard registry scanning mechanisms that flag classic indicators like shell commands (`subprocess.run()`, `eval()`, `exec()`) in setup files, the attackers utilized a multi-stage, evasive deployment model [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). They first uploaded several "dormant" versions containing the obfuscated downloader code inside a Basque language frequency dictionary, but without active calls to execute it [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

On January 21, 2026, the attackers published version `1.2.0` of `spellcheckpy` [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). This version modified the initialization routine of the `WordFrequency` class to compile and execute the base64-decoded dictionary data upon import [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). Consequently, any developer importing the library unwittingly triggered the download and execution of a fully featured Remote Access Trojan (RAT) [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

The package was reported to PyPI administrators and removed on January 22, 2026, limiting the blast radius to roughly 1,000 installations [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). Subsequent research linked the campaign to a functionally identical incident documented by HelixGuard in November 2025 [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat) [HelixGuard](https://helixguard.ai/blog/malicious-spellcheckers-2025-11-19/).

---

## Technical Analysis

### Initial Access
The primary entry point is typosquatting [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). The attackers relied on developers typing the wrong library name (`spellcheckpy` or `spellcheckerpy` instead of `pyspellchecker`) during local installation or manually writing their dependency files [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

### Package or Artifact Manipulation
The packages were structured similarly to the legitimate `pyspellchecker` project, mimicking standard linguistic modules [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). However, the file `resources/eu.json.gz`, which is legitimately used to store compressed Basque language word frequencies, was weaponized [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). The attackers injected a key named `"spellchecker"` containing a base64-encoded, compressed Python payload representing the first-stage downloader [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

In early "dormant" releases, the loader file `utils.py` contained code to read the file but omitted execution routines, rendering it invisible to security monitors [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat): [1]

```python
def test_file(filepath: PathOrStr, encoding: str, index: str):
    # Reads compressed data but does not trigger execution

The following script or command is provided to check, audit, or remediate the system:

```

### Execution Trigger
The execution trigger was flipped in version `1.2.0` of `spellcheckpy` [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). The threat actor modified the constructor function `WordFrequency.__init__` [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). When a developer imports the module and instantiates the spelling checker, the system runs the constructor, which immediately compiles and executes the hidden script [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat):
```python
if eval(compile(base64.b64decode(test_file("eu", "utf-8", "spellchecker")).decode("utf-8"), ...)):
    exec(szCode)
```

### Payload Behavior
Once compiled and executed, the downloader performs the following sequences [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat):
1.  **SSL Disabling:** It disables local SSL verification using `ssl._create_unverified_context()` to ensure smooth connection routing [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
2.  **Beaconing Loop:** It establishes a persistent beaconing loop, executing an HTTPS POST request every 5 seconds to `https://updatenet[.]work/update1.php` [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
3.  **Telemetry Exfiltration:** The POST payload carries a unique victim machine identifier, system metrics, and a hardcoded Campaign ID (`FD429DEABE`) [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). [1]
4.  **Encrypted Command Execution:** The C2 server responds with encrypted commands, which the client decrypts using a 16-byte XOR key array (`03 06 02 01 06 00 04 07 00 01 09 06 08 01 02 05`) and a secondary XOR key (`0x7B`) [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). The RAT supports full remote shell access, command execution, local file harvesting, and targeted credential theft [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). [1]

### Exfiltration / C2
**Domains**:
- updatenet[.]work

**Ips**:
- 172.86.73[.]139

**Urls**:
- https://updatenet[.]work/update1.php
- https://updatenet[.]work/settings/history.php

**Protocols**:
- HTTPS

**Endpoints**:
- /update1.php
- /settings/history.php

**Confidence**: high

### Propagation
The malicious code does not contain lateral propagation or worm-like replication capabilities [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). It relies entirely on developers manually importing the typosquatted package or pulling it via misconfigured automated dependency requirements [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

### Obfuscation or Evasion
*   **Steganographic Data Blending:** Embedding base64-encoded, zlib-compressed payloads inside Basque frequency dictionary resource files which are structurally standard in spelling utilities [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
*   **Dormant Upload Staging:** Releasing multiple early versions of the package with the downloader code but no execution trigger, avoiding automated publish-time detection systems [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).
*   **Dynamic Code Compilation:** Avoiding obvious dynamic evaluation keywords like `exec()` or `eval()` directly in the primary package script and compiling strings dynamically inside standard class constructors (`WordFrequency.__init__`) [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat).

---

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: pypi
  - **packages**: spellcheckerpy,spellcheckpy
  - **versions**: spellcheckerpy (all versions),spellcheckpy (all versions, trigger active in 1.2.0)
  - **repositories**: 
  - **container_images**: 
  - **CI_CD_systems**: 
  - **developer_tools**: 
  - **environments**: developer workstations,CI runners,build pipelines,containers,production systems

**Credentials At Risk**:
- environment variables
- SSH keys
- cloud provider credentials
- database connection keys
- API tokens
- cryptocurrency wallet keys

**Not Currently Known To Affect**:
- legitimate pyspellchecker users
- systems where spellcheckerpy or spellcheckpy was installed but the SpellChecker or WordFrequency class was never instantiated or imported (for versions < 1.2.0)

---

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- www.aikido.dev
- update1.php
- history.php

### Urls
- hxxps://www[.]aikido[.]dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat
- hxxps://helixguard[.]ai/blog/malicious-spellcheckers-2025-11-19/
- hxxps://updatenet[.]work/update1[.]php
- hxxps://updatenet[.]work/settings/history[.]php


## Detection and Hunting

### Hunt Manifest: spellcheckpy-typosquatting-rat-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with PyPI spellcheckpy Typosquatting RAT Campaign?
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
OUT = Path(os.environ.get("OUT", "hp-spellcheckpy-typosquatting-rat-scope"))

DOMAINS = ["www.aikido.dev","helixguard.ai","updatenet.work","update1.php","history.php"]
URLS = ["https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat","https://helixguard.ai/blog/malicious-spellcheckers-2025-11-19/","https://updatenet.work/update1.php`","https://updatenet.work/settings/history.php`"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS, URLS]:
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
1. [Aikido Security](https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat). **Role:** PRIMARY_RESEARCH **Impact:** Detailed the discovery of the spellcheckpy typosquatting campaign, payload extraction, and import-time execution trigger in version 1.2.0.
2. [HelixGuard](https://helixguard.ai/blog/malicious-spellcheckers-2025-11-19/). **Role:** PRIMARY_RESEARCH **Impact:** Documented the November 2025 typosquatted campaign under the package name `spellcheckers` communicating with C2 domain `dothebest[.]store` using an identical codebase.
3. [Halcyon](https://www.halcyon.ai/blog/cloudzy-iranian-linked-c2p-infrastructure-ransomware). **Role:** ENRICHMENT_DATA **Impact:** Published the "Cloudzy with a Chance of Ransomware" investigation exposing RouterHosting LLC (Cloudzy) as an Iranian-linked C2P provider heavily utilized by APTs and ransomware groups.
4. [The Hacker News](https://thehackernews.com/2025/11/malicious-pypi-packages-spellcheckpy-typosquat.html). **Role:** SECONDARY_ANALYSIS **Impact:** Aggregated reporting of the typosquatted package takedown timeline on PyPI.
