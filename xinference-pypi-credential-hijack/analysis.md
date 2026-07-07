---
title: "Xinference PyPI 2.6.x Import-Time Credential Exfiltration"
date: 2026-04-22
severity: "critical"
tags:
  - pypi
  - supply-chain
  - xinference
  - ai-ml
  - credential-theft
summary: "JFrog reported that the legitimate PyPI package xinference shipped malicious versions 2.6.0, 2.6.1, and 2.6.2 with import-time code in xinference/__init__.py. The payload collected host and secret material into love[.]tar[.]gz and posted it to whereisitat[.]lucyatemysuperbox[.]space with header X-QT-SR: 14."
sourceCount: 2
---

## Executive Summary
JFrog reported a PyPI supply-chain compromise of the legitimate `xinference` package affecting versions `2.6.0`, `2.6.1`, and `2.6.2`. The malicious code lived in `xinference/__init__.py`, so exposure requires installation plus Python import, CLI startup, service startup, or another path that loads the package [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].

The decoded payload created a temporary directory, ran a second-stage collector, captured output to a temporary file named `f`, compressed it into `love.tar.gz`, and uploaded it to `https://whereisitat.lucyatemysuperbox.space/` using `curl --data-binary` and header `X-QT-SR: 14` [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)]. JFrog lists the package file hash, stage hashes, archive name, actor marker string, affected versions, and Xray ID `XRAY-96896` [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].

Current PyPI release history shows `2.5.0` before `2.7.0`; the malicious `2.6.x` releases are no longer in the visible history. Use version selectors and package-cache evidence as the primary exposure proof, then use C2/domain/header/hash selectors to separate confirmed execution from presumed exposure [[pypi.org](https://pypi.org/project/xinference/#history)].

## Key Facts
**Event Type**: legitimate PyPI package compromise

**Ecosystem**: PyPI

**Package**:
  - **name**: xinference
  - **malicious_versions**: 2.6.0,2.6.1,2.6.2
  - **visible_current_pypi_gap**: 2.5.0 to 2.7.0

**Collection Window Utc**:
  - **start**: 2026-04-22T00:00:00Z
  - **end**: 2026-04-23T23:59:59Z

**Execution Trigger**: Python import or service/CLI path loading xinference/__init__.py

**Malicious File**:
  - **path**: xinference/__init__.py
  - **sha256**: e1e007ce4eab7774785617179d1c01a9381ae83abfd431aae8dba6f82d3ac127

**Decoded Stage Hashes Sha256**:
  - **stage_1**: 077d49fa708f498969d7cdffe701eb64675baaa4968ded9bd97a4936dd56c21c
  - **stage_2**: fe17e2ea4012d07d90ecb7793c1b0593a6138d25a9393192263e751660ec3cd0

**Network Iocs**:
- whereisitat[.]lucyatemysuperbox[.]space
- hxxps://whereisitat[.]lucyatemysuperbox[.]space/

**Protocol Artifacts**:
- curl --data-binary
- X-QT-SR: 14

**File Artifacts**:
- love[.]tar[.]gz
- f

**Strings**:
- # hacked by teampcp

**Credentials At Risk**:
- environment variables
- SSH keys
- cloud credentials
- Kubernetes tokens and configs
- Docker registry credentials
- PyPI/npm/Cargo publishing tokens
- .env secrets
- TLS private keys and certificates
- database credentials
- wallet keys and seed material

## Evidence Assessment
* **confirmed:** JFrog identified `xinference` versions `2.6.0`, `2.6.1`, and `2.6.2` as compromised and lists Xray ID `XRAY-96896` [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].
* **confirmed:** JFrog identified `xinference/__init__.py` as the malicious file, SHA-256 `e1e007ce4eab7774785617179d1c01a9381ae83abfd431aae8dba6f82d3ac127`, and decoded stage SHA-256 values `077d49fa708f498969d7cdffe701eb64675baaa4968ded9bd97a4936dd56c21c` and `fe17e2ea4012d07d90ecb7793c1b0593a6138d25a9393192263e751660ec3cd0` [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].
* **confirmed:** JFrog observed exfiltration to `https://whereisitat.lucyatemysuperbox.space/`, archive name `love.tar.gz`, and HTTP header `X-QT-SR: 14` [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].
* **unclear:** Public evidence does not prove the exact PyPI publish credential theft path. JFrog describes a likely path based on prior campaign patterns, but the specific initial access vector remains unconfirmed [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].
* **not_observed:** JFrog states the payload does not include persistence, a reverse shell, destructive wiping, ransomware, or privilege escalation [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].

## Impact Determination
| Classification | Criteria | Evidence to collect | Handling decision |
| --- | --- | --- | --- |
| Confirmed compromise | `xinference==2.6.0`, `xinference==2.6.1`, or `xinference==2.6.2` was installed and import/runtime/C2 evidence exists. | Installed package metadata, lockfile, package cache, Python import traces, `xinference/__init__.py` hash, `love.tar.gz`, C2 DNS/HTTP, `X-QT-SR: 14`, `# hacked by teampcp`. | Preserve the host/container/runner evidence, isolate the asset, revoke credentials reachable from the Python process, and run the downstream audits below. |
| Presumed exposed | An affected version was installed in a host, image, notebook, virtualenv, or CI job, but import/network telemetry is missing. | `pip freeze`, `requirements*.txt`, `poetry.lock`, `uv.lock`, image layer output, CI install output, package cache. | Treat secret material readable by that environment as exposed unless import non-execution can be proven. |
| Potentially exposed | `xinference` was unpinned or upgraded during the April 22-23 collection window, but resolved version evidence is incomplete. | Dependency manifests, package proxy records, CI output, image build history, notebook environment exports. | Collect resolver/cache evidence before reducing scope. |
| Not exposed | Evidence shows no malicious `2.6.x` version in source, lockfiles, package caches, images, hosts, or runtime telemetry. | Negative dependency inventory, virtualenv/container search, package cache query, and network selector search. | Keep negative evidence with the case record and close this event for that asset. |
| Unknown | Required package inventory, CI output, endpoint telemetry, image inventory, or network telemetry is unavailable. | Named telemetry gap with system, owner, and retention status. | Keep high-value AI/ML, GPU, CI, and cloud-adjacent assets in scope until evidence is recovered or risk is explicitly accepted. |

### Minimum Evidence To Collect
**Package Evidence**:
- xinference==2.6.0
- xinference==2.6.1
- xinference==2.6.2
- xinference/__init__.py SHA-256 e1e007ce4eab7774785617179d1c01a9381ae83abfd431aae8dba6f82d3ac127

**Runtime Evidence**:
- Python import of xinference
- subprocess.Popen child Python execution
- curl --data-binary

**Network Evidence**:
- whereisitat[.]lucyatemysuperbox[.]space
- hxxps://whereisitat[.]lucyatemysuperbox[.]space/
- X-QT-SR: 14

**File Evidence**:
- love[.]tar[.]gz
- temporary collector output file named f

**String Evidence**:
- # hacked by teampcp

## Timeline
* **2026-04-22:** JFrog published research identifying `xinference` versions `2.6.0`, `2.6.1`, and `2.6.2` as compromised and yanked [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].
* **2026-04-22:** JFrog described the malicious payload in `xinference/__init__.py`, including import-time execution and staged collection/exfiltration [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].
* **2026-04-22:** JFrog listed the IOCs: affected package versions, C2 domain/URL, header `X-QT-SR: 14`, SHA-256 hashes, archive `love.tar.gz`, and marker `# hacked by teampcp` [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].
* **2026-04-25:** PyPI visible release history resumed at `2.7.0` after `2.5.0`, leaving the compromised `2.6.x` releases absent from the current visible release list [[pypi.org](https://pypi.org/project/xinference/#history)].

## What Happened
Attackers published malicious `xinference` versions directly to PyPI under the legitimate package name. JFrog reports that this was not a lookalike package; the affected identity was the real `xinference` package [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].

The malicious code was placed in `xinference/__init__.py`, making import and service startup the relevant execution boundary. The first stage decoded a second-stage collector, ran it in a child Python interpreter, wrote collected output to a temporary file named `f`, compressed that file into `love.tar.gz`, and uploaded the archive with `curl` to the C2 URL [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].

JFrog's decoded collector logic targeted host inventory and secret locations. The article specifically calls out SSH material, cloud credentials, Kubernetes service account tokens/configs, Docker registry credentials, package publishing tokens, `.env` secrets, TLS material, database passwords, and wallet key material as credential classes requiring downstream scoping [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].

## Technical Analysis
### Package Manipulation
**Package Identity**:
  - **registry**: PyPI
  - **package**: xinference
  - **malicious_versions**: 2.6.0,2.6.1,2.6.2

**Malicious File**:
  - **path**: xinference/__init__.py
  - **sha256**: e1e007ce4eab7774785617179d1c01a9381ae83abfd431aae8dba6f82d3ac127

**Execution Trigger**: module import or startup path that imports xinference

### Payload Behavior
The stage-one payload created temporary working storage, decoded and piped a second-stage collector into a child Python interpreter, captured stdout into `f`, compressed the output into `love.tar.gz`, and sent the archive using `curl --data-binary` [[research.jfrog.com](https://research.jfrog.com/post/xinference-compromise/)].

### Exfiltration
**Exfiltration**:
  - **domain**: whereisitat[.]lucyatemysuperbox[.]space
  - **url**: hxxps://whereisitat[.]lucyatemysuperbox[.]space/
  - **method**: HTTP POST
  - **tool**: curl
  - **body_mode**: --data-binary
  - **custom_header**: X-QT-SR: 14
  - **archive**: love[.]tar[.]gz

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: PyPI
  - **packages**: xinference==2.6.0,xinference==2.6.1,xinference==2.6.2
  - **environments**: developer virtualenvs,Jupyter notebook kernels,GPU inference servers,CI runners,container images built from affected requirements,Kubernetes pods importing xinference
  - **downstream_systems**: AWS,GCP,Azure,Kubernetes,Docker registries,PyPI/npm/Cargo registries,Git hosting

**Not Currently Known To Affect**:
- visible PyPI releases 2.5.0 and 2.7.0 when installed from official current metadata

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- e1e007ce4eab7774785617179d1c01a9381ae83abfd431aae8dba6f82d3ac127
- 077d49fa708f498969d7cdffe701eb64675baaa4968ded9bd97a4936dd56c21c
- fe17e2ea4012d07d90ecb7793c1b0593a6138d25a9393192263e751660ec3cd0

### Domains
- whereisitat.lucyatemysuperbox.space

### Urls
- hxxps://whereisitat[.]lucyatemysuperbox[.]space/


## Detection and Hunting

### Hunt Manifest: xinference-pypi-credential-hijack-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Xinference PyPI 2.6.x Import-Time Credential Exfiltration?
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
OUT = Path(os.environ.get("OUT", "hp-xinference-pypi-credential-hijack-scope"))

VERSIONS = ["xinference==2.6.0","xinference==2.6.1","xinference==2.6.2"]
FILES = ["xinference/__init__.py","love.tar.gz","f"]
DOMAINS = ["whereisitat.lucyatemysuperbox.space","subprocess.Popen"]
URLS = ["https://whereisitat.lucyatemysuperbox.space/"]
HASHES = ["e1e007ce4eab7774785617179d1c01a9381ae83abfd431aae8dba6f82d3ac127","077d49fa708f498969d7cdffe701eb64675baaa4968ded9bd97a4936dd56c21c","fe17e2ea4012d07d90ecb7793c1b0593a6138d25a9393192263e751660ec3cd0"]

# Collect unique indicators
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "ioc-indicators.txt"
indicators = set()
for group in [VERSIONS, FILES, DOMAINS, URLS, HASHES]:
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

    if "PACKAGES" in globals() and PACKAGES:
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
1. [JFrog Security Research: TeamPCP strikes again: Xinference PyPI package compromised](https://research.jfrog.com/post/xinference-compromise/) - **Role:** PRIMARY_RESEARCH - **Impact:** Affected versions, malicious file, payload behavior, IOCs, hashes, C2, header, archive name, and non-persistence notes.
2. [PyPI: xinference release history](https://pypi.org/project/xinference/#history) - **Role:** REGISTRY_METADATA - **Impact:** Current visible project metadata and release-history gap around `2.6.x`.
