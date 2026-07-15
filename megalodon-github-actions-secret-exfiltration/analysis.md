---
title: "Megalodon GitHub Actions Secret Exfiltration Campaign"
date: 2026-05-24
severity: "critical"
tags:
  - supply-chain
  - github-actions
  - ci-cd
  - credential-theft
  - workflow-injection
summary: "Megalodon added malicious GitHub Actions workflows to thousands of public repositories to collect environment variables, cloud credentials, source-control secrets, and runner tokens."
sourceCount: 1
---

## Executive Summary
StepSecurity reported Megalodon as a mass GitHub Actions secret-exfiltration campaign affecting 5,561 public repositories, with SafeDep publishing a dataset of 5,718 malicious commits. The campaign inserted disguised workflow files into repositories so GitHub Actions would execute attacker-controlled secret collection logic [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories).

The payload collected environment variables, process environments, cloud credentials, SSH keys, Docker configuration, npm tokens, Kubernetes configs, Vault tokens, Terraform credentials, OIDC tokens, and source-code secrets before posting a compressed archive to `216[.]126[.]225[.]129:8443`. Use the workflow-history, runner-egress, and downstream identity audit recipes below to determine which repositories executed the payload and which credential classes were exposed [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories).

## Key Facts
**Threat Type**: malicious GitHub Actions workflow injection

**Ecosystem**: GitHub Actions

**Registry**: GitHub repositories

**Affected Packages**:
- not package-specific; repository workflow compromise

**Malicious Versions**:

**Known Good Versions**:

**Fixed Or Safe Versions**:

**Execution Trigger**: GitHub Actions workflow execution after malicious workflow file is committed

**Primary Impact**: mass CI/CD secret collection and exfiltration

**Campaign Context**: May 2026 CI/CD supply-chain wave focused on direct runner execution and credential theft.

**Confidence**: medium

**Canonical Source**: https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories

**Last Verified**: 2026-05-24

## Evidence Assessment
- **confirmed:** StepSecurity reports 5,561 affected repositories and 5,718 malicious commits in a SafeDep-published dataset [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories).
- **confirmed:** The campaign used malicious workflow files with names such as `SysDiag` and `Optimize-Build` to trigger GitHub Actions execution [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories).
- **confirmed:** The payload collected multiple classes of secrets and exfiltrated to `216[.]126[.]225[.]129:8443` [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories).
- **unclear:** The dataset was not independently fetched in this local pass, so per-repository remediation status remains a collection gap.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | Repository history contains the reported malicious workflow, commit hash, C2 endpoint, or payload content and the workflow executed. | Commit object, workflow file, Actions run metadata, runner logs, and network telemetry. | Remove the workflow, isolate affected runners, and rotate every credential class available to the run. | Malicious commits are reverted or removed, workflows are disabled, and downstream audits are clean. |
| Presumed exposed | A matching workflow exists and may have run with secrets, even if exfiltration telemetry is missing. | Workflow path, commit timestamp, runner assignment, permissions, and secret availability. | Rotate GitHub, cloud, package, container, SSH, Kubernetes, Vault, and Terraform credentials reachable from the job. | Credential owners confirm revocation of old material and no suspicious downstream writes are found. |
| Potentially exposed | Repository search finds suspicious workflow names, bot authors, archive creation, or the C2 IP but execution state is incomplete. | Code search hits, git log output, workflow run list, and runner telemetry availability. | Freeze suspicious workflow paths and collect missing run evidence before narrowing rotation. | Each hit is dispositioned as confirmed, presumed, or not exposed. |
| Not exposed | No matching workflow names, C2 endpoint, malicious hashes, or suspicious workflow additions exist in repository history. | Repository code search, git history search, and Actions run export. | Record the clean search and keep workflow ownership controls active. | Search artifacts are preserved with the date, repository list, and query terms. |
| Unknown | Repository history, Actions logs, or the public dataset comparison is unavailable. | Named evidence gaps and the repository population not yet searched. | Keep the repository in the investigation queue and apply conservative credential rotation for high-value projects. | Dataset comparison and workflow history are complete or the risk owner accepts the gap. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Repository search results for `.github/workflows/SysDiag.yml`, `.github/workflows/Optimize-Build.yml`, reported hashes, and `216[.]126[.]225[.]129`.
- Git commit metadata for any workflow additions and the author identity used.
- GitHub Actions run metadata for malicious or suspicious workflows.
- Runner process, archive creation, and egress telemetry.
- Inventory of secrets and OIDC permissions available to each matching workflow run.

## Timeline
- **2026-05-22** StepSecurity publishes Megalodon public analysis, citing 5,561 affected repositories and 5,718 malicious commits [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories).
- **2026-05-24** This local feed split creates a standalone Megalodon article instead of grouping it into a weekly roundup.

## What Happened
Megalodon did not need to compromise a package registry. It targeted repository automation directly by adding workflow files disguised as normal CI optimization or diagnostics. Once the workflow ran, the runner exposed a high-value environment: repository tokens, cloud credentials, deployment secrets, and process-level secrets.

StepSecurity's writeup emphasizes the directness of the attack. A workflow file committed to a repository can run trusted automation without any application-code dependency update, which makes repository history and workflow governance critical evidence sources [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories).

## Technical Analysis

### Initial Access
The public report focuses on malicious commits and affected repository count; it does not prove one universal initial access mechanism for every repository. Review commit authorship, branch protection, token scopes, and whether malicious workflow commits bypassed normal review.

### Package or Artifact Tampering
The artifact is the GitHub Actions workflow file itself, not a package release. Reported workflow names include `SysDiag` and `Optimize-Build`, which are plausible enough to blend into routine automation [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories). [1]

### Execution Trigger
Execution occurs when GitHub Actions runs the malicious workflow. Trigger conditions depend on the committed workflow, but the important defender point is that the malicious code executes inside the repository's trusted CI context.

### Payload Behavior
The payload collects environment variables, process environments, cloud credentials, SSH keys, Docker configuration, npm tokens, Kubernetes configs, Vault tokens, Terraform credentials, OIDC tokens, and source-code secrets. It then compresses and posts collected data to the C2 endpoint [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories). [1]

### Exfiltration / C2
The reported exfiltration endpoint is `216[.]126[.]225[.]129:8443/collect`. Any runner egress to that host and port should be treated as a high-confidence incident [StepSecurity](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories). [1]

### Propagation
Megalodon propagated operationally through many repository commits rather than through a self-replicating package payload. StepSecurity reports thousands of affected repositories and malicious commits, making source-control search and dataset comparison the primary scoping methods.

### Obfuscation or Evasion
The campaign used benign-looking workflow names and CI-maintenance framing. This is effective because many repositories accept workflow changes as routine build hygiene unless workflow file review is explicitly protected.

### Workflow Injection and Exfiltration Path
The following architectural flowchart details the Megalodon attack lifecycle, illustrating how a workflow injection event triggers automated secret harvesting inside the CI/CD runner and the subsequent egress path to the C2 server: [1]

```mermaid
graph TD
    classDef attacker fill:#f96,stroke:#333,stroke-width:2px;
    classDef github fill:#9cf,stroke:#333,stroke-width:2px;
    classDef runner fill:#fcf,stroke:#333,stroke-width:2px;
    classDef c2 fill:#ff9,stroke:#333,stroke-width:2px; [1]

    Attacker[1. Attacker]:::attacker
    GitRepo[2. Target GitHub Repo]:::github
    GHActions[3. GitHub Actions CI/CD Engine]:::github
    Runner[4. CI/CD Runner Environment]:::runner
    Exfil[5. Exfiltration C2 <br/> 216[.]126[.]225[.]129:8443]:::c2

    Attacker -- "Injects Malicious Commit <br/> (e.g. SysDiag / Optimize-Build)" --> GitRepo
    GitRepo -- "Triggers Workflow Event <br/> (e.g. pull_request_target / push)" --> GHActions
    GHActions -- "Spawns Runner with Secrets" --> Runner

    subgraph Runner Context
        Runner -- "1. Harvest Env Vars" --> Secrets[Credentials & Tokens]
        Runner -- "2. Harvest SSH Keys" --> SSH[~/.ssh/*]
        Runner -- "3. Harvest Cloud Keys" --> Cloud[AWS, Azure, GCP]
        Runner -- "4. Harvest API Keys" --> API[NPM, Terraform, Vault]
        Secrets & SSH & Cloud & API --> Archive[Compressed Secrets Archive]
    end

    Runner -- "Exfiltrates Archive (POST)" --> Exfil
```

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: GitHub Actions,GitHub repositories
  - **packages**:
  - **versions**: 5,718 malicious commits reported by StepSecurity/SafeDep
  - **repositories**: 5,561 public repositories reported by StepSecurity
  - **ci_cd_systems**: GitHub Actions
  - **container_images**:
  - **developer_tools**: GitHub Actions,repository workflow automation

**Credentials At Risk**:
- GitHub tokens
- GitHub Actions secrets
- OIDC tokens
- AWS credentials
- Azure credentials
- GCP credentials
- SSH private keys
- Docker registry credentials
- npm tokens
- Kubernetes configs
- Vault tokens
- Terraform credentials

**Not Currently Known To Affect**:
- Private repositories not represented in the public dataset, unless local audit finds matching commits or workflow files.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 1c9e803c80cc7fed000022d4c94f4b5bc2e90062
- 7f6120bb10c870b9fde146961a18e5bf0b3d4401
- acac5a9854650c4ae2883c4740bf87d34120c038

### Urls
- hxxps://216[.]126[.]225[.]129:8443/collect

### Ips
- 216[.]126[.]225[.]129


## Detection and Hunting

### Hunt Manifest: megalodon-github-actions-secret-exfiltration-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Megalodon GitHub Actions Secret Exfiltration Campaign?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-megalodon-github-actions-secret-exfiltration-scope"))

FILES = [".github/workflows/SysDiag.yml",".github/workflows/Optimize-Build.yml"]
URLS = ["https://216.126.225.129:8443/collect"]
IPS = ["216[.]126[.]225[.]129"]
HASHES = ["1c9e803c80cc7fed000022d4c94f4b5bc2e90062","7f6120bb10c870b9fde146961a18e5bf0b3d4401","acac5a9854650c4ae2883c4740bf87d34120c038"]
PROCESS_PATTERNS = ["workflow collects environment variables and credential files"]
NETWORK_PATTERNS = ["HTTPS POST to 216[.]126[.]225[.]129:8443/collect"]

# Collect unique indicators
indicators = set()
for group in [FILES, URLS, IPS, HASHES, PROCESS_PATTERNS, NETWORK_PATTERNS]:
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

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [StepSecurity: Megalodon: Mass GitHub Actions Secret Exfiltration Across 5,500+ Public Repositories](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories) - **Role:** PRIMARY_RESEARCH - **Impact:** Documents affected repository and commit counts, workflow names, payload collection scope, C2 IP, and hunting pivots.
