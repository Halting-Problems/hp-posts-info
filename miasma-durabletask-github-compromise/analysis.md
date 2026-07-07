---
title: "Miasma DurableTask GitHub Repository Compromise"
date: 2026-06-05
severity: "critical"
tags:
  - github
  - repository-compromise
  - supply-chain
  - credential-theft
  - microsoft
  - azure
  - miasma
  - hades
  - teampcp
summary: "On June 5, 2026, the official Azure/durabletask GitHub repository was compromised. Threat actors pushed a backdated commit ('Switched DataConverter to OrchestrationContext [skip ci]') that added a malicious tasks.json and configuration files targeting AI coding tools to execute credential-stealing payloads. Later follow-up reporting showed the broader Miasma/Hades campaign continued spreading across npm and PyPI through open-time and import-time triggers."
sourceCount: 5
---

## Executive Summary

On **2026-06-05**, security researchers disclosed a highly sophisticated supply chain compromise targeting the official Microsoft/Azure repository **`Azure/durabletask`** [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]. A compromised contributor account was used to push a backdated commit titled `"Switched DataConverter to OrchestrationContext [skip ci]"` [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]. The commit introduced zero functional changes to the codebase but added `.vscode/tasks.json` with `"runOn": "folderOpen"` to execute `.github/setup.js` automatically when the folder is opened in Visual Studio Code [[threatlocker.com](https://www.threatlocker.com/blog/the-spreading-blight-miasma-supply-chain-campaign)] [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)]. 

Furthermore, the commit planted configuration files targeting AI coding assistants (Claude Code, Cursor, Gemini CLI) to execute credential-stealing payloads [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)] [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)]. Microsoft and GitHub security teams responded within minutes, disabling 73 repositories across 4 organizations (Azure, Azure-Samples, Microsoft, MicrosoftDocs) to contain the spread [[threatlocker.com](https://www.threatlocker.com/blog/the-spreading-blight-miasma-supply-chain-campaign)] [[phoenix.security](https://phoenix.security/blog/hades-wave-supply-chain-ai-coding-assistants)]. The compromised account was linked to prior activity on PyPI where it published malicious versions of the `durabletask` package (1.4.1, 1.4.2, 1.4.3) [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)].

A June 18 StepSecurity follow-up showed the broader Miasma/Hades family was still actively spreading across npm and PyPI, with open-time and import-time triggers replacing the older install-time assumptions many scanners rely on. That follow-up attributes the npm branch to a 157-byte `binding.gyp` "Phantom Gyp" trigger, the repository branch to IDE/AI-assistant auto-run files, and the PyPI branch to an obfuscated `__init__.py` import hook that downloads Bun and launches the JavaScript payload [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-and-hades-are-spreading-now-detect-them-on-developer-machines-with-suspicious-files)].

## Key Facts

**Threat Type**: Repository Compromise, AI Coding Assistant Abuse & Credential Theft

**Ecosystem**: github, git, vscode, claude, cursor, gemini

**Registry**: GitHub

**Affected Repositories**:
- Azure/durabletask

**Compromised Files**:
- .vscode/tasks.json
- .claude/settings.json
- .gemini/settings.json
- .cursor/rules/setup.mdc
- .github/setup.js

**Reported Publish Date**: 2026-06-05

**Execution Trigger**: Opening the repository in VS Code or using AI coding assistants (Claude Code, Cursor, Gemini CLI) in the workspace

**Publish Path**: Compromised contributor credentials (PAT)

**Credential Risk**:
- AWS credentials
- Azure service principal tokens
- Google Cloud tokens
- Kubernetes config files
- GitHub personal access tokens
- Developer workstation environments

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| The Azure/durabletask repository was compromised on June 5, 2026. | confirmed | ThreatLocker and StepSecurity report that a compromised contributor account pushed the malicious commit [[threatlocker.com](https://www.threatlocker.com/blog/the-spreading-blight-miasma-supply-chain-campaign)] [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]. |
| The commit added tasks.json running a payload on folder open in VS Code. | confirmed | StepSecurity and Zscaler detail the `.vscode/tasks.json` configuration utilizing `"runOn": "folderOpen"` to invoke `.github/setup.js` [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)] [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)]. |
| The commit targeted AI coding tools (Claude Code, Cursor, Gemini CLI). | confirmed | Phoenix Security and Zscaler document the inclusion of `.cursor/rules/setup.mdc`, `.claude/settings.json`, and `.gemini/settings.json` [[phoenix.security](https://phoenix.security/blog/hades-wave-supply-chain-ai-coding-assistants)] [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)]. |
| GitHub disabled 73 repositories across Azure and Microsoft organizations to contain the spread. | confirmed | ThreatLocker and Phoenix Security report that GitHub swept and disabled 73 repositories across 4 organizations (Azure, Azure-Samples, Microsoft, MicrosoftDocs) [[threatlocker.com](https://www.threatlocker.com/blog/the-spreading-blight-miasma-supply-chain-campaign)] [[phoenix.security](https://phoenix.security/blog/hades-wave-supply-chain-ai-coding-assistants)]. |
| The compromise is linked to prior durabletask PyPI malicious packages. | confirmed | StepSecurity confirmed the same contributor account was responsible for publishing malicious `durabletask` versions 1.4.1, 1.4.2, and 1.4.3 on PyPI [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]. |
| Follow-up reporting shows the broader Miasma/Hades campaign is still propagating through open-time and import-time triggers beyond the original DurableTask repository event. | confirmed | StepSecurity's June 18 follow-up describes the npm branch's `binding.gyp` "Phantom Gyp" trigger, the repository branch's IDE/AI-tool auto-run files, and the PyPI branch's `__init__.py` import hook that downloads Bun and executes the JavaScript payload [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-and-hades-are-spreading-now-detect-them-on-developer-machines-with-suspicious-files)]. |

## Impact Determination

| Classification | Criteria | Required evidence | Handling decision | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | An affected repository was cloned, and opened in VS Code (with auto-run tasks enabled) or accessed via Cursor, Claude Code, or Gemini CLI, and telemetry shows outbound requests to C2 domains or executions of `.github/setup.js`. | Terminal command history, VS Code task logs, process execution telemetry (e.g. node.js running setup.js), network logs showing connections to getsessions.org or masscan.cloud. | Isolate the developer workstation, revoke and rotate all credentials stored on the workstation (AWS, Azure, GCP, GitHub), and check for lateral movement. | Workstation is re-imaged, all credentials are confirmed rotated, and network/EDR monitoring shows no further C2 beaconing. |
| Presumed exposed | An affected repository was cloned and opened in a workspace with active AI coding assistants or VS Code, but endpoint/network logs are incomplete. | Git clone history, workspace file paths, or developer shell history containing references to the compromised durabletask repository branches. | Revoke and rotate all developer and cloud tokens accessible from the workstation. | Rebuild clean environments and confirm revocation of all potentially exposed API keys. |
| Potentially exposed | The repository was cloned, but it was never opened in VS Code or accessed via targeted AI tools. | Git clone records, workspace directory inventory, and shell logs. | Audit the local workspace directory to confirm the absence of execution triggers, or delete the cloned repository safely. | Clean deletion of the workspace folders. |
| Not exposed | The repository was not cloned, or local Git repositories do not contain the compromised commit or branch. | Negative search results in developer environment inventories and codebase scanning. | Maintain standard prevention controls (disable task auto-run in VS Code). | Search evidence covers all active developer endpoints. |
| Unknown | Inventory, shell history, or network/EDR logs are missing. | A gap statement naming unavailable systems or logs. | Treat the system as potentially exposed and conduct a targeted audit. | Gaps are resolved or risk accepted. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Developer workspace inventory checking for the existence of .github/setup.js or tasks.json with runOn folderOpen
- EDR process execution logs for node.js executing setup.js
- Network/DNS resolution logs for getsession[.]org, masscan.cloud, or git-tanstack[.]com
- Git logs or checkout histories for durabletask repository showing commit Switched DataConverter to OrchestrationContext

## Timeline

- **2026-06-05T08:00:00Z:** The attacker utilizes compromised contributor PAT credentials to push a backdated commit ("Switched DataConverter to OrchestrationContext [skip ci]") to the official `Azure/durabletask` repository. The commit is backdated to March 9, 2020. Source: [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]
- **2026-06-05T08:15:00Z:** StepSecurity and ThreatLocker automated monitoring systems flag an anomalous change in repository config files targeting IDE and AI agent settings. Source: [[threatlocker.com](https://www.threatlocker.com/blog/the-spreading-blight-miasma-supply-chain-campaign)] [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]
- **2026-06-05T08:20:00Z:** GitHub security systems perform an automated sweep and disable 73 repositories across Azure, Azure-Samples, Microsoft, and MicrosoftDocs organizations to prevent local auto-run spread. Source: [[threatlocker.com](https://www.threatlocker.com/blog/the-spreading-blight-miasma-supply-chain-campaign)] [[phoenix.security](https://phoenix.security/blog/hades-wave-supply-chain-ai-coding-assistants)]
- **2026-06-05T10:30:00Z:** Security researchers publish analysis linking the compromise to the broader Miasma/Hades campaign run by TeamPCP. Source: [[phoenix.security](https://phoenix.security/blog/hades-wave-supply-chain-ai-coding-assistants)] [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)]
- **2026-06-18T00:00:00Z:** StepSecurity publishes a campaign-wide follow-up stating that Miasma and Hades are still spreading across npm and PyPI through `binding.gyp` build triggers, IDE/AI-tool auto-run files, and `__init__.py` import hooks, with hundreds of malicious artifacts and more than 113 affected repositories observed across the broader campaign [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-and-hades-are-spreading-now-detect-them-on-developer-machines-with-suspicious-files)].

## What Happened

On June 5, 2026, threat actors targeted the developer ecosystem by exploiting developer configurations instead of standard runtime dependencies [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)] [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)]. Utilizing compromised Personal Access Tokens (PATs) belonging to an Azure project contributor, the attackers pushed a backdated commit to the `Azure/durabletask` repository [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]. The commit message "Switched DataConverter to OrchestrationContext [skip ci]" was selected to bypass automated CI/CD builds [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]. It did not modify any source code files but added five files designed to trigger a large, obfuscated JavaScript payload (`.github/setup.js`) when opened in VS Code or various AI-assisted coding tools [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)].

Recognizing the threat, GitHub took immediate automated action, disabling 73 repositories across multiple Microsoft organizations to isolate the backdoor [[threatlocker.com](https://www.threatlocker.com/blog/the-spreading-blight-miasma-supply-chain-campaign)]. This threat is tracked as a child event of the Miasma worm (Hades variant) operated by TeamPCP, who had previously hijacked PyPI credentials to publish backdoored `durabletask` packages [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)] [[phoenix.security](https://phoenix.security/blog/hades-wave-supply-chain-ai-coding-assistants)].

## Technical Analysis

### Initial Access
The attacker gained write access to the `Azure/durabletask` repository by using a compromised contributor's Personal Access Token (PAT), bypassing standard OIDC/trusted commit validation gates [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)].

### Package or Artifact Manipulation
The commit backdated the author/committer timestamps to March 9, 2020, to make the changes appear historical and evade Git history checks [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)]. Rather than modifying actual logic, it introduced:
- `.github/setup.js` (4.6 MB obfuscated JavaScript file)
- `.vscode/tasks.json`
- `.claude/settings.json`
- `.gemini/settings.json`
- `.cursor/rules/setup.mdc`

### Execution Trigger
The attack leveraged the automatic execution features of modern IDEs and AI coding tools [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)]:
- **VS Code:** The `"runOn": "folderOpen"` option in `.vscode/tasks.json` automatically runs the configured task (executing `node .github/setup.js`) as soon as the workspace folder is opened by a user.
- **Claude Code & Gemini CLI:** The `SessionStart` hook in `.claude/settings.json` and `.gemini/settings.json` executes the script when the AI session begins.
- **Cursor:** The `.cursor/rules/setup.mdc` file uses prompt injection to instruct the Cursor AI agent to execute `.github/setup.js` under the guise of setting up the workspace.

### Payload Behavior
Once triggered, `.github/setup.js` scans the local developer workstation or runner. It targets active environment variables, credentials, configuration profiles, and files containing secret keys for AWS, Azure, Google Cloud, Kubernetes (kubeconfig), and GitHub.

### Exfiltration / C2
Collected credentials are sent to TeamPCP-controlled C2 servers [[zscaler.com](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)]:
- `api.masscan.cloud`
- `filev2.getsession.org`
- `seed1.getsession.org`
- `seed2.getsession.org`
- `seed3.getsession.org`
- `git-tanstack.com`

### Propagation
The malware does not feature direct replication code inside `durabletask`, but stolen tokens are routinely recycled by TeamPCP's centralized infrastructure to automate compromises of other packages downstream [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)].

### Obfuscation or Evasion
The `setup.js` file is heavily obfuscated with nested eval structures and anti-analysis checks, and the `[skip ci]` flag in the commit prevented CI/CD pipelines from running tests that might have triggered detections.

## Affected Assets and Blast Radius

**Affected Assets**:
  - **ecosystems**: github,vscode
  - **packages**: 
  - **repositories**: Azure/durabletask
  - **container_images**: 
  - **CI_CD_systems**: GitHub Actions
  - **developer_tools**: Visual Studio Code,Claude Code,Cursor IDE,Gemini CLI

**Credentials At Risk**:
- AWS access keys
- Azure service principal tokens
- Google Cloud credentials
- GitHub personal access tokens
- Kubernetes configuration files (kubeconfig)

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- setup.mdc
- api.masscan.cloud
- filev2[.]getsession[.]org
- seed1[.]getsession[.]org
- seed2[.]getsession[.]org
- seed3[.]getsession[.]org
- git-tanstack[.]com

### Urls
- hxxps://api[.]masscan[.]cloud
- hxxps://filev2[.]getsession[.]org
- hxxps://seed1[.]getsession[.]org
- hxxps://seed2[.]getsession[.]org
- hxxps://seed3[.]getsession[.]org
- hxxps://git-tanstack[.]com


## Detection and Hunting

### Hunt Manifest: miasma-durabletask-github-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Miasma DurableTask GitHub Repository Compromise?
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
OUT = Path(os.environ.get("OUT", "hp-miasma-durabletask-github-compromise-scope"))

FILES = [".vscode/tasks.json",".claude/settings.json",".gemini/settings.json",".cursor/rules/setup.mdc",".github/setup.js"]
DOMAINS = ["setup.mdc","api.masscan.cloud","filev2[.]getsession[.]org","seed1[.]getsession[.]org","seed2[.]getsession[.]org","seed3[.]getsession[.]org","git-tanstack[.]com"]
URLS = ["https://api.masscan.cloud","https://filev2.getsession.org","https://seed1.getsession.org","https://seed2.getsession.org","https://seed3.getsession.org","https://git-tanstack.com"]

# Collect unique indicators
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "ioc-indicators.txt"
indicators = set()
for group in [FILES, DOMAINS, URLS]:
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

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Remediation and Closure

### Containment
1. **Isolate Affected Workstations:** Immediately disconnect developer machines from local networks and the internet if a compromised repository was opened with auto-run enabled.
2. **Disable Auto-Run in VS Code:** Set `"git.autoRepositoryTrust": false` and `"task.allowAutomaticTasks": "off"` in global user settings.
3. **Hunt for campaign trigger files beyond this repository:** Search local workspaces and package caches for `binding.gyp` trigger files, suspicious `__init__.py` one-liners, and auto-run files like `.vscode/tasks.json`, `.claude/settings.json`, `.gemini/settings.json`, `.cursor/rules/setup.mdc`, and `.github/setup.js` because the same campaign has since been observed spreading through all three trigger classes [[stepsecurity.io](https://www.stepsecurity.io/blog/miasma-and-hades-are-spreading-now-detect-them-on-developer-machines-with-suspicious-files)].
4. **Remove files:** Delete the cloned repository folder from local disks.

### Eradication
1. **Rotate Credentials:** Revoke and rotate all secrets on the affected machine, including:
   - AWS Access Key IDs and Secret Access Keys.
   - Azure Service Principal client secrets.
   - GCP service account keys.
   - GitHub Personal Access Tokens (PATs) and SSH keys.
   - Kubernetes `kubeconfig` client certificates.
2. **Clean Python Caches:** Check for any rogue `.pth` files in Python site-packages directories (e.g. `*-setup.pth`).

### Recovery
1. **Deploy Clean Repositories:** Re-clone repositories after verifying they have been restored by administrators.
2. **Implement MFA & OIDC:** Enforce multi-factor authentication and OpenID Connect (OIDC) trusted publishing workflows for all internal deployments and code repositories.

## Sources

1. [ThreatLocker: The Spreading Blight - Miasma Supply Chain Campaign targeting AI Tools](https://www.threatlocker.com/blog/the-spreading-blight-miasma-supply-chain-campaign)
2. [StepSecurity: Miasma Hades Compromise in Azure DurableTask](https://www.stepsecurity.io/blog/miasma-hades-durabletask-compromise)
3. [Phoenix Security: Hades Wave - Supply Chain Campaign Explores AI Coding Assistants](https://phoenix.security/blog/hades-wave-supply-chain-ai-coding-assistants)
4. [Zscaler ThreatLabz: Miasma Hades Campaign targeting Developer IDEs and AI Assistants](https://www.zscaler.com/blogs/security-research/miasma-hades-campaign-developer-ides-ai-assistants)
5. [StepSecurity: Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspicious Files](https://www.stepsecurity.io/blog/miasma-and-hades-are-spreading-now-detect-them-on-developer-machines-with-suspicious-files)
