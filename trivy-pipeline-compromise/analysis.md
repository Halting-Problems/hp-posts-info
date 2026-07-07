---
title: "Aqua Security Trivy CI/CD Pipeline & Tag Poisoning"
date: 2026-03-19
severity: "critical"
tags:
  - ci-cd
  - github-actions
  - supply-chain
  - tag-poisoning
  - credential-theft
summary: "On March 19, 2026, the widely adopted container vulnerability scanner Trivy was compromised in a major supply chain attack. Cybercrime group TeamPCP poisoned version tags to harvest and exfiltrate runner credentials."
sourceCount: 7
---
## Executive Summary
On March 19, 2026, the widely adopted container vulnerability scanner **Trivy** (developed by Aqua Security) was compromised in a major supply chain attack tracked as **CVE-2026-33634** (GHSA-69fq-xp46-6x23) [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23). Executed by the cybercrime group **TeamPCP** (also tracked as UNC6780, PCPcat, DeadCatx3, ShellForce, and CipherForce) [Wiz.io Threat Research](https://www.wiz.io), the attack targeted key Trivy distribution channels [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23). The threat actors force-pushed malicious commits to 76 of 77 version tags in `aquasecurity/trivy-action` and all 7 tags in `aquasecurity/setup-trivy` [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23). Simultaneously, they released a compromised official Trivy binary (**v0.69.4**) and poisoned container images (**v0.69.5** and **v0.69.6**) on Docker Hub [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23). The injected payload acted as a memory-scraping credential stealer, harvesting secrets from CI/CD runners via `/proc/*/mem` and exfiltrating them to an attacker-controlled typosquatted C2 domain `scan.aquasecurtiy[.]org` [Legit Security](https://www.legitsecurity.com). If outbound access to the C2 domain failed, the malware deployed a fallback technique, leveraging stolen GitHub tokens to create a public repository named `tpcp-docs` on the victim's organization to store encrypted exfiltrated data [Palo Alto Networks Unit 42](https://www.paloaltonetworks.com). Start with the runner-memory, tag-drift, and fallback-repository hunts below, then rotate identities exposed during confirmed runs [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23).

## Key Facts
**Threat Type**: CI/CD Pipeline Compromise & Tag Poisoning

**Ecosystem**: github-actions, container-images, go

**Registry**: GitHub Releases, Docker Hub

**Affected Packages**:
- aquasecurity/trivy-action
- aquasecurity/setup-trivy
- aquasec/trivy

**Malicious Versions**:
- aquasecurity/trivy-action@v0.0.1..v0.34.2
- aquasecurity/setup-trivy@v0.2.0..v0.2.6
- trivy-binary@v0.69.4
- aquasec/trivy:0.69.5
- aquasec/trivy:0.69.6

**Fixed Versions**:
- aquasecurity/trivy-action@v0.35.0
- aquasecurity/setup-trivy@v0.2.6
- trivy-binary@v0.69.7
- aquasec/trivy:0.69.7

**Safe Versions**:

**Exposure Window**: 2026-03-19T08:00:00Z to 2026-03-19T18:00:00Z

**Execution Trigger**: Runner execution of workflows containing poisoned actions, or execution of compromised CLI binaries/containers

**Primary Impact**: Host memory scraping, secret harvesting, and automated exfiltration via typosquat C2 or public fallback repositories

**Known Iocs**:
- scan.aquasecurtiy[.]org
- tpcp-docs

**Confidence**: high

**Canonical Source**: https://github.com/advisories/GHSA-69fq-xp46-6x23

## Evidence Assessment
*   **confirmed:**
    *   Residual active token left during an incomplete, non-atomic credential rotation in late February 2026 allowed attackers repository write access. Source: [Wiz.io Threat Research](https://www.wiz.io)
    *   Malicious force-pushing occurred across 76 of 77 historical version tags in `aquasecurity/trivy-action` and all 7 tags in `aquasecurity/setup-trivy`. Source: [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23)
    *   Compromised v0.69.4 binary and container images v0.69.5 and v0.69.6 hosted on Docker Hub contained malicious payloads. Source: [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23)
    *   Malicious code attempted memory scraping of runner processes via `/proc/*/mem` and targeted AWS, GCP, Azure, GitHub, and webhook credentials. Source: [Legit Security](https://www.legitsecurity.com)
*   **likely:**
    *   The campaign is attributed to the cybercrime threat group TeamPCP. Source: [Broadcom / Symantec](https://www.broadcom.com)
    *   A fallback exfiltration route was triggered upon primary C2 failures, dynamically creating a public repository named `tpcp-docs` to leak encrypted data. Source: [Palo Alto Networks Unit 42](https://www.paloaltonetworks.com)
*   **unclear:**
    *   The total number of downstream pipelines and credentials harvested during the active 10-hour exposure window. Source: [CrowdStrike Intelligence](https://www.crowdstrike.com)
*   **not_observed:**
    *   Self-propagating worm capabilities spreading laterally inside victim infrastructure beyond the immediate CI/CD workspace environment. Source: [Palo Alto Networks Unit 42](https://www.paloaltonetworks.com)

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | a poisoned Trivy action tag, binary, or image is present and workflow action, compromised CLI binary, or container image executes in a runner or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing workflow action, compromised CLI binary, or container image executes in a runner or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | a poisoned Trivy action tag, binary, or image was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but workflow, action, release, or runner execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for aquasecurity/trivy-action@v0.0.1-v0.34.2, aquasecurity/setup-trivy@v0.2.0-v0.2.6, trivy-binary@v0.69.4, aquasec/trivy:0.69.5.
- Execution evidence for workflow action, compromised CLI binary, or container image executes in a runner.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-02-28T00:00:00Z** Aqua Security experiences an initial security incident. Key credentials are rotated, but a single persistent token remains active. Source: [Wiz.io Threat Research](https://www.wiz.io)
- **2026-03-19T08:00:00Z** TeamPCP utilizes the residual credential to gain write access to the Trivy repositories on GitHub. Source: [Wiz.io Threat Research](https://www.wiz.io)
- **2026-03-19T09:00:00Z** Attackers begin force-pushing malicious commits to `aquasecurity/trivy-action` and `aquasecurity/setup-trivy` version tags, and upload malicious binary v0.69.4. Source: [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23)
- **2026-03-19T12:00:00Z** Downstream enterprise users report anomalous outbound network connections during pipeline security scans. Source: [CrowdStrike Intelligence](https://www.crowdstrike.com)
- **2026-03-19T18:00:00Z** Aqua Security identifies the compromise, revokes the hijacked write tokens, pulls the malicious releases, and publishes a remediation advisory. Source: [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23)
- **2026-03-20T09:00:00Z** Coordinated security advisories are released detailing the cleanup actions. The incident is cataloged as GHSA-69fq-xp46-6x23. Source: [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23)

## What Happened
The attack originated in late February 2026, when Aqua Security experienced an initial security incident [Wiz.io Threat Research](https://www.wiz.io). Although the security team initiated credential rotations, the remediation process was not fully atomic [Wiz.io Threat Research](https://www.wiz.io). A single persistent token was left active, which gave the threat actors a lingering foothold [Wiz.io Threat Research](https://www.wiz.io).

On March 19, 2026, at 08:00 UTC, the cybercrime group TeamPCP leveraged the residual write token to access official Trivy repositories on GitHub [Wiz.io Threat Research](https://www.wiz.io). Within two hours, the threat actors force-pushed poisoned commits directly into 76 of the 77 version tags for `aquasecurity/trivy-action`, and all 7 tags in `aquasecurity/setup-trivy` [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23). Because Git version tags are mutable, pipelines consuming these actions automatically pulled and executed the poisoned commits [Legit Security](https://www.legitsecurity.com). Additionally, the attackers published a compromised Trivy binary (`v0.69.4`) and uploaded two infected container images (`v0.69.5` and `v0.69.6`) on Docker Hub [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23).

By 12:00 UTC, multiple downstream enterprise environments detected suspicious network requests from security scanning jobs [CrowdStrike Intelligence](https://www.crowdstrike.com). Aqua Security intervened, revoking the hijacked access credentials, removing the compromised releases, and publishing advisory notices to restrict further downstream damage [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23). The vulnerability was subsequently logged as CVE-2026-33634 [NIST NVD Advisory](https://nvd.nist.gov/vuln/detail/CVE-2026-33634).

## Technical Analysis

### Initial Access
The threat actors gained access to Aqua Security's official repository structures by exploiting a residual API write credential [Wiz.io Threat Research](https://www.wiz.io). This credential survived a non-atomic credential rotation in late February 2026, leaving a single persistent token active and permitting write operations [Wiz.io Threat Research](https://www.wiz.io).

### Package or Artifact Manipulation
The attackers modified official distribution points in a multi-pronged attack [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23):
* **Git Tag Poisoning:** The attackers force-pushed modified commits directly to historical Git tags in `aquasecurity/trivy-action` and `aquasecurity/setup-trivy` [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23).
* **Compromised Binaries:** They modified the compilation pipelines of the core Trivy scanner to inject malicious assembly into the compiled `v0.69.4` binaries [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23).
* **Container Poisoning:** They rebuilt official Docker Hub container images (`v0.69.5` and `v0.69.6`) incorporating the malicious payload [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23).

### Execution Trigger
The execution trigger occurred automatically whenever a downstream developer pipeline pulled and executed a workflow using `uses: aquasecurity/trivy-action` or `uses: aquasecurity/setup-trivy` [Legit Security](https://www.legitsecurity.com). Alternatively, executing the compromised `v0.69.4` binary in CLI operations or running the compromised `v0.69.5`/`v0.69.6` containers initiated runtime execution of the payload [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23).

### Payload Behavior
Once executed in a victim's CI/CD pipeline or host environment, the malicious payload initiated a highly targeted credential harvesting sequence:
* **Memory Scraping:** The payload read active host memory via the `/proc/*/mem` virtual filesystem to parse environment variables and memory space for active credentials [Legit Security](https://www.legitsecurity.com).
* **Credential Targets:** The malware scanned for AWS/GCP/Azure cloud access keys, Kubernetes service account tokens, GitHub Actions OIDC tokens, SSH private keys, and webhook endpoints for Slack and Discord [Legit Security](https://www.legitsecurity.com).
* **Data Packaging:** The collected secrets were compressed and encrypted using a robust hybrid AES-256 and RSA-4096 encryption scheme to evade deep packet inspection [Palo Alto Networks Unit 42](https://www.paloaltonetworks.com).

### Exfiltration / C2
**Domains**:
- scan.aquasecurtiy[.]org

**Ips**:

**Urls**:
- hxxps://scan[.]aquasecurtiy[.]org/exfil

**Protocols**:
- HTTPS

**Endpoints**:
- /exfil

**Confidence**: high

The encrypted data was transmitted via HTTPS POST to the attacker-controlled typosquat domain `scan.aquasecurtiy[.]org` [Legit Security](https://www.legitsecurity.com).

In instances where outbound network queries to the typosquatted C2 domain were blocked or failed, the payload fell back to an alternative exfiltration path: it utilized the harvested GitHub Personal Access Tokens (PATs) or runner OIDC tokens to authenticate to GitHub, create a public repository named `tpcp-docs` (or variations like `docs-tpcp`) within the victim's own organization, and uploaded the encrypted secrets as a release asset [Palo Alto Networks Unit 42](https://www.paloaltonetworks.com). This allowed TeamPCP to bypass outbound firewall restrictions by utilizing legitimate GitHub APIs and using the victim's own infrastructure as a storage medium [Palo Alto Networks Unit 42](https://www.paloaltonetworks.com). [1]

### Propagation
The attack did not feature self-propagating worm-like code inside the target network; however, the initial attack vector propagated automatically to all downstream pipelines that used mutable version tags [Legit Security](https://www.legitsecurity.com).

### Obfuscation or Evasion
To evade detection, the attackers employed several techniques:
* **Typosquatting C2:** The domain name `scan.aquasecurtiy[.]org` typosquatted Aqua Security's real domain `aquasecurity.org` to escape domain blacklist sweeps and inspection [Legit Security](https://www.legitsecurity.com). [1]
* **Hybrid Encryption:** The exfiltrated data was encrypted using hybrid AES-256 and RSA-4096 encryption, hiding the plaintext credentials from network-layer traffic analyzers [Palo Alto Networks Unit 42](https://www.paloaltonetworks.com). [1]
* **Reputation Hijacking:** The fallback exfiltration wrote encrypted payloads directly to a public GitHub repository (`tpcp-docs`) created on the victim's own GitHub organization, masking illegal data transfer under legitimate GitHub traffic [Palo Alto Networks Unit 42](https://www.paloaltonetworks.com). [1]

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: github-actions,container-images,go
  - **packages**: aquasecurity/trivy-action,aquasecurity/setup-trivy,aquasec/trivy
  - **versions**: trivy-action@v0.0.1-v0.34.2,setup-trivy@v0.2.0-v0.2.6,trivy-binary@v0.69.4,aquasec/trivy:0.69.5,aquasec/trivy:0.69.6
  - **repositories**: github.com/aquasecurity/trivy-action,github.com/aquasecurity/setup-trivy,github.com/aquasecurity/trivy
  - **container_images**: aquasec/trivy:0.69.5,aquasec/trivy:0.69.6
  - **CI_CD_systems**: GitHub Actions
  - **developer_tools**: Trivy CLI
  - **environments**: developer workstations,CI runners,build pipelines,containers,production systems

**Credentials At Risk**:
- AWS access keys
- GCP service account keys
- Azure access tokens
- GitHub Actions OIDC tokens
- GitHub Personal Access Tokens (PATs)
- SSH private keys
- Slack/Discord webhook secrets

**Not Currently Known To Affect**:
- CI/CD pipelines running on GitLab or Bitbucket that did not fetch the affected Trivy binaries or container images.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- scan[.]aquasecurtiy[.]org
- www[.]legitsecurity[.]com

### Urls
- hxxps://scan[.]aquasecurtiy[.]org/exfil
- hxxps://www[.]legitsecurity[.]com
- hxxps://github[.]com/advisories/GHSA-69fq-xp46-6x23


## Detection and Hunting

### Hunt Manifest: trivy-pipeline-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Aqua Security Trivy CI/CD Pipeline & Tag Poisoning?
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
OUT = Path(os.environ.get("OUT", "hp-trivy-pipeline-compromise-scope"))

DOMAINS = ["scan[.]aquasecurtiy[.]org","www[.]legitsecurity[.]com","github.com"]
URLS = ["https://scan.aquasecurtiy.org/exfil","https://www.legitsecurity.com","https://github.com/advisories/GHSA-69fq-xp46-6x23"]

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
            print(f"[+] Querying go list for {package}...")
            env = os.environ.copy()
            env["GONOSUMDB"] = "*"
            res = subprocess.run(["go", "list", "-m", "-json", package], capture_output=True, text=True, env=env)
            if res.returncode == 0:
                (registry_dir / f"go-{safe_name}.json").write_text(res.stdout)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [GitHub Advisory Database](https://github.com/advisories/GHSA-69fq-xp46-6x23). **Role:** DIRECT_SOURCE **Impact:** Detailed the compromised tags, versions, safe releases, and remediation timeline.
2. [Broadcom / Symantec](https://www.broadcom.com/support/security-center/teampcp-supply-chain-trivy-compromise). **Role:** PRIMARY_RESEARCH **Impact:** Detailed threat actor TeamPCP and the broader campaign context.
3. [NIST NVD Advisory](https://nvd.nist.gov/vuln/detail/CVE-2026-33634). **Role:** ENRICHMENT_DATA **Impact:** Formally registered the CVE tracking the vulnerability and details of the supply chain compromise.
4. [Legit Security](https://www.legitsecurity.com/blog/trivy-pipeline-compromise-memory-scraping-payload). **Role:** PRIMARY_RESEARCH **Impact:** Documented the memory scraping payload targeting `/proc/*/mem` and exfiltration to `scan.aquasecurtiy[.]org`.
5. [Wiz.io Threat Research](https://www.wiz.io/blog/trivy-pipeline-compromise-residual-token-abuse). **Role:** PRIMARY_RESEARCH **Impact:** Uncovered the incomplete, non-atomic credential rotation that left a residual write token active.
6. [CrowdStrike Intelligence](https://www.crowdstrike.com/blog/trivy-pipeline-compromise-ci-cd-network-anomalies). **Role:** PRIMARY_RESEARCH **Impact:** Identified outbound CI/CD network anomalies and flagged early indicators.
7. [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/teampcp-trivy-pipeline-compromise-encryption/). **Role:** SECONDARY_ANALYSIS **Impact:** Analyzed the encryption routine (AES-256 + RSA-4096) and fallback exfiltration repository `tpcp-docs`.
