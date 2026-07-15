---
title: "GlassWorm Developer Supply-Chain Botnet Takedown"
date: 2026-05-27
severity: "critical"
tags:
  - supply-chain
  - vscode
  - open-vsx
  - npm
  - pypi
summary: "CrowdStrike, Google, and Shadowserver disrupted GlassWorm command-and-control on 2026-05-26 after the campaign used malicious IDE extensions, packages, and poisoned repositories to compromise developer systems."
sourceCount: 5
---

## Executive Summary

On 2026-05-26 at 14:00 UTC, CrowdStrike says it coordinated with Google and the Shadowserver Foundation to disrupt the GlassWorm botnet's command-and-control channels, cutting infected developer machines off from new operator instructions and payload delivery [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/). The takedown does not prove that infected hosts are clean. It gives defenders a short containment window to find developer workstations, CI runners, and build boxes that installed GlassWorm-linked extensions or packages.

GlassWorm is a developer-tooling supply-chain campaign first publicly documented by Koi Security in October 2025. Koi reported self-propagation through stolen marketplace credentials and malicious code concealed with invisible Unicode characters [Koi Security](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace). CrowdStrike later described trojanized VS Code-compatible extensions, malicious npm and Python packages, and more than 300 poisoned GitHub repositories created or modified with previously stolen developer credentials [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/). Socket's April 2026 research adds registry-level detail: a cluster of 73 Open VSX impersonation extensions, including activated hosts that used `extensionPack` transitive delivery, bundled native `.node` installers, or obfuscated JavaScript to retrieve VSIX payloads from GitHub [Socket](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm).

Treat any confirmed GlassWorm hit as a developer identity incident, not just malware cleanup. The affected endpoints can hold GitHub, npm, Open VSX, SSH, cloud, Kubernetes, package-registry, AI-tooling, and wallet credentials.

## Key Facts

**Threat Type**: developer tooling supply-chain botnet

**Ecosystems**:
- Open VSX
- VS Code-compatible extension marketplaces
- npm
- PyPI / Python packages
- GitHub repositories

**Campaign Activity First Seen**: at least early 2025

**First Public Disclosure**: 2025-10-18

**Disruption Time Utc**: 2026-05-26T14:00:00Z

**Primary Targets**:
- software developer workstations
- CI/CD runners
- source-code repositories
- package registry publisher accounts

**Execution Paths**:
- Open VSX extension activation
- VS Code-compatible IDE extension installation
- npm postinstall hooks
- Python setup scripts
- poisoned repository code changes

**Confirmed Malicious Extensions**:
- outsidestormcommand.monochromator-theme
- keyacrosslaud.auto-loop-for-antigravity
- krundoven.ironplc-fast-hub
- boulderzitunnel.vscode-buddies
- cubedivervolt.html-code-validate
- winnerdomain17.version-lens-tool

**Activated April 29 Hosts**:
- drobnyak.angular-auto-helper
- galushko.vsclassic-auto-pilot
- gusarev.mermaid-super-studio
- lavrentev.project-live-studio
- lesnitsky.tikbook-easy-lens
- mashulin.vue-easy-studio
- mitrokhin.vsc-easy-studio
- mlechevik.nunjucks-rich-pilot
- mokridin.material-pro-suite
- ovchinin.markdown-live-craft
- peschanov.dbcode-smart-suite
- platarov.podmanager-pro-craft
- polikash.pretty-deep-kit
- porzhnev.swiftformat-deep-hub
- smolyak.slog-smart-studio
- svetelin.industrious-live-hub
- tarasenya.todo-rich-hub

**Hashes**:
- 1b62b7c2ed7cc296ce821f977ef7b22bae59ef1dcdb9a34ae19467ee39bcf168
- 4ebfe8f66ca7e9751060b3301b5e8838d6017593cdae748541de83bfa28183bd
- 97c275e3406ad6576529f41604ad138c5bdc4297d195bf61b049e14f6b30adfd

**Network Iocs Defanged**:
- 164.92.88[.]210
- github[.]com/SquadMagistrate10/wnxtgkih
- github[.]com/francesca898/dqwffqw
- github[.]com/ColossusQuailPray/oiegjqde

**Behavioral Iocs**:
- DownloadManager
- start_socks
- https://nodejs[.]org/download/release
- __import__('zlib')

**Confidence**: high

**Last Verified**: 2026-06-10

## Evidence Assessment

- **confirmed:** CrowdStrike states that the GlassWorm botnet disruption occurred on 2026-05-26 at 14:00 UTC with Google and Shadowserver cooperation [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/).
- **confirmed:** CrowdStrike describes four C2 resolution channels: Solana transaction memos, BitTorrent DHT, Google Calendar event titles, and direct server connections [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/).
- **confirmed:** Socket identifies 73 Open VSX impersonation extensions and an April 29 activation wave involving 23 new versions across 22 copycat extensions [Socket](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm).
- **confirmed:** Socket lists native installer hashes, a downloaded VSIX payload hash, GitHub payload-hosting repositories, six confirmed malicious extensions, and 17 activated April 29 host extensions [Socket](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm).
- **confirmed:** CrowdStrike published two YARA rules and states that post-disruption connections to `164.92.88[.]210` identify GlassWorm-infected machines [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/).
- **likely:** Any developer endpoint that ran a malicious extension should be treated as a credential exposure point even if the post-disruption C2 no longer responds.
- **unclear:** The complete package list, poisoned-repository list, downstream victim count, and number of hosts still reaching the sinkhole are not publicly enumerated.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | Host installed a confirmed malicious extension, executed a GlassWorm package hook, matched a listed payload hash, or connected to the CrowdStrike-operated sinkhole address after disruption. | Extension inventory, package-manager logs, endpoint file hashes, process telemetry, DNS/proxy/firewall logs, and preserved IDE extension directories. | Isolate the host, preserve disk and volatile evidence, rotate developer and CI credentials from a clean system, and review recent repository and registry activity. | Endpoint is rebuilt or forensically cleared, tokens are revoked, repository writes are audited, and registry publisher sessions are reset. |
| Presumed exposed | Host installed one of the activated April 29 Open VSX hosts, used Open VSX auto-update during the exposure window, or ran package installs from a repository later tied to GlassWorm. | IDE extension manifests, Open VSX cache, shell history, npm/Python install logs, and EDR process telemetry. | Freeze developer credentials, audit GitHub and registry activity, and collect endpoint artifacts before removal. | No execution, no suspicious network, and no credential use after exposure are confirmed. |
| Potentially exposed | Developer or CI asset uses VS Code-compatible IDEs, Open VSX, npm, PyPI, or unreviewed GitHub dependencies but no inventory has been collected. | Asset inventory, extension lists, package-lock exports, GitHub audit logs, and proxy telemetry. | Run the endpoint and network hunts below. | Scope is mapped to confirmed, presumed, or not exposed. |
| Not exposed | No listed extensions, hashes, GitHub payload repositories, sinkhole traffic, suspicious IDE installs, or GlassWorm package execution appears in complete telemetry. | Negative results from endpoint, package, repository, and network searches covering the full exposure period. | Record evidence and keep auto-update controls enabled. | Evidence package is retained with query timestamps. |
| Unknown | IDE extension directories, network telemetry, or developer identity logs are unavailable. | Gap statement naming missing systems and time ranges. | Decide rotations based on the highest-value credentials reachable from affected developers. | Missing telemetry is recovered or risk acceptance is approved. |

## Timeline

- **Early 2025:** CrowdStrike says GlassWorm operators were already targeting software developers through the open-source supply chain [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/).
- **2025-10-18:** Koi Security publicly documents the Open VSX worm and invisible-Unicode delivery technique [Koi Security](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace).
- **2026-03-13:** Aikido reports a renewed wave affecting more than 150 GitHub repositories plus npm and VS Code ecosystem artifacts [Aikido](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode).
- **2026-04-25:** Socket publishes the 73-extension Open VSX sleeper cluster report [Socket](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm).
- **2026-04-29T18:15:00Z to 2026-04-29T19:34:00Z:** Socket observes an activation wave pushing 23 new versions across 22 copycat extensions [Socket](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm).
- **2026-05-26T14:00:00Z:** CrowdStrike coordinates simultaneous disruption of GlassWorm C2 channels [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/).
- **2026-06-10:** Primary-source review confirms no public post-takedown victim count or complete artifact inventory.

## What Happened

GlassWorm blended social engineering with developer ecosystem mechanics. Socket's Open VSX cluster used copied names, icons, descriptions, and README content to impersonate legitimate extensions. Some extensions started as sleepers, then later received updates that pulled or installed malicious payloads through extension dependencies, `extensionPack`, GitHub-hosted VSIX files, native `.node` modules, or obfuscated JavaScript [Socket](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm).

CrowdStrike's takedown write-up expands the campaign boundary beyond Open VSX. It says GlassWorm used VS Code-compatible extensions, npm and Python package execution paths, and poisoned GitHub repositories, with a full-featured Node.js RAT and resilient C2 resolution across blockchain, peer-to-peer, public calendar, and direct server infrastructure [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/).

## Technical Analysis

### Initial Access

Initial access can arrive through a developer installing a cloned extension, an auto-updated Open VSX extension, a malicious npm package with a postinstall hook, a Python package setup script, or a poisoned GitHub repository. The most defensible public extension anchors are the six confirmed malicious extensions and the April 29 activated host extensions listed by Socket [Socket](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm). [1]

### Loader Behavior

Socket observed two important loader styles. One uses platform-specific native `.node` binaries loaded from extension activation code. Another uses obfuscated JavaScript to retrieve a VSIX payload from GitHub and install it into multiple IDEs with the `--install-extension` flow [Socket](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm). This means source review of the installed extension package may miss the behavior that ultimately executes. [1]

### Command And Control

CrowdStrike says GlassWorm used four C2 layers: Solana memo dead drops, BitTorrent DHT configuration lookups, Google Calendar event-title dead drops, and direct VPS-hosted server connections [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/). After the takedown, CrowdStrike shared a sinkhole-style indicator: infected machines now beacon to `164.92.88[.]210` [CrowdStrike](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/). [1]

### Credential Risk

The campaign targets developer systems because one endpoint can hold keys to source control, package publishing, cloud deployments, CI runners, and internal services. Rotate credentials in dependency order: registry tokens and GitHub sessions first, then cloud and CI/CD secrets, then SSH keys and workstation-local secrets. [1]

## Affected Assets and Blast Radius

**Affected Assets**:
- VS Code, Cursor, Positron, Windsurf, VSCodium, and other VSIX-compatible IDE installations
- Developer workstations and CI runners that installed GlassWorm-linked extensions or packages
- GitHub repositories writable by credentials available to infected developers
- npm, PyPI, and extension-publisher accounts reachable from infected systems

**Platforms**:
- Windows
- macOS
- Linux

**Highest Risk**:
- Developer endpoints with package publishing or repository administration access
- Build runners holding cloud, deployment, or registry secrets

**Public Scope Limitations**:
- CrowdStrike did not enumerate the complete malicious package or poisoned repository list
- A public count of remaining sinkhole connections was not available through 2026-06-10

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 1b62b7c2ed7cc296ce821f977ef7b22bae59ef1dcdb9a34ae19467ee39bcf168
- 4ebfe8f66ca7e9751060b3301b5e8838d6017593cdae748541de83bfa28183bd
- 97c275e3406ad6576529f41604ad138c5bdc4297d195bf61b049e14f6b30adfd

### Urls
- hxxps://nodejs[.]org/download/release


## Detection and Hunting

### Hunt Manifest: glassworm-developer-supply-chain-botnet-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with GlassWorm Developer Supply-Chain Botnet Takedown?
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
OUT = Path(os.environ.get("OUT", "hp-glassworm-developer-supply-chain-botnet-scope"))

DOMAINS = ["nodejs.org"]
URLS = ["https://nodejs.org/download/release"]
HASHES = ["1b62b7c2ed7cc296ce821f977ef7b22bae59ef1dcdb9a34ae19467ee39bcf168","4ebfe8f66ca7e9751060b3301b5e8838d6017593cdae748541de83bfa28183bd","97c275e3406ad6576529f41604ad138c5bdc4297d195bf61b049e14f6b30adfd"]

# Collect unique indicators
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "ioc-indicators.txt"
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

1. Remove affected developer hosts from the network after collecting volatile process, network, and extension inventory evidence.
2. Disable IDE extension auto-update for VS Code-compatible clients until extension provenance is reviewed.
3. Block or alert on the listed GitHub payload repositories and the CrowdStrike sinkhole indicator in proxy, DNS, and firewall telemetry.

### Eradication

1. Uninstall listed extensions and preserve their directories first.
2. Rebuild confirmed developer endpoints where token theft, RAT execution, or sinkhole traffic is found.
3. Revoke active GitHub, npm, PyPI, Open VSX, cloud, SSH, and CI/CD tokens for affected users from a clean administrative workstation.

### Recovery

1. Re-issue package registry tokens with least privilege and short expiry.
2. Require signed commits, protected branches, and package publishing approval for affected repositories.
3. Re-enable extension installation only from allowlisted publishers and pinned extension IDs.

### Closure Gates

- No listed extension IDs, payload repositories, hashes, or sinkhole traffic remain in endpoint and network telemetry.
- GitHub and package registry audit logs show no unexplained repository writes, workflow changes, package publications, or new tokens during the exposure window.
- All credentials reachable from confirmed hosts have been revoked and reissued from a clean environment.

## Sources

1. [CrowdStrike: Disrupting Glassworm: Inside CrowdStrike's Takedown of a Developer-Targeting Botnet](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/) - **Role:** DIRECT_SOURCE - **Impact:** Disruption time, campaign scope, C2 architecture, sinkhole indicator, and YARA rules.
2. [Koi Security: GlassWorm First Self-Propagating Worm Using Invisible Code](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace) - **Role:** PRIMARY_RESEARCH - **Impact:** Original public disclosure, invisible-Unicode loader, extension compromise, and propagation behavior.
3. [Aikido: GlassWorm Returns with Invisible Unicode Attacks](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode) - **Role:** PRIMARY_RESEARCH - **Impact:** March 2026 repository, npm, and VS Code ecosystem expansion.
4. [Socket: 73 Open VSX Sleeper Extensions Linked to GlassWorm](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm) - **Role:** PRIMARY_RESEARCH - **Impact:** April extension cluster, activation wave, artifact hashes, extension IDs, and payload repositories.
5. [Shadowserver: Media coverage of the GlassWorm disruption](https://www.shadowserver.org/who-we-are/media-coverage/) - **Role:** DIRECT_SOURCE - **Impact:** Independent participant confirmation of the coordinated May 26 disruption.
