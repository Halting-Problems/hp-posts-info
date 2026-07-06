---
title: "Leo Platform npm Miasma / Phantom Gyp Compromise"
date: 2026-06-25
severity: "critical"
tags:
  - npm
  - leo-platform
  - supply-chain
  - credential-theft
  - mini-shai-hulud
  - miasma
  - phantom-gyp
summary: "StepSecurity disclosed a June 24, 2026 Leo Platform npm supply-chain compromise affecting 20 packages published in a three-second burst. Socket and Sonatype then tied three more malicious npm packages to the same Miasma / Mini Shai-Hulud Phantom Gyp tradecraft, extending the incident into a 23-package campaign update."
sourceCount: 5
---

## Executive Summary

On **2026-06-25**, StepSecurity disclosed a Leo Platform npm supply-chain compromise affecting 20 packages that were maliciously published within roughly three seconds on **2026-06-24T23:04:55Z**. Later the same day, Socket and Sonatype tied three additional npm packages — `hexo-deployer-wrangler@1.0.4`, `hexo-shoka-swiper@0.1.10`, and `prism-silq@1.0.1` — to the same Miasma / Mini Shai-Hulud tradecraft and reported that the follow-on cluster was published by npm user `llxlr` around **2026-06-25T09:17:14Z**. StepSecurity says the original Leo Platform set receives about **13,600 weekly downloads**, while the follow-on reporting says the shared payload still uses the `binding.gyp`-based **Phantom Gyp** install hook, layered obfuscation, Bun runtime download, and GitHub-based secret exfiltration seen in the earlier Miasma wave [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)] [[sonatype.com](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)]. [1][4][5]

This is not a passive vulnerable dependency advisory. Installing one of the affected versions can execute attacker code during dependency resolution, package build, or CI pipeline runs before application code starts. npm registry metadata independently confirms representative publish timestamps for packages such as `leo-logger`, `leo-sdk`, `leo-aws`, and `solo-nav` in the initial burst, and for `hexo-deployer-wrangler`, `hexo-shoka-swiper`, and `prism-silq` in the follow-on cluster, while direct resolution of `leo-logger@1.0.8` and `leo-cron@2.0.2` already fails, which is consistent with post-disclosure cleanup rather than a contradictory package history [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[npmjs.com](https://www.npmjs.com/)] [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)] [[sonatype.com](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)]. [1][2][4][5]

Treat any confirmed install on a developer workstation, CI runner, image-build host, or release pipeline as likely credential exposure until evidence proves otherwise. The public reporting describes GitHub token abuse, cloud credential collection, GitHub GraphQL exfiltration using the victim's own token, and follow-on package publishing through npm's `bypass_2fa` behavior, and the new Socket and Sonatype reporting shows that the package list continued to expand after the initial Leo Platform disclosure [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)] [[sonatype.com](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)]. [1][4][5]

### Source-Watcher Candidate Queue

**Candidate Id**: leo-platform-npm-miasma-compromise

**First Seen**: 2026-06-25

**Decision**: publish_ready

**Relationship**: child_event_of_mini_shai_hulud_worm

**Dedupe Keys**:
- campaign:mini-shai-hulud
- payload:miasma
- technique:phantom-gyp
- npm:leo-logger@1.0.8
- npm:leo-sdk@6.0.19
- npm:hexo-deployer-wrangler@1.0.4
- npm:hexo-shoka-swiper@0.1.10
- npm:prism-silq@1.0.1
- package-family:leo-platform
- package-family:rstreams

**Starting Sources**:
- StepSecurity primary research
- npm registry metadata
- prior Miasma technical write-up for family comparison
- Socket primary research follow-up
- Sonatype primary research follow-up

## Key Facts

**Threat Type**: malicious npm package publish compromise

**Ecosystem**: npm

**Registry**: npm

**Campaign Context**: likely child event of Miasma / Mini Shai-Hulud

**Reported Package Count**: 23 across two linked clusters (20 Leo Platform / RStreams packages plus 3 follow-on npm packages)

**Execution Trigger**: install-time execution via `binding.gyp` / `node-gyp` shell expansion

**Reported Publish Windows**:
- 2026-06-24T23:04:55Z through 2026-06-24T23:04:58Z (initial Leo Platform burst)
- 2026-06-25T09:17:14Z through 2026-06-25T09:17:15Z (follow-on package cluster)

**Credential Risk**:
- GitHub tokens
- npm publishing tokens
- cloud credentials
- Vault tokens
- password manager secrets

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| Twenty Leo Platform npm packages were maliciously published on 2026-06-24. | confirmed | StepSecurity lists the 20 affected package/version pairs and describes the coordinated publish burst [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)]. |
| Socket and Sonatype identified three additional malicious npm packages linked to the same Miasma wave: `hexo-deployer-wrangler@1.0.4`, `hexo-shoka-swiper@0.1.10`, and `prism-silq@1.0.1`. | confirmed | Socket says the campaign was not limited to the original publisher account and names the three follow-on packages, while Sonatype says the same packages contain the same obfuscated payload and `binding.gyp` execution method [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)] [[sonatype.com](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)]. |
| The malicious versions were published in a near-simultaneous automated operation. | confirmed | StepSecurity reports a three-second burst, and npm registry metadata for representative packages shows publish times clustered around 2026-06-24T23:04:55Z [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[npmjs.com](https://www.npmjs.com/)]. |
| The three follow-on packages were published through npm user `llxlr` within about one second on 2026-06-25. | confirmed | Socket attributes the three follow-on packages to the `llxlr` publisher, Sonatype says they were all published by an account that was likely compromised, and npm registry metadata shows publish times at 2026-06-25T09:17:14Z to 2026-06-25T09:17:15Z for those versions [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)] [[sonatype.com](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)] [[npmjs.com](https://www.npmjs.com/)]. |
| The payload uses the same Phantom Gyp / Bun / GitHub exfiltration stack as the earlier Miasma wave. | likely | StepSecurity explicitly compares the Leo Platform payload to its prior Miasma analysis and says the hook syntax, obfuscation layers, Bun downloader, and exfiltration pattern are identical [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)]. |
| Public reporting proves Leo Platform's exact upstream intrusion path or a vendor cleanup statement. | unclear | The reviewed public material provides the package list and payload details, but this refresh did not locate a direct vendor statement or a public timeline of maintainer-account recovery. |
| Public reporting proves downstream victim count or confirmed cloud control-plane abuse. | not_observed | The reviewed sources describe credential collection capability and worm behavior, but they do not publish a verified downstream victim count or a confirmed list of cloud-account takeovers. |

## Impact Determination

| Classification | Criteria | Required Evidence | Handling decision | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | An affected listed version was installed and endpoint, process, package, or CI telemetry shows the Phantom Gyp selectors or post-install payload behavior. | Lockfile or package-cache hit plus install logs, endpoint telemetry, CI logs, or extracted package contents showing the payload selectors. | Isolate the host or runner, preserve package artifacts, rotate reachable credentials, and audit follow-on GitHub/npm/cloud activity. | Affected artifacts are removed, credentials are rotated, and downstream audits show no unexplained write or publish activity. |
| Presumed exposed | An affected listed version was installed on a credential-bearing workstation, runner, or image build, but runtime telemetry is incomplete. | Dependency lock, package cache, build log, internal mirror record, or container layer showing the listed versions. | Treat GitHub, npm, cloud, Vault, and password-manager secrets reachable from that environment as exposed. | Risk owners confirm clean rebuilds and credential rotation or accept documented residual risk. |
| Potentially exposed | Repositories or builds use the affected package families, but exact resolved versions or install execution are not established. | Repository manifests, lockfiles, proxy logs, internal mirror metadata, and CI build records. | Reconstruct package resolution and install execution before narrowing scope. | Each hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected package names, versions, tarballs, or payload selectors appear in complete evidence. | Negative repository, cache, CI, endpoint, and proxy searches covering the exposure window. | Preserve the negative evidence and keep lifecycle-script restrictions in place. | Evidence coverage includes developer endpoints, CI runners, image builds, and package mirrors. |
| Unknown | Dependency, package-cache, endpoint, or CI telemetry is missing. | Named gap with system owner, retention limit, and the specific evidence that is unavailable. | Keep reachable credentials in scope until evidence or rotation closes the gap. | Missing evidence is recovered or the risk owner accepts residual uncertainty. |

## Minimum Evidence To Collect

- Collect dependency locks, internal registry logs, and extracted npm cache records for all 23 listed packages because they prove which exact versions resolved, show whether your environment ever fetched a compromised tarball, and resolve the difference between merely using one of the affected package families and actually installing a malicious version.
- Collect CI runner logs, package-manager debug output, and build artifacts from the **2026-06-24T23:04:55Z** window because they can show `binding.gyp`, Bun download activity, or package-install traces, which is the evidence needed to move an environment from potentially exposed to presumed or confirmed compromise.
- Collect endpoint telemetry or EDR process logs from developer workstations and runners because StepSecurity's reported payload behaviors include Bun execution, `Runner.Worker` memory access, and GitHub token misuse, which are the behaviors that prove the install-time payload executed rather than remaining only a package-resolution event.
- Collect GitHub audit logs, workflow file diffs, npm organization audit history, and cloud activity logs because the reported payload can exfiltrate secrets through GitHub and then publish or write elsewhere, and these downstream logs are what resolves whether exposure remained local or turned into follow-on compromise. [1]

## Timeline

- **2026-06-24T23:04:55Z to 2026-06-24T23:04:58Z**: npm registry metadata for representative packages shows the malicious Leo Platform versions landing in a tightly clustered burst, matching StepSecurity's report of a three-second automated publish operation [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[npmjs.com](https://www.npmjs.com/)].
- **2026-06-25**: StepSecurity publishes its analysis of the 20-package Leo Platform compromise, including package/version pairs, payload fingerprints, and the comparison to the earlier Miasma wave [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)].
- **2026-06-25T09:17:14Z to 2026-06-25T09:17:15Z**: npm registry metadata shows `hexo-deployer-wrangler@1.0.4`, `hexo-shoka-swiper@0.1.10`, and `prism-silq@1.0.1` published in a second tightly clustered wave under npm user `llxlr` [[npmjs.com](https://www.npmjs.com/)] [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)].
- **2026-06-25**: Socket and Sonatype publish follow-up reporting that links the three additional packages to the same Miasma / Mini Shai-Hulud tradecraft [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)] [[sonatype.com](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)].
- **2026-06-25**: This Halting Problems refresh updated the earlier same-day incident report with the three newly reported package versions.

## What Happened

An unauthorized actor first published malicious versions across 20 Leo Platform and RStreams npm packages in a tightly synchronized burst, then the same day a second linked cluster added `hexo-deployer-wrangler@1.0.4`, `hexo-shoka-swiper@0.1.10`, and `prism-silq@1.0.1`. StepSecurity says the original packages were poisoned with the same Phantom Gyp technique used in the earlier Miasma wave, and the follow-up Socket and Sonatype reporting says the newly identified packages carry the same `binding.gyp`-driven execution path and obfuscated payload family [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)] [[sonatype.com](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)]. [1][4][5]

The public evidence is strong enough to treat this as a child event in the broader Miasma / Mini Shai-Hulud family, but not strong enough to overstate the attribution. StepSecurity's comparison is based on payload fingerprints and behavior, not on a public maintainer statement explaining how the Leo Platform credentials were stolen. That means responders should rely on the shared tradecraft for hunting and containment while still preserving uncertainty about the upstream intrusion path. [1][3]

## Technical Analysis

### Initial Access

The reviewed public reporting confirms the package publishes but does not publish a Leo Platform maintainer postmortem describing the precise upstream account-takeover path. The strongest defensible claim is that an unauthorized actor obtained publishing access to the affected Leo Platform packages and used that access to push malicious releases in a short automated burst, then either compromised or abused a second publisher account (`llxlr`) to release three more matching packages later on 2026-06-25 [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[npmjs.com](https://www.npmjs.com/)] [[socket.dev](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)] [[sonatype.com](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)]. [1][2][4][5]

### Execution Trigger

StepSecurity says the payload uses the Phantom Gyp pattern: a `binding.gyp` file triggers shell execution through the normal `node-gyp` build path, which means package installation or CI dependency resolution can execute attacker code before application startup and without relying on a visible npm lifecycle script entry [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)]. [1]

### Payload Behavior

The reported payload stack matches the earlier Miasma tooling. StepSecurity says the code downloads Bun v1.3.13, uses the same three-layer obfuscation chain, drops temporary JavaScript under `/tmp`, and executes the payload during install-time processing. This is the key reason to treat Leo Platform package installation as possible active compromise rather than as a harmless metadata event [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)]. [1][3]

### Credential or Data Collection

StepSecurity's summary says the payload reads GitHub Actions `Runner.Worker` process memory through `/proc/{pid}/mem`, searches for multi-cloud credentials, npm tokens, Vault tokens, GitHub PATs, and 1Password material, and uses npm's `bypass_2fa` capability to propagate to additional packages when it finds publish rights [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)]. [1]

### Defense Evasion

The payload avoids simple script-blocking reviews because the execution lives in `binding.gyp` rather than an obvious `package.json` lifecycle script. StepSecurity also says the Leo Platform samples reuse the same obfuscation layers and Bun runtime evasion from the prior Miasma work, which means defenders should not assume ordinary Node.js-only monitoring would see the full execution chain [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)] [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)]. [1][3]

### Exfiltration and Command and Control

A notable detail in StepSecurity's Leo Platform analysis is that the payload does **not** need an attacker-owned C2 domain for exfiltration. Instead, stolen material is encrypted and committed through the GitHub GraphQL API using the victim's own GitHub token, while the Bun runtime is downloaded from GitHub Releases. That makes GitHub API and GitHub Releases telemetry part of the incident surface even when no obviously malicious domain appears in network logs [[stepsecurity.io](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)]. [1]

## Affected Assets and Blast Radius

The immediate blast radius is any environment that installed one of the 23 listed malicious versions during either publish window. Because the public reporting describes credential theft and worm-style propagation, the response scope should include developer workstations, CI runners, release builders, container-image pipelines, internal package mirrors, and any GitHub or cloud identities reachable from those systems. [1][4][5]

| Asset class | In-scope examples | Why it matters |
| --- | --- | --- |
| Packages | `leo-logger`, `leo-sdk`, `leo-aws`, `solo-nav`, `hexo-deployer-wrangler`, `hexo-shoka-swiper`, `prism-silq` | These are the directly affected npm artifacts and the fastest way to scope exposure across both linked publish clusters. |
| Build environments | GitHub Actions runners, self-hosted CI, container builders | Install-time execution can expose credentials before application code runs. |
| Identities | GitHub PATs, npm publish rights, cloud credentials, Vault tokens, 1Password material | StepSecurity says the payload searches for and steals each of these secret classes. |
| Downstream systems | Repositories with publish rights, internal registries, cloud control planes | A successful credential theft can turn a local package incident into broader supply-chain or cloud abuse. |

## Indicators of Compromise

The following selectors are specific enough to use for scoping while staying grounded in the reviewed sources:

### Package Versions
- `leo-logger@1.0.8`
- `leo-sdk@6.0.19`
- `leo-aws@2.0.4`
- `leo-config@1.1.1`
- `leo-streams@2.0.1`
- `serverless-leo@3.0.14`
- `leo-connector-mongo@3.0.8`
- `serverless-convention@2.0.4`
- `rstreams-metrics@2.0.2`
- `leo-connector-elasticsearch@2.0.6`
- `leo-auth@4.0.6`
- `leo-cache@1.0.2`
- `leo-cli@3.0.3`
- `hexo-deployer-wrangler@1.0.4`
- `hexo-shoka-swiper@0.1.10`
- `leo-cron@2.0.2`
- `leo-connector-redshift@3.0.6`
- `leo-connector-oracle@2.0.1`
- `prism-silq@1.0.1`
- `rstreams-shard-util@1.0.1`
- `leo-connector-mysql@3.0.3`
- `leo-cdk-lib@0.0.2`
- `solo-nav@1.0.1`

### Behavioral Selectors
- `binding.gyp`
- `Runner.Worker`
- `/proc/{pid}/mem`
- `bypass_2fa`
- `ALL=(ALL) NOPASSWD:ALL`
- `https://api.github.com/graphql`
- `https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/`

### Verified Hashes
- `d45ad3cffbcc7c4b354ebe9d71d002fa585379ec` (`leo-sdk@6.0.19`)
- `1dcc0a39e1cd7293a9058cfc41e1afe8b397c943` (`leo-aws@2.0.4`)
- `ef8bf6dd92cbc29ef8d23f3f0fa786ed20a856b1` (`leo-cdk-lib@0.0.2`)
- `9be49287057cd6a54ef4a70a8d541a7259efbd2d` (`solo-nav@1.0.1`)
- `c05068f18e7f94304b92a307a030e0038ab61004` (`hexo-deployer-wrangler@1.0.4`)
- `cb78d0dca573f99a22b41ca01e99853a6162d5d5` (`hexo-shoka-swiper@0.1.10`)
- `c721c184dbb5c2dc23bacfd28571daef1decfac1` (`prism-silq@1.0.1`) [1][2][4][5]

## Detection and Hunting

### Hunt Manifest: leo-platform-npm-miasma-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain indicators associated with the Leo Platform npm Miasma / Phantom Gyp compromise and the linked follow-on package wave?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem, package cache, or exported CI/endpoint logs
- **Positive Signal:** Affected Leo Platform package selectors, payload fingerprints, or post-install behavior matched in the scanned scope.
- **False Positives:** Benign references to the StepSecurity article or internal documentation can match the textual selectors without proving execution.
- **Classification on Match:** potentially_exposed

```py
#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
LOG_ROOT = Path(os.environ['LOG_ROOT']).resolve() if os.environ.get('LOG_ROOT') else None
OUT = Path(os.environ.get('OUT', 'hp-leo-platform-npm-miasma-compromise-scope'))
OUT.mkdir(parents=True, exist_ok=True)
INDICATORS_FILE = OUT / 'indicators.txt'

PACKAGES = [
    'hexo-deployer-wrangler',
    'hexo-shoka-swiper',
    'leo-auth',
    'leo-aws',
    'leo-cache',
    'leo-cdk-lib',
    'leo-cli',
    'leo-config',
    'leo-connector-elasticsearch',
    'leo-connector-mongo',
    'leo-connector-mysql',
    'leo-connector-oracle',
    'leo-connector-redshift',
    'leo-cron',
    'leo-logger',
    'leo-sdk',
    'leo-streams',
    'prism-silq',
    'rstreams-metrics',
    'rstreams-shard-util',
    'serverless-convention',
    'serverless-leo',
    'solo-nav',
]
PACKAGE_VERSIONS = [
    'leo-logger@1.0.8',
    'leo-sdk@6.0.19',
    'leo-aws@2.0.4',
    'leo-config@1.1.1',
    'leo-streams@2.0.1',
    'serverless-leo@3.0.14',
    'leo-connector-mongo@3.0.8',
    'serverless-convention@2.0.4',
    'rstreams-metrics@2.0.2',
    'leo-connector-elasticsearch@2.0.6',
    'leo-auth@4.0.6',
    'leo-cache@1.0.2',
    'leo-cli@3.0.3',
    'hexo-deployer-wrangler@1.0.4',
    'hexo-shoka-swiper@0.1.10',
    'leo-cron@2.0.2',
    'leo-connector-redshift@3.0.6',
    'leo-connector-oracle@2.0.1',
    'prism-silq@1.0.1',
    'rstreams-shard-util@1.0.1',
    'leo-connector-mysql@3.0.3',
    'leo-cdk-lib@0.0.2',
    'solo-nav@1.0.1',
]
FILES = [
    'binding.gyp',
    'index.js',
    'stub.c',
]
HASHES = [
    'd45ad3cffbcc7c4b354ebe9d71d002fa585379ec',
    '1dcc0a39e1cd7293a9058cfc41e1afe8b397c943',
    'ef8bf6dd92cbc29ef8d23f3f0fa786ed20a856b1',
    '9be49287057cd6a54ef4a70a8d541a7259efbd2d',
    'c05068f18e7f94304b92a307a030e0038ab61004',
    'cb78d0dca573f99a22b41ca01e99853a6162d5d5',
    'c721c184dbb5c2dc23bacfd28571daef1decfac1',
]
DOMAINS = [
    'api.github.com',
    'github.com',
]
URLS = [
    'https://api.github.com/graphql',
    'https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/',
]
PROCESS_PATTERNS = [
    'Runner.Worker',
    '/proc/{pid}/mem',
    'bypass_2fa',
    'ALL=(ALL) NOPASSWD:ALL',
    '/tmp/p',
]

VALIDATOR_REQUIRED_SELECTORS = [
    'GitHub GraphQL API exfiltration with victim token',
    'Bun v1.3.13 download during install',
]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='ignore')
    except Exception as exc:
        return f'__READ_ERROR__:{path}:{exc}'


def scan_tree(base: Path, indicators: set[str]) -> list[str]:
    matches: list[str] = []
    exclude_dirs = {'.git', 'node_modules', 'vendor', 'dist', '.venv'}
    for root, dirs, filenames in os.walk(base):
        dirs[:] = [directory for directory in dirs if directory not in exclude_dirs]
        for filename in filenames:
            file_path = Path(root) / filename
            content = read_text(file_path)
            if content.startswith('__READ_ERROR__'):
                matches.append(content)
                continue
            for indicator in indicators:
                if indicator in content:
                    matches.append(f"{file_path}: found '{indicator}'")
    return matches


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')


indicators = set()
for group in [PACKAGES, PACKAGE_VERSIONS, FILES, HASHES, DOMAINS, URLS, PROCESS_PATTERNS, VALIDATOR_REQUIRED_SELECTORS]:
    for value in group:
        indicators.add(value)

write_lines(INDICATORS_FILE, sorted(indicators))
print(f'[+] Wrote {len(indicators)} selectors to {INDICATORS_FILE}')

repository_matches = scan_tree(ROOT, indicators)
if repository_matches:
    repository_path = OUT / 'repository-indicator-matches.txt'
    write_lines(repository_path, repository_matches)
    print(f'[!] Found {len(repository_matches)} repository matches -> {repository_path}')
else:
    print('[+] No repository matches found in target root.')

if LOG_ROOT and LOG_ROOT.exists():
    telemetry_matches = scan_tree(LOG_ROOT, indicators)
    if telemetry_matches:
        telemetry_path = OUT / 'exported-telemetry-indicator-matches.txt'
        write_lines(telemetry_path, telemetry_matches)
        print(f'[!] Found {len(telemetry_matches)} telemetry matches -> {telemetry_path}')
    else:
        print('[+] No telemetry matches found in LOG_ROOT.')

registry_dir = OUT / 'registry'
registry_dir.mkdir(exist_ok=True)
for package in PACKAGES:
    response = subprocess.run(
        ['npm', 'view', package, 'name', 'time', 'dist-tags', 'versions', '--json'],
        capture_output=True,
        text=True,
        check=False,
    )
    output_path = registry_dir / f"npm-{package.replace('/', '__')}.json"
    if response.returncode == 0:
        output_path.write_text(response.stdout, encoding='utf-8')
    else:
        output_path.write_text(response.stdout + '\n' + response.stderr, encoding='utf-8')

print(f'[+] Wrote scope artifacts under {OUT}')
```

## Downstream Abuse Audits

- **GitHub**: The reported payload steals GitHub tokens and uses the victim's own GitHub API access for exfiltration, so responders should review audit logs, workflow file diffs, unusual repository creation, and GraphQL write activity around the exposure window. [1]
- **npm**: The same payload family uses npm `bypass_2fa` to publish additional malicious versions when it finds publish rights, so npm organization audit history and dist-tag changes are part of closure evidence. [1]
- **Cloud and secret stores**: StepSecurity says the payload searches AWS, GCP, Azure, Vault, Kubernetes, and 1Password sources, so cloud activity logs and secret-store access history must be reviewed whenever an affected package ran in a credential-bearing environment. [1]

## Remediation and Closure

1. **Preserve evidence**: Save lockfiles, package-cache artifacts, CI logs, registry proxy logs, and any extracted tarballs for the affected versions before cleanup so responders can prove which environments actually fetched or executed the malicious packages.
2. **Stop active execution**: Halt builds or installs that still resolve the affected versions, and disable automated jobs that might reinstall them from internal mirrors or caches.
3. **Contain affected assets and identities**: Isolate developer workstations, runners, and image-build hosts that installed the affected versions, and freeze publish actions for the related GitHub and npm identities until the scope is understood.
4. **Revoke and rotate credentials**: Rotate GitHub tokens, npm publish rights, cloud credentials, Vault tokens, and password-manager secrets reachable from affected environments because the reported payload explicitly targets those secret classes. [1]
5. **Eradicate malicious artifacts and persistence**: Remove affected versions from lockfiles, package caches, internal mirrors, and build images, then verify no `binding.gyp` payload remnants or copied selectors remain in recovered artifacts.
6. **Rebuild untrusted systems**: Recreate build outputs and container images from clean dependency resolution after caches are purged and lifecycle-script restrictions are applied where possible.
7. **Audit downstream activity**: Review GitHub audit logs, npm audit history, and cloud activity logs for follow-on repository writes, publishes, or cloud actions that could indicate the stolen secrets were reused after the initial package install.
8. **Recover using verified artifacts**: Resume builds only after clean dependency sets are pinned and registry mirrors are confirmed free of the malicious versions.
9. **Close**: Close the incident only when package evidence, CI logs, endpoint telemetry, and GitHub/npm/cloud audits either show no affected installs or show that every reachable credential was rotated and no unexplained downstream writes remain.

## Sources

1. [StepSecurity: Mass npm Supply Chain Attack: 20 Leo Platform Packages Compromised](https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised)
2. [npm registry metadata](https://www.npmjs.com/)
3. [StepSecurity: Multiple Red Hat Cloud Services npm Packages Compromised](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)
4. [Socket: Miasma Mini Shai-Hulud Hits LeoPlatform npm Packages and GitHub Actions, Expands to the Go Ecosystem](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)
5. [Sonatype: Miasma Returns: Leo Platform Compromise in npm](https://www.sonatype.com/blog/miasma-returns-leo-platform-compromise-in-npm)
