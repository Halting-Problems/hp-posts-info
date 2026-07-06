---
title: "15 Malicious JetBrains Plugins Stole AI API Keys from 70,000 Developers"
date: 2026-06-19
severity: "critical"
tags:
  - jetbrains-marketplace
  - ide-plugins
  - supply-chain
  - credential-theft
  - developer-workstations
  - ai
summary: "StepSecurity and JetBrains say 15 malicious JetBrains Marketplace plugins stole AI provider API keys from developers, then a remote kill-switch and marketplace purge removed the listings and banned the publisher accounts."
sourceCount: 3
---

## Executive Summary

On 2026-06-16, JetBrains received reports that 15 third-party JetBrains Marketplace plugins were stealing developer-entered AI provider API keys. JetBrains says it purged the plugins from Marketplace, permanently banned the seven publisher accounts tied to the campaign, and marked the affected plugins as broken so they disable themselves inside installed IDEs on the next relaunch [2].

StepSecurity's independent investigation adds the campaign shape that JetBrains did not publish: the malicious listings were active from late October 2025 through June 2026, used seven vendor accounts, accumulated roughly 70,000 total installations, and exfiltrated OpenAI, DeepSeek, and SiliconFlow keys to a hardcoded server at `39.107.60[.]51` in Beijing that remained live on 2026-06-19 [1]. The incident is best treated as a developer-endpoint credential theft event, not a source-repository compromise [1][2].

Representative Marketplace checks for sample plugin IDs such as `org.sm.yms.toolkit`, `com.json.simple.kit`, and `com.dp.git.ai.tool` now return 404, which is consistent with JetBrains's purge statement but only proves removal for the sampled listings we tested [3].

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected Artifact** | 15 malicious JetBrains Marketplace plugin listings masquerading as AI utilities |
| **Ecosystem** | JetBrains Marketplace / JetBrains IDE plugins |
| **Malicious Listings** | `org.sm.yms.toolkit`, `com.json.simple.kit`, `org.bug.find.tools`, `org.translate.ai.simple`, `com.yy.test.ai.simple`, `com.dev.ai.toolkit`, `com.json.view.simple`, `com.my.git.ai.kit`, `org.check.ai.ds`, `com.review.tool.code`, `org.code.assist.dev.tool`, `com.coder.ai.dpt`, `com.my.code.tools`, `ord.cp.code.ai.kit`, `com.dp.git.ai.tool` |
| **Exposure Window** | 2025-10-31 to 2026-06-17 |
| **Execution Trigger** | Developer enters an AI provider API key into plugin settings and clicks **Apply** |
| **Primary Impact** | AI API key theft and unauthorized outbound HTTP exfiltration from developer workstations |
| **Immediate Action** | Remove the plugins, revoke any entered AI keys, and audit IDE/network telemetry for `39.107.60[.]51` |
| **Confidence** | high |

## Evidence Assessment

- **confirmed:** JetBrains states that 15 third-party plugins were reported on 2026-06-16, removed from Marketplace, blocked from future downloads, and disabled through backend kill-switch logic inside installed IDEs [2].
- **confirmed:** StepSecurity identified the campaign's 15 plugin names, seven publisher accounts, approximate 8-month dwell time, and the hardcoded exfiltration server at `39.107.60[.]51` [1].
- **confirmed:** Sample JetBrains Marketplace listing requests for representative plugin IDs now return 404, matching the vendor purge claim for the specific IDs we tested [3].
- **likely:** StepSecurity's ~70,000-installation figure is a campaign-level estimate based on marketplace visibility, not a JetBrains-confirmed count [1].
- **unclear:** Public sources reviewed here do not name the initial account-compromise path, the original source repository, or whether any publisher recovery mechanisms were abused [1][2].
- **not_observed:** JetBrains says its internal source code, development environments, and core corporate infrastructure were not accessed or exposed [2].

## Impact Determination

| Exposure Classification | Criteria | Required Evidence | Required Action | Closure Gate |
| --- | --- | --- | --- | --- |
| **Confirmed Compromise** | A listed plugin is installed and a developer entered an AI provider API key, or telemetry shows the IDE sending traffic to `39.107.60[.]51` / `/api/software/*`. | Plugin inventory, IDE settings artifacts, proxy/firewall logs, or endpoint network telemetry tying the plugin to the C2 server. | Isolate the workstation, preserve plugin and network artifacts, and revoke every entered AI key from a clean device. | No listed plugin remains installed; affected keys are revoked; AI-provider logs show no post-discovery use. |
| **Presumed Exposed** | A listed plugin was installed during the exposure window, but telemetry cannot prove key entry or exfiltration. | Extension inventory, install logs, auto-update records, or package-cache evidence. | Remove the plugin, rebuild the IDE profile if needed, and rotate any AI keys that may have been typed into it. | The endpoint no longer contains the plugin and the key owners confirm revocation. |
| **Potentially Exposed** | JetBrains IDEs are present, but the extension inventory or settings history has not yet been collected. | Host inventory plus missing telemetry statement. | Collect the missing IDE inventory and network logs before narrowing scope. | Every asset is dispositioned as confirmed, presumed, or not exposed. |
| **Not Exposed** | No listed plugin IDs, plugin directories, or outbound hits to the C2 infrastructure appear in complete telemetry. | Negative searches across plugin directories, logs, and network telemetry. | Preserve the negative results and keep Marketplace guardrails enabled. | Search evidence covers the relevant developer endpoints and time window. |
| **Unknown** | The host, IDE inventory, or network telemetry is unavailable. | A gap statement naming the missing systems and time range. | Keep the asset in scope and make conservative key-rotation decisions for high-value developer accounts. | The missing evidence is collected or the residual risk is accepted. |

## Minimum Evidence To Collect

- **What to collect:** JetBrains IDE extension inventory, plugin directories, and recent settings files that can show whether a listed plugin was installed or configured.
  Where it normally comes from: JetBrains profile directories such as `~/.local/share/JetBrains/<product>/plugins/`, `%APPDATA%\\JetBrains\\<product>\\plugins\\`, and IDE settings exports.
  Why it is relevant: It proves whether one of the malicious listings was present on the workstation during the exposure window.
  Which decision it resolves: confirmed compromise vs. presumed exposed vs. not exposed.
- **What to collect:** Firewall, proxy, and EDR logs covering connections from JetBrains IDE processes to `39.107.60[.]51` and `/api/software/*`.
  Where it normally comes from: Endpoint protection telemetry, corporate proxies, and packet capture records from the developer workstation.
  Why it is relevant: StepSecurity and JetBrains both describe plaintext HTTP exfiltration to a hardcoded IP [1][2].
  Which decision it resolves: whether the plugin actually sent an API key off-host.
- **What to collect:** AI provider billing and audit logs for OpenAI, DeepSeek, SiliconFlow, or any other provider whose key was entered into the plugin.
  Where it normally comes from: provider admin consoles and billing dashboards.
  Why it is relevant: It shows whether stolen keys were already used for unauthorized model calls or spend.
  Which decision it resolves: key revocation urgency and downstream abuse scope.

## Timeline

- **2025-10-31:** StepSecurity says the first malicious plugin listing, `DeepSeek Junit Test` (`org.sm.yms.toolkit`), was published [1].
- **2026-06-09 to 2026-06-10:** The two highest-volume late-stage listings, `CodeGPT AI Assistant` and `DeepSeek AI Assist`, were published and collectively drove most of the observed install count [1].
- **2026-06-16:** JetBrains receives security reports about the campaign and begins response actions [2].
- **2026-06-17:** JetBrains says it purges the 15 plugins, bans the seven publisher accounts, and activates the remote disablement path inside installed IDEs [2].
- **2026-06-19:** StepSecurity independently verifies that the attacker-controlled C2 server at `39.107.60[.]51` is still live and serving API requests [1].

## What Happened

The malicious listings impersonated AI-assisted development tools such as code review, unit-test generation, and Git commit-message helpers. They only exposed the theft behavior when a developer entered an AI provider key into the plugin's settings and clicked **Apply**, which triggered a `save()` routine that validated key-like input before sending it to the attacker-controlled server [1][2].

JetBrains's response shows this was treated as a Marketplace abuse incident rather than a platform compromise: the company removed the plugins, blocked the accounts, and relied on a backend mechanism to disable installed copies on relaunch [2]. The downstream security problem is therefore the developer's secret exposure, not a compromise of JetBrains' own source or infrastructure [2].

## Technical Analysis

### Initial Access

The campaign reached developers through the JetBrains Marketplace trust boundary. StepSecurity identified seven publisher accounts that distributed the 15 plugins, while JetBrains confirms those accounts were permanently terminated [1][2]. The public evidence reviewed here does not show an upstream compromise of JetBrains itself or of any listed source repository [1][2].

### Package or Artifact Manipulation

The artifacts were published as ordinary Marketplace plugins with believable names and descriptions. StepSecurity's plugin inventory shows a patient campaign that started in late 2025 and expanded across multiple listings and vendor identities, which is a strong indicator of deliberate Marketplace abuse rather than a one-off typo or accidental upload [1].

### Execution Trigger

The theft path was user-driven. JetBrains says the malicious plugins waited until a developer entered an AI provider key into the settings panel and clicked **Apply**; StepSecurity's code analysis says the plugin validated the key format before sending it onward [1][2]. This means a clean install alone is not enough to prove exfiltration, but any host that both installed the plugin and stored a key in it should be treated as credential-compromised.

### Payload Behavior

StepSecurity reports that the code checked for OpenAI-style `sk-` keys, deduplicated already-seen secrets, and sent the captured key to the C2 server in a JSON payload [1]. JetBrains independently describes the same plaintext-exfiltration pattern and says the plugins also installed a JVM-wide `X509TrustManager` to suppress certificate warnings, which is a defensive-evasion step aimed at reducing local telemetry noise [2].

### Credential or Data Collection

The public evidence supports a narrow collection scope: AI provider API keys entered into the plugin settings, specifically those used with OpenAI, DeepSeek, and SiliconFlow [1][2]. No source reviewed here claims the plugin harvested GitHub tokens, cloud credentials, or filesystem secrets directly; those should remain `not_observed` unless local telemetry proves broader collection [1][2].

### Defense Evasion

The plugins hid inside a functional AI-workflow façade. They behaved like legitimate AI helpers, suppressed TLS warnings, and used a hardcoded HTTP endpoint rather than a visibly malformed malware dropper, which makes the traffic easy to miss if defenders only watch for TLS anomalies or obvious file drops [1][2].

### Exfiltration and Command and Control

**Network IOCs in prose are defanged:** `39.107.60[.]51`, `hxxp://39.107.60[.]51/api/software/key`, and `hxxp://39.107.60[.]51/api/software/check` [1]. StepSecurity says the server was hosted on Alibaba Cloud in Beijing and remained operational on 2026-06-19, while JetBrains confirms the exfiltration used plaintext HTTP [1][2].

## Affected Assets and Blast Radius

The blast radius is concentrated on developer endpoints and identity material, not on the JetBrains build infrastructure itself [2].

| Asset / Identity | Exposure Notes |
| --- | --- |
| JetBrains IDE users | Anyone who installed one of the 15 plugins and entered an AI provider key is in scope [1][2]. |
| AI API keys | OpenAI, DeepSeek, and SiliconFlow keys are the primary confirmed exposure class [1][2]. |
| Developer workstations | The theft path executes in the user's IDE session and can be repeated across every affected workstation [1][2]. |
| Publisher accounts | Seven publisher accounts were banned, but public sources do not show whether those accounts were stolen or simply malicious from the start [1][2]. |
| JetBrains corporate systems | Not currently known to be affected; JetBrains explicitly says its internal systems were not compromised [2]. |

## Indicators of Compromise

The following indicators are confirmed in the reviewed sources and are suitable for scoping endpoint, proxy, and billing telemetry [1][2].

### Plugin IDs

- `org.sm.yms.toolkit`
- `com.json.simple.kit`
- `org.bug.find.tools`
- `org.translate.ai.simple`
- `com.yy.test.ai.simple`
- `com.dev.ai.toolkit`
- `com.json.view.simple`
- `com.my.git.ai.kit`
- `org.check.ai.ds`
- `com.review.tool.code`
- `org.code.assist.dev.tool`
- `com.coder.ai.dpt`
- `com.my.code.tools`
- `ord.cp.code.ai.kit`
- `com.dp.git.ai.tool`

### Publisher Handles

- `mycode`
- `misshewei`
- `keteme`
- `simpledev`
- `skyblue`
- `dialycode`
- `947cb4c8-5db1-4cf0-8182-0aae7c433bb3`

### Network IOCs

- `39.107.60[.]51`
- `hxxp://39.107.60[.]51/api/software/key`
- `hxxp://39.107.60[.]51/api/software/check`
- `X-Api-Key: F48D2AA7CF341F782C1D`

## Detection and Hunting

### Hunt Manifest: jetbrains-malicious-plugins-ai-api-key-theft-hunt-1
- **Title:** JetBrains plugin and telemetry scope
- **Question:** Does the telemetry scope contain indicators associated with the malicious JetBrains Marketplace AI-key theft campaign?
- **Telemetry Family:** file
- **Telemetry Context:** JetBrains IDE plugin inventory, local files, and exported telemetry
- **Positive Signal:** Indicators of compromise matched in telemetry: JetBrains plugin IDs, publisher handles, or C2 network selectors
- **False Positives:** Benign JetBrains plugins may mention AI models in metadata, but they should not contain the campaign's exact plugin IDs, publisher handles, or attacker C2 selectors.
- **Classification on Match:** treat the workstation as credential-compromised and rotate any AI provider keys entered into the matched plugins

```py
#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path
from typing import Iterable

PLUGIN_IDS = [
    "org.sm.yms.toolkit",
    "com.json.simple.kit",
    "org.bug.find.tools",
    "org.translate.ai.simple",
    "com.yy.test.ai.simple",
    "com.dev.ai.toolkit",
    "com.json.view.simple",
    "com.my.git.ai.kit",
    "org.check.ai.ds",
    "com.review.tool.code",
    "org.code.assist.dev.tool",
    "com.coder.ai.dpt",
    "com.my.code.tools",
    "ord.cp.code.ai.kit",
    "com.dp.git.ai.tool",
]

PLUGIN_NAMES = [
    "DeepSeek Junit Test",
    "DeepSeek Git Commit",
    "DeepSeek FindBugs",
    "DeepSeek AI Chat",
    "DeepSeek Dev AI",
    "DeepSeek AI Coding",
    "AI FindBugs",
    "AI Git Commitor",
    "AI Coder Review",
    "DeepSeek Coder AI",
    "AI Coder Assistant",
    "DeepSeek Code Review",
    "CodeGPT AI Assistant",
    "DeepSeek AI Assist",
    "Coding Simple Tool",
]

PUBLISHERS = [
    "mycode",
    "misshewei",
    "keteme",
    "simpledev",
    "skyblue",
    "dialycode",
    "947cb4c8-5db1-4cf0-8182-0aae7c433bb3",
]

REFERENCE_DOMAINS = [
    "stepsecurity.io",
    "blog.jetbrains.com",
    "plugins.jetbrains.com",
]

REFERENCE_URLS = [
    "https://www.stepsecurity.io/blog/jetbrains-malicious-plugins-ai-api-key-theft",
    "https://blog.jetbrains.com/platform/2026/06/marketplace-ecosystem-security-update-malicious-ai-plugins/",
    "https://plugins.jetbrains.com/plugin/org.sm.yms.toolkit",
    "https://plugins.jetbrains.com/plugin/com.json.simple.kit",
    "https://plugins.jetbrains.com/plugin/com.dp.git.ai.tool",
]

NETWORK_IOCS = [
    "39.107.60.51",
    "http://39.107.60.51/api/software/key",
    "http://39.107.60.51/api/software/check",
    "X-Api-Key: F48D2AA7CF341F782C1D",
]

NETWORK_PATTERNS = [
    "POST /api/software/key",
    "POST /api/software/check",
    "JetBrains IDE process sending HTTP POST requests to 39.107.60.51",
]

INDICATORS = sorted({*PLUGIN_IDS, *PLUGIN_NAMES, *PUBLISHERS, *REFERENCE_DOMAINS, *REFERENCE_URLS, *NETWORK_IOCS, *NETWORK_PATTERNS})


def write_indicator_file(out_dir: Path, indicators: Iterable[str]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    indicator_file = out_dir / "ioc-indicators.txt"
    with indicator_file.open("w", encoding="utf-8") as handle:
        for item in sorted(set(indicators)):
            handle.write(item + "\n")
    return indicator_file


def scan_tree(root: Path, indicators: Iterable[str]) -> list[str]:
    matches: list[str] = []
    exclude_dirs = {".git", "node_modules", "dist", "vendor", "__pycache__"}
    indicator_list = list(indicators)

    if not root.exists():
        return matches

    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for filename in filenames:
            path = Path(current_root) / filename
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for indicator in indicator_list:
                if indicator in content:
                    matches.append(f"{path}: found '{indicator}'")
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Scope JetBrains malicious plugin indicators in a local tree or telemetry export.")
    parser.add_argument("root", nargs="?", default=".", help="directory tree to scan")
    parser.add_argument("--telemetry-root", default=os.environ.get("LOG_ROOT", ""), help="optional telemetry/export directory to scan")
    parser.add_argument("--out", default=os.environ.get("OUT", "hp-jetbrains-malicious-plugins-ai-api-key-theft-scope"), help="output directory")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    telemetry_root = Path(args.telemetry_root).resolve() if args.telemetry_root else None
    out_dir = Path(args.out).resolve()

    indicator_file = write_indicator_file(out_dir, INDICATORS)
    repo_matches = scan_tree(root, INDICATORS)
    repo_match_file = out_dir / "repository-indicator-matches.txt"
    if repo_matches:
        repo_match_file.write_text("\n".join(repo_matches) + "\n", encoding="utf-8")

    telemetry_matches: list[str] = []
    if telemetry_root and telemetry_root.exists():
        telemetry_matches = scan_tree(telemetry_root, INDICATORS)
        telemetry_match_file = out_dir / "exported-telemetry-indicator-matches.txt"
        if telemetry_matches:
            telemetry_match_file.write_text("\n".join(telemetry_matches) + "\n", encoding="utf-8")

    summary = {
        "root": str(root),
        "telemetry_root": str(telemetry_root) if telemetry_root else None,
        "out_dir": str(out_dir),
        "indicator_file": str(indicator_file),
        "repository_match_count": len(repo_matches),
        "telemetry_match_count": len(telemetry_matches),
    }
    (out_dir / "scan-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"[+] Wrote indicator file: {indicator_file}")
    print(f"[+] Repository matches: {len(repo_matches)}")
    if telemetry_root and telemetry_root.exists():
        print(f"[+] Telemetry matches: {len(telemetry_matches)}")
    print(f"[+] Summary written to: {out_dir / 'scan-summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Downstream Abuse Audits

This incident is an AI-provider credential theft case, so the first downstream audit is the provider console, not GitHub or CI/CD. Inspect OpenAI, DeepSeek, SiliconFlow, and any other AI platform whose key was entered into one of the 15 plugins for unexpected usage spikes, unfamiliar source IPs, or billable runs after the plugin interaction [1][2].

Only expand into GitHub, cloud, or CI/CD audits if the affected developer workstation also shows evidence of broader secret exposure. That applicability decision matters here because the public evidence supports API-key theft from the IDE, not code-repository tampering or a build-system implant [1][2].

## Remediation and Closure

1. **Preserve evidence:** capture JetBrains plugin directories, IDE settings, browser/session artifacts, proxy logs, and provider billing history before removing anything. Those artifacts prove whether a key was actually typed into the plugin.
2. **Stop active execution:** remove the listed plugins from every JetBrains IDE and rely on JetBrains's backend disablement only as a backstop, not as your sole control [2].
3. **Contain affected assets and identities:** block `39.107.60[.]51` at network controls and isolate any workstation that shows an outbound hit to the C2 server [1][2].
4. **Revoke and rotate credentials:** reissue every AI provider key entered into the listed plugins. The plugin was designed to steal exactly that class of credential, so revocation is mandatory even if you have not yet seen billable misuse [1][2].
5. **Eradicate malicious artifacts and persistence:** clear plugin caches, uninstall any residual plugin copies, and remove any copied settings or auto-install artifacts that could reintroduce the listings after relaunch [2].
6. **Rebuild untrusted systems:** if the workstation also contains other sensitive secrets, rebuild the IDE profile or the entire endpoint rather than trying to surgically cleanse it.
7. **Audit downstream activity:** review AI-provider logs for unfamiliar IPs, unusual token spend, or requests that occurred after the key was entered into the plugin [1][2].
8. **Recover using verified artifacts:** restore the developer environment only after clean plugin inventories and clean provider logs are confirmed.
9. **Close:** close the case only when the targeted plugins are absent, every entered AI key is revoked, and network telemetry shows no further interaction with `39.107.60[.]51`.

## Sources

1. [StepSecurity — "15 Malicious JetBrains Plugins Stole AI API Keys from 70,000 Developers"](https://www.stepsecurity.io/blog/jetbrains-malicious-plugins-ai-api-key-theft): primary research on the 15 plugin names, seven vendor accounts, 8-month campaign window, API-key exfiltration code, and live C2 server.
2. [JetBrains Blog — "JetBrains Marketplace Ecosystem Security Update: Addressing Malicious Third-Party AI Plugins"](https://blog.jetbrains.com/platform/2026/06/marketplace-ecosystem-security-update-malicious-ai-plugins/): vendor response confirming the 15-plugin purge, seven publisher bans, remote disablement path, and plaintext HTTP exfiltration.
3. [JetBrains Marketplace representative listing checks](https://plugins.jetbrains.com/plugin/org.sm.yms.toolkit): direct fetches for sample plugin IDs `org.sm.yms.toolkit`, `com.json.simple.kit`, and `com.dp.git.ai.tool` returned 404 after the purge, confirming removal for the sampled listings.
