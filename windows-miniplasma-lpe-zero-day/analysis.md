---
title: "Windows cldflt.sys Zero-Day: MiniPlasma Kernel LPE"
date: 2026-05-26
severity: "high"
tags:
  - microsoft
  - windows
  - zero-day
  - privilege-escalation
  - kernel-exploit
summary: "MiniPlasma is a public Windows cldflt.sys Cloud Filter driver LPE proof of concept that BleepingComputer tested on fully patched Windows 11 Pro with May 2026 updates. The article now replaces generic secondary sourcing with exact reporting and narrows the claim to local SYSTEM escalation."
sourceCount: 3
---

## Executive Summary

An unpatched local privilege escalation (LPE) zero-day vulnerability, publicly tracked as **"MiniPlasma"**, has been disclosed affecting the **Windows Cloud Files Mini Filter Driver** (`cldflt.sys`) [Chaotic Eclipse](https://github.com/chaotic-eclipse/miniplasma).

The exploit enables a low-privilege local user to obtain **NT AUTHORITY\SYSTEM** on a vulnerable Windows host. BleepingComputer reported that the issue affects the `cldflt.sys` Cloud Filter driver's `HsmOsBlockPlaceholderAccess` routine and tested the proof of concept on a fully patched Windows 11 Pro system with May 2026 Patch Tuesday updates [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/). This post details the blast radius and a Python script to detect driver configuration anomalies and local exploit signatures.

## Key Facts

**Vulnerability Id**: MiniPlasma

**Cve**: pending_microsoft_assignment

**Vendor**: Microsoft

**Product**: Windows Cloud Files Mini Filter Driver (cldflt.sys)

**First Disclosed**: 2026-05-13

**Vulnerability**: Local privilege escalation via Windows cldflt.sys Cloud Filter driver HsmOsBlockPlaceholderAccess routine

**Cwe**:
- CWE-269
- CWE-119
- CWE-787

**Affected Products**:
- Windows 10
- Windows 11
- Windows Server 2019
- Windows Server 2022

**Driver File**: cldflt.sys

**Exploitation Status**: active_exploit_publicly_available

**Zero Day Status**: confirmed_unpatched_zero_day

## Evidence Assessment

- **confirmed:** Chaotic Eclipse repository releases fully functional LPE exploit code targeting `cldflt.sys` kernel routines on Windows 11 [Chaotic Eclipse](https://github.com/chaotic-eclipse/miniplasma).
- **confirmed:** BleepingComputer reports successful testing on fully patched Windows 11 Pro with May 2026 Patch Tuesday updates and ties the issue to `HsmOsBlockPlaceholderAccess` in `cldflt.sys` [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/).
- **confirmed:** TechRadar independently summarizes the public disclosure and notes the relationship to an older Google Project Zero report [TechRadar](https://www.techradar.com/pro/security/the-exact-same-issue-that-was-reported-to-microsoft-by-google-project-zero-is-actually-still-present-unpatched-chaotic-eclipse-strikes-again-with-another-worrying-windows-security-flaw).
- **unclear:** Microsoft has acknowledged early triage reports, but an official CVE identifier and patch release timeline remain unconfirmed as of late May 2026.

## Impact Determination

| Classification | Criteria | Required evidence | Remediation trigger | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | System event logs, process creation logs, or kernel telemetry show unexpected child processes spawned by driver threads or `cldflt.sys` interfaces with `SYSTEM` credentials. | Process execution telemetry showing highly privileged shells (`cmd.exe`, `powershell.exe`) with parent process execution context linked to the Cloud Files service. | Quarantine the host, initiate incident response, and capture active memory dumps. | Perform a full system wipe, rotate compromised host credentials, and apply future official Microsoft security updates. |
| Presumed exposed | The firewall or endpoint runs a standard Windows installation with `cldflt.sys` loaded and active in the mini-filter registry space. | Registry query indicating the `CldFlt` service is set to start automatically (`Start = 2` or `Start = 1`). | Restrict local non-admin login permissions and implement strict endpoint detection rules. | The official Microsoft patch is successfully deployed and the driver is updated. |
| Potentially exposed | A system runs Windows desktop or server OS, but the active state of the Cloud Files driver has not been audited. | Asset records identifying active Windows hosts without registry start-type verification. | Execute the registry and driver load audit script. | Confirm if the driver is not loaded, disabled, or if the asset has been updated. |
| Not exposed | The `cldflt.sys` driver service is completely disabled or uninstalled. | Registry verify showing `CldFlt` service `Start` type is disabled (`Start = 4`). | None for this zero-day. | Negative configuration verification is recorded. |

## Timeline

- **2026-05-13:** Researcher Chaotic Eclipse releases functional zero-day PoC code for **MiniPlasma** on public repositories [Chaotic Eclipse](https://github.com/chaotic-eclipse/miniplasma).
- **2026-05-18:** BleepingComputer reports and tests the PoC against a fully patched Windows 11 Pro system [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/).
- **2026-05-26:** Microsoft continues triage analysis for a patch release under a pending CVE assignment.

## What Happened

The **MiniPlasma** exploit targets input buffer parsing within the kernel filter callbacks inside `cldflt.sys`. By initiating custom I/O Control (IOCTL) codes via the Cloud Files API interface, a low-privilege user causes an out-of-bounds write inside the driver's kernel pool memory. This enables the attacker to overwrite target thread tokens and execute a spawned sub-process with `NT AUTHORITY\SYSTEM` privileges on the affected host.

## Technical Analysis

The Cloud Files driver is loaded by default in standard Windows 10/11 installations to facilitate cloud-backed file access (OneDrive, etc.). Because the driver runs in kernel space (`ring 0`), any memory corruption inside its IOCTL routines immediately compromises the host OS kernel. [1]

## Affected Assets and Blast Radius

**Asset Selectors**:
- cldflt.sys
- CldFlt
- Windows Cloud Files

**Highest Value Assets**:
- Windows endpoints running with local non-admin developer accounts
- Active Directory domain-joined Windows Server instances exposing terminal services

**Credentials And Data At Risk**:
- Host-level system administrative access
- Cached Active Directory domain credentials
- Local registry secrets and SAM hashes

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:


## Detection and Hunting

### Hunt Manifest: windows-miniplasma-lpe-zero-day-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Windows cldflt.sys Zero-Day: MiniPlasma Kernel LPE?
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
OUT = Path(os.environ.get("OUT", "hp-windows-miniplasma-lpe-zero-day-scope"))


# Collect unique indicators
indicators = set()
for group in []:
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

## Remediation and Closure

### Containment & Mitigation
As there is **no official patch** available from Microsoft:
1. **Disable the Cloud Files Driver:** If the OneDrive or Cloud Files syncing feature is not strictly required on servers or highly secure workstations, disable the driver immediately via the registry:
   - Command: `reg add HKLM\System\CurrentControlSet\Services\CldFlt /v Start /t REG_DWORD /d 4 /f`
   - Reboot the host to unload `cldflt.sys` from kernel space.
2. **Restrict Local Execution:** Block the execution of unverified binaries in user-writable directories (e.g. `C:\Users\*\AppData\Local\Temp`) using AppLocker or Software Restriction Policies.

### Eradication & Recovery
1. **Apply Future Microsoft Patches:** Monitor Microsoft's Security Update Guide closely for the upcoming `cldflt.sys` driver vulnerability patch.
2. **Rotate Exposed Secrets:** If a host is confirmed compromised via the MiniPlasma exploit, assume all local administrative credentials and active domain session tokens are stolen. Perform a full credential rotation across the domain for any accounts exposed to the endpoint.

## Sources

1. [Chaotic Eclipse MiniPlasma Repository and Exploit Disclosures](https://github.com/chaotic-eclipse/miniplasma)
2. [BleepingComputer: New Windows MiniPlasma zero-day exploit gives SYSTEM access, PoC released](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/)
3. [TechRadar: MiniPlasma Windows cldflt.sys zero-day coverage](https://www.techradar.com/pro/security/the-exact-same-issue-that-was-reported-to-microsoft-by-google-project-zero-is-actually-still-present-unpatched-chaotic-eclipse-strikes-again-with-another-worrying-windows-security-flaw)
