---
title: "Chromium Background Fetch Zero-Day: Persistent Service Worker Exposure"
date: 2026-05-26
severity: "high"
tags:
  - google-chrome
  - chromium
  - zero-day
  - security-bypass
  - cross-site-scripting
summary: "A public Chromium Background Fetch proof of concept showed that a service worker could repeatedly start background fetches after a malicious page visit. Chromium restricted BackgroundFetchManager.fetch() from service-worker contexts on May 21, 2026; downstream deployment remained browser- and channel-specific through June 10."
sourceCount: 5
---

## Executive Summary

In May 2026, a previously restricted Chromium issue and proof of concept became public. The demonstrated behavior allowed a service worker to call `BackgroundFetchManager.fetch()` and repeatedly delegate network work to the browser after the initiating page was gone [[arstechnica.com](https://arstechnica.com/security/2026/05/google-publishes-exploit-code-threatening-millions-of-chromium-users/)].

This is **not a demonstrated Same-Origin Policy bypass, CORS response leak, cookie theft primitive, or system-level code-execution flaw**. The supported risk is persistent browser-mediated activity from an attacker-controlled origin, including tracking browser availability, consuming network resources, and proxy- or denial-of-service-like abuse [[arstechnica.com](https://arstechnica.com/security/2026/05/google-publishes-exploit-code-threatening-millions-of-chromium-users/)].

Chromium landed commit `2976e22e8416cf3a341294855047bb6280ced6b2` on **May 21, 2026**. The change makes `BackgroundFetchManager.fetch()` throw `NotAllowedError` when called from a service-worker global scope by default, with a server-configurable origin allowlist to reduce compatibility risk [[chromium.googlesource.com](https://chromium.googlesource.com/chromium/src/+/2976e22e8416cf3a341294855047bb6280ced6b2)]. Brave immediately backported the change to its release and beta branches [[github.com](https://github.com/brave/brave-core/pull/36655)].

As of **June 10, 2026**, Chrome 149 was the stable desktop channel and Chrome 150 was beta [Sources 4 and 5]. The Chromium fix landed at main-branch position `#1634751`, associated with the Chrome 150 development line. Do not infer protection from a Chromium-family product name alone; verify the browser's exact build or vendor advisory.

## Key Facts

**Issue**: Chromium bug 40062121

**Cve**: not_assigned_as_of_2026-06-10

**Component**: Background Fetch API from Service Worker context

**Public Disclosure**: 2026-05-20

**Upstream Fix Commit**: 2976e22e8416cf3a341294855047bb6280ced6b2

**Upstream Fix Landed**: 2026-05-21

**Chromium Commit Position**: refs/heads/main@{#1634751}

**Fixed Behavior**: BackgroundFetchManager.fetch() throws NotAllowedError in a service-worker global scope by default

**Chrome Channel State 2026 06 10**:
  - **stable**: Chrome 149
  - **beta**: Chrome 150

**Exploitation Status**: public proof of concept; no confirmed in-the-wild exploitation in reviewed sources

**Not Demonstrated**:
- Same-Origin Policy bypass
- CORS response-body disclosure
- credential or cookie theft
- native code execution

## Evidence Assessment

- **confirmed:** Public reporting documented accidental exposure of the restricted Chromium issue and proof-of-concept material on May 20, 2026 [[arstechnica.com](https://arstechnica.com/security/2026/05/google-publishes-exploit-code-threatening-millions-of-chromium-users/)].
- **confirmed:** Chromium commit `2976e22e...` restricts Background Fetch calls from service-worker contexts and defaults to `NotAllowedError` [[chromium.googlesource.com](https://chromium.googlesource.com/chromium/src/+/2976e22e8416cf3a341294855047bb6280ced6b2)].
- **confirmed:** Brave merged the upstream change into its `1.90.x` release and `1.91.x` beta branches and verified the behavior in a Chromium 149 nightly build [[github.com](https://github.com/brave/brave-core/pull/36655)].
- **confirmed:** Chrome 149 reached stable on June 2, while Chrome 150 beta was current on June 10 [Sources 4 and 5].
- **unclear:** Google had not assigned a public CVE or published a Chrome security bulletin explicitly mapping a stable build to bug `40062121` by June 10.
- **not_observed:** Reviewed sources do not confirm exploitation in the wild or cross-origin response disclosure.

## Impact Determination

| Classification | Criteria | Required evidence | Handling decision |
| --- | --- | --- | --- |
| Confirmed abuse | A suspicious origin has a service-worker registration plus Background Fetch activity or recurring browser-originated traffic after the visible page closed. | Browser profile, service-worker storage, DevTools Background Services capture, DNS/proxy flow, and browsing history. | Preserve the profile, clear the origin's site data and service worker, block the origin, and update to a vendor-confirmed fixed build. |
| Presumed exposed | A user visited an untrusted origin with an affected build, and profile or network telemetry needed to establish service-worker activity is unavailable. | Browser version/channel, visit history, profile retention, and proxy/DNS coverage. | Update the browser and inspect or reset the affected profile for high-value endpoints. |
| Potentially exposed | Chromium-family browsers are present but exact build and profile inventory are unknown. | Endpoint software inventory and browser profile enumeration. | Resolve versions and identify profiles with service-worker storage. |
| Not exposed | The browser vendor confirms the restriction is present, or the endpoint used a different browser engine and no affected Chromium build. | Exact executable version plus vendor/build mapping. | Preserve version evidence; no incident response is required without suspicious activity. |
| Unknown | Build, browsing, profile, and network telemetry are unavailable. | Named telemetry gap and owner. | Update the browser and apply conservative profile cleanup for privileged endpoints. |

## Timeline

- **Late 2022:** The issue was reported privately to Chromium, according to the later public reporting [[arstechnica.com](https://arstechnica.com/security/2026/05/google-publishes-exploit-code-threatening-millions-of-chromium-users/)].
- **2026-05-20:** Chromium issue details and proof-of-concept code became public and were subsequently restricted again [[arstechnica.com](https://arstechnica.com/security/2026/05/google-publishes-exploit-code-threatening-millions-of-chromium-users/)].
- **2026-05-21:** Chromium landed the service-worker Background Fetch restriction in commit `2976e22e...` [[chromium.googlesource.com](https://chromium.googlesource.com/chromium/src/+/2976e22e8416cf3a341294855047bb6280ced6b2)].
- **2026-05-22:** Brave merged its backport and prepared release/beta uplifts [[github.com](https://github.com/brave/brave-core/pull/36655)].
- **2026-06-02:** Chrome 149 entered the stable desktop channel [[chromereleases.googleblog.com](https://chromereleases.googleblog.com/2026/06/stable-channel-update-for-desktop.html)].
- **2026-06-10:** Chrome 150 beta `150.0.7871.13` was current; no public CVE mapping was found [[chromereleases.googleblog.com](https://chromereleases.googleblog.com/)].

## Technical Analysis

Background Fetch is intended to let the browser complete large downloads without keeping a page or service worker running continuously. The exposed proof of concept used a service worker to initiate additional Background Fetch operations, creating a loop in which browser-managed work could outlive the original page. [1]

The upstream fix checks the execution context of `BackgroundFetchManager.fetch()`. Calls from a service-worker global scope are denied by default. Chromium also added a feature-controlled origin allowlist, unit tests, web-platform tests, and browser tests [[chromium.googlesource.com](https://chromium.googlesource.com/chromium/src/+/2976e22e8416cf3a341294855047bb6280ced6b2)].

The security boundary matters: an attacker still operates under its own origin. The issue extends persistence and resource use; it does not, by itself, grant access to another origin's response bodies, authenticated cookies, local files, or native operating-system privileges. [1]

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 2976e22e8416cf3a341294855047bb6280ced6b2


## Detection and Hunting

### Hunt Manifest: chromium-browser-fetch-leak-zero-day-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Chromium Background Fetch Zero-Day: Persistent Service Worker Exposure?
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
OUT = Path(os.environ.get("OUT", "hp-chromium-browser-fetch-leak-zero-day-scope"))

HASHES = ["2976e22e8416cf3a341294855047bb6280ced6b2"]

# Collect unique indicators
indicators = set()
for group in [HASHES]:
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

1. Deploy a browser build whose vendor confirms it contains the service-worker Background Fetch restriction.
2. Do not assume every Chromium 149 build is fixed solely because the upstream commit exists; verify downstream backport status.
3. For suspicious profiles, preserve evidence and then remove the origin's service worker and site data.
4. Block confirmed abusive origins at browser, DNS, proxy, and secure web gateway layers.
5. For privileged browsing, use a clean, updated profile and minimize untrusted browsing in the same profile.

Closure requires exact browser-version evidence, removal or disposition of suspicious service-worker registrations, and no continued traffic to the origin after cleanup.

## Sources

1. [Ars Technica: Google publishes exploit code threatening millions of Chromium users](https://arstechnica.com/security/2026/05/google-publishes-exploit-code-threatening-millions-of-chromium-users/) - **Role:** ORIGINAL_REPORTING - **Impact:** Public-disclosure sequence, proof-of-concept context, and demonstrated abuse framing.
2. [Chromium commit 2976e22e: Restrict background fetch from Service Worker context](https://chromium.googlesource.com/chromium/src/+/2976e22e8416cf3a341294855047bb6280ced6b2) - **Role:** DIRECT_SOURCE - **Impact:** Exact fix behavior, feature control, tests, bug ID, commit date, and commit position.
3. [Brave: Cherry-pick upstream fix for Service Worker background fetch](https://github.com/brave/brave-core/pull/36655) - **Role:** DIRECT_SOURCE - **Impact:** Downstream backport, release/beta uplifts, and validation details.
4. [Chrome Releases: Chrome 149 Stable Channel Update](https://chromereleases.googleblog.com/2026/06/stable-channel-update-for-desktop.html) - **Role:** VENDOR_RELEASE - **Impact:** Stable-channel version state on June 2, 2026.
5. [Chrome Releases](https://chromereleases.googleblog.com/) - **Role:** VENDOR_RELEASE - **Impact:** Chrome 150 beta and Chrome 149 stable channel state through June 10, 2026.
