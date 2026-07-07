---
layout: ../../layouts/ThreatPostLayout.astro
title: "OptinMonster Supply Chain Attack"
date: 2026-06-12
slug: optinmonster-supply-chain-attack
description: "WordPress plugins OptinMonster, TrustPulse, and PushEngage had CDN-hosted SDK files tampered to inject malicious JavaScript. The malware creates rogue admin accounts and installs hidden PHP backdoors."
ecosystem: wordpress
severity: high
tags:
  - supply-chain
  - wordpress
  - backdoor
  - malware
summary: "Awesome Motive's CDN-hosted SDK files for WordPress plugins OptinMonster, TrustPulse, and PushEngage were tampered to inject malicious JavaScript. When an administrator logs in, the payload runs in their context, creates rogue administrator accounts, and silently installs a self-hiding PHP backdoor plugin, exfiltrating credentials to tidio[.]cc."
sourceCount: 1
---

## Executive Summary

WordPress plugins OptinMonster, TrustPulse, and PushEngage, all operated by WordPress plugin developer Awesome Motive, were affected by a supply chain attack where CDN-hosted JavaScript SDK files were tampered to inject malicious code. The campaign, active as of June 12, 2026, targeted sites running these plugins by delivering compromised files directly from the vendor's CDN endpoints [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

The injected JavaScript executes specifically when a logged-in WordPress administrator visits the site. It attempts to create a rogue administrator account (`developer_api1`) and install a self-hiding PHP backdoor plugin disguised as normal utility plugins. Stolen administrative credentials and system details are exfiltrated to the lookalike command and control (C2) domain `tidio[.]cc` [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

Awesome Motive has updated the affected CDN assets, cleaning the scripts for OptinMonster and TrustPulse, and subsequently the PushEngage SDK. WordPress site owners must inspect their local databases and filesystems to detect and eradicate any rogue accounts or backdoor code planted during the exposure window.

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected Assets** | optinmonster, trustpulse, pushengage |
| **Ecosystem** | wordpress |
| **Malicious Scripts** | a.omappapi.com/app/js/api.min.js, a.opmnstr.com/app/js/api.min.js, a.optnmstr.com/app/js/api.min.js, a.trstplse.com/app/js/api.min.js, clientcdn.pushengage.com/sdks/pushengage-web-sdk.js |
| **Exposure Window** | 2026-06-12 22:17:00 UTC to 2026-06-14 |
| **Immediate Action** | Inspect users table for rogue accounts, search plugins directory for hidden backdoors, rotate passwords and salts |

## Evidence Assessment

- **confirmed:** Sansec observed malicious JavaScript payloads served directly from Awesome Motive's CDN domains, including `a.omappapi.com` and `clientcdn.pushengage.com` [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **confirmed:** The malicious payload detects WordPress admin sessions via Cookies, paths, and admin bars, gating execution to logged-in administrators only [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **confirmed:** The malware creates an admin account with username `developer_api1` and email `customer1usx@gmail.com` using multiple API fallbacks [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **confirmed:** A backdoor ZIP plugin is downloaded and installed, which actively hides itself from administrative plugin menus and registers unauthenticated endpoints (`developer_api1_fm` and `developer_api1_eval`) [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **confirmed:** Encrypted C2 communication was routed to the C2 server at `tidio[.]cc` [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **unknown:** The precise point of origin for the CDN compromise (Awesome Motive servers, CDN credentials, or upstream provider) remains unconfirmed [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

## Impact Determination

| Exposure Classification | Criteria | Required Evidence | Required Action | Closure Gate |
| --- | --- | --- | --- | --- |
| **Confirmed Compromise** | Rogue administrator `developer_api1` or matching `dev_xxxxxx` account exists in the database, or backdoor plugin files are present on disk. | User record containing username or email pattern, or files under `content-delivery-helper` / `database-optimizer`. | Revoke rogue accounts, delete backdoor directories, rotate all admin passwords/keys, and check web logs for shell execution. | Clean filesystem scan, verification of no unauthorized admin users, and validated database integrity. |
| **Presumed Exposed** | WordPress site utilized OptinMonster, TrustPulse, or PushEngage with administrative logins active during the exposure window, but files/users have been cleaned. | HTTP access logs showing CDN script loads during administrative sessions. | Re-audit database history, rotate administrative keys, and inspect PHP process logs for unexpected commands. | No matching access patterns and negative file scan. |
| **Potentially Exposed** | The affected plugins are installed, but no administrative logins occurred during the specific compromise period. | Verification of plugin installation and lack of admin sessions. | Keep plugins updated and run a scan to confirm zero footprint. | Verified clean scan. |

## Minimum Evidence To Collect

- **WordPress Database Users Table**: Query the users table or review SQL database dumps because it resolves the presence of the fixed operator user `developer_api1` or randomised `dev_xxxxxx` usernames.
- **Plugins Directory Contents**: Audit `/wp-content/plugins/` on the server disk because it identifies backdoor plugins such as `content-delivery-helper` or `database-optimizer` that are hidden from the WordPress dashboard interface.
- **HTTP Server Logs**: Scan web server access logs for queries containing `developer_api1_fm` or `developer_api1_eval` because it determines if the threat actor successfully invoked the backdoor web shell or evaluated code.
- **Local Browser Storage**: Inspect administrative browser profiles for the key `_pe_ts` in `localStorage` because it confirms the execution of the SDK script in the administrator's browser.

## Timeline

- **2026-04-28**: Domain `tidio[.]cc` is registered and TLS certificate is issued [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **2026-06-12 22:17 UTC**: First injection detected in OptinMonster and TrustPulse SDKs served via vendor CDN edges [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **2026-06-12 22:42 UTC**: Injected code is cleaned from OptinMonster and TrustPulse CDN paths [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **2026-06-13 19:02 UTC**: PushEngage SDK is observed still serving the malicious code from certain CDN edges [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].
- **2026-06-14**: PushEngage CDN SDK files are cleaned and no longer serve the malicious script [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

## What Happened

The supply chain compromise impacted the CDN infrastructure hosting JavaScript SDK files for OptinMonster, TrustPulse, and PushEngage plugins. When a logged-in administrator accessed their WordPress dashboard, their browser pulled the compromised SDK from the vendor CDN. The embedded malware executed in the admin's session, created a new administrative user, and downloaded a custom ZIP containing a PHP backdoor. The backdoor plugin registered unauthenticated shell commands and base64 eval handlers, while hiding its footprint from WordPress administrative menus [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

## Technical Analysis

### Initial Access
The malicious payload was introduced by modifying legitimate SDK files hosted on Awesome Motive-operated CDN endpoints (using BunnyNet CDN) [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

### Execution Trigger
The malware executes client-side within the browser of a WordPress administrator. It uses several checks to exit early if run inside headless/automated environments, or if no WordPress admin indicator (such as cookies starting with `wordpress_logged_in_`, `/wp-admin/` paths, or the WordPress admin bar) is present [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

### Payload Behavior
Once the administrator session is validated, the payload harvests security nonces from the page source and WordPress REST configuration. It then proceeds to create a new administrator account using a cascade of four fallback methods:
1. Simulating a form submit to `user-new.php`
2. Sending an AJAX request to `admin-ajax.php`
3. Executing a REST request to `/wp/v2/users`
4. Posting to a dynamically created hidden iframe [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)]

### Credential or Data Collection
The script collects the newly created username and password, WordPress version, admin URL path, execution timestamps, and site domain. This data is XOR-encrypted (using key `jX9kM2nP4qR6sT8v`), base64-encoded, and prepared for exfiltration [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

### Defense Evasion
The downloaded PHP backdoor hides itself from the WordPress dashboard plugin lists (both the standard view and the REST `/wp/v2/plugins` endpoint). It also suppresses updates and hides from the list of recently active plugins. The backdoor masquerades under varying names (such as "Content Delivery Helper" or "Database Optimizer") while keeping the underlying backdoor logic identical [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

### Exfiltration and Command and Control
The exfiltration channel delivers the credentials to `tidio[.]cc/cdn-cgi/` via `sendBeacon`, falling back to `fetch` (with `no-cors`), `XMLHttpRequest`, or an `Image` object request [[sansec.io](https://sansec.io/research/optinmonster-supply-chain-attack)].

## Affected Assets and Blast Radius

| Asset Name | Type | Scope | Downstream Impact |
| --- | --- | --- | --- |
| **OptinMonster SDK** | CDN JS Asset | `a.omappapi.com`, `a.opmnstr.com`, `a.optnmstr.com` | Client-side admin session takeover |
| **TrustPulse SDK** | CDN JS Asset | `a.trstplse.com` | Client-side admin session takeover |
| **PushEngage SDK** | CDN JS Asset | `clientcdn.pushengage.com` | Client-side admin session takeover |
| **WordPress Sites** | Deployment | Sites with active admin sessions during window | Remote Code Execution via PHP backdoor |

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- tidio[.]cc
- gmail[.]com

### Urls
- hxxps://a[.]omappapi[.]com/app/js/api[.]min[.]js
- hxxps://a[.]opmnstr[.]com/app/js/api[.]min[.]js
- hxxps://a[.]optnmstr[.]com/app/js/api[.]min[.]js
- hxxps://a[.]trstplse[.]com/app/js/api[.]min[.]js
- hxxps://clientcdn[.]pushengage[.]com/sdks/pushengage-web-sdk[.]js


## Detection and Hunting

### Hunt Manifest: optinmonster-supply-chain-attack-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with OptinMonster Supply Chain Attack?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for optinmonster-supply-chain-attack.

Searches repository trees and exported logs for literal IOC values from iocs.json.
Exit codes:
  0: no matches
  1: one or more indicators matched
  2: execution error
"""
import argparse
import fnmatch
import os
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT", "hp-optinmonster-supply-chain-attack-ioc-scope"))
CONTENT_INDICATORS = [
  "tidio[.]cc",
  "a.omappapi.com",
  "a.opmnstr.com",
  "a.optnmstr.com",
  "a.trstplse.com",
  "clientcdn.pushengage.com",
  "gmail[.]com",
  "https://a.omappapi.com/app/js/api.min.js",
  "https://a.opmnstr.com/app/js/api.min.js",
  "https://a.optnmstr.com/app/js/api.min.js",
  "https://a.trstplse.com/app/js/api.min.js",
  "https://clientcdn.pushengage.com/sdks/pushengage-web-sdk.js",
  "84.201.6.54"
]
PATH_INDICATORS = [
  "wp-content/plugins/content-delivery-helper/content-delivery-helper.php",
  "wp-content/plugins/database-optimizer/database-optimizer.php"
]
EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}

def _iter_files(root):
    root = Path(root)
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            yield Path(current) / name

def _path_matches(path):
    text = str(path)
    matches = []
    for indicator in PATH_INDICATORS:
        if not indicator:
            continue
        if indicator.startswith(("/", "~")):
            candidate = Path(os.path.expanduser(indicator))
            if candidate.exists() and path == candidate:
                matches.append(indicator)
        if indicator in text or fnmatch.fnmatch(text, indicator) or fnmatch.fnmatch(path.name, indicator):
            matches.append(indicator)
    return matches

def _content_matches(path):
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []
    return [indicator for indicator in CONTENT_INDICATORS if indicator and indicator in content]

def _scan_roots(roots):
    matches = []
    for root in roots:
        if not root:
            continue
        for path in _iter_files(root):
            for indicator in _path_matches(path):
                matches.append(f"{path}: path matched {indicator!r}")
            for indicator in _content_matches(path):
                matches.append(f"{path}: content matched {indicator!r}")
    return matches

def main():
    parser = argparse.ArgumentParser(description="Scan files and logs for Halting Problems IOC values")
    parser.add_argument("roots", nargs="*", default=["."], help="File or directory roots to scan")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log directory")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    indicator_lines = sorted(set(CONTENT_INDICATORS + PATH_INDICATORS))
    (OUT / "ioc-indicators.txt").write_text("\n".join(indicator_lines) + "\n")

    roots = list(args.roots)
    if args.log_root:
        roots.append(args.log_root)
    matches = _scan_roots(roots)
    if matches:
        (OUT / "ioc-scope-matches.txt").write_text("\n".join(matches) + "\n")
        print(f"[!] Found {len(matches)} IOC matches; details written under {OUT}")
        return 1
    print(f"[+] No IOC matches found; indicator inventory written under {OUT}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[-] Execution failure: {exc}", file=sys.stderr)
        sys.exit(2)
```

### Hunt Manifest: optinmonster-supply-chain-attack-hunt-2
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with OptinMonster Supply Chain Attack?
- **Telemetry Family:** network
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for optinmonster-supply-chain-attack.

Searches repository trees and exported logs for literal IOC values from iocs.json.
Exit codes:
  0: no matches
  1: one or more indicators matched
  2: execution error
"""
import argparse
import fnmatch
import os
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT", "hp-optinmonster-supply-chain-attack-ioc-scope"))
CONTENT_INDICATORS = [
  "tidio[.]cc",
  "a.omappapi.com",
  "a.opmnstr.com",
  "a.optnmstr.com",
  "a.trstplse.com",
  "clientcdn.pushengage.com",
  "gmail[.]com",
  "https://a.omappapi.com/app/js/api.min.js",
  "https://a.opmnstr.com/app/js/api.min.js",
  "https://a.optnmstr.com/app/js/api.min.js",
  "https://a.trstplse.com/app/js/api.min.js",
  "https://clientcdn.pushengage.com/sdks/pushengage-web-sdk.js",
  "84.201.6.54"
]
PATH_INDICATORS = [
  "wp-content/plugins/content-delivery-helper/content-delivery-helper.php",
  "wp-content/plugins/database-optimizer/database-optimizer.php"
]
EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}

def _iter_files(root):
    root = Path(root)
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            yield Path(current) / name

def _path_matches(path):
    text = str(path)
    matches = []
    for indicator in PATH_INDICATORS:
        if not indicator:
            continue
        if indicator.startswith(("/", "~")):
            candidate = Path(os.path.expanduser(indicator))
            if candidate.exists() and path == candidate:
                matches.append(indicator)
        if indicator in text or fnmatch.fnmatch(text, indicator) or fnmatch.fnmatch(path.name, indicator):
            matches.append(indicator)
    return matches

def _content_matches(path):
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []
    return [indicator for indicator in CONTENT_INDICATORS if indicator and indicator in content]

def _scan_roots(roots):
    matches = []
    for root in roots:
        if not root:
            continue
        for path in _iter_files(root):
            for indicator in _path_matches(path):
                matches.append(f"{path}: path matched {indicator!r}")
            for indicator in _content_matches(path):
                matches.append(f"{path}: content matched {indicator!r}")
    return matches

def main():
    parser = argparse.ArgumentParser(description="Scan files and logs for Halting Problems IOC values")
    parser.add_argument("roots", nargs="*", default=["."], help="File or directory roots to scan")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log directory")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    indicator_lines = sorted(set(CONTENT_INDICATORS + PATH_INDICATORS))
    (OUT / "ioc-indicators.txt").write_text("\n".join(indicator_lines) + "\n")

    roots = list(args.roots)
    if args.log_root:
        roots.append(args.log_root)
    matches = _scan_roots(roots)
    if matches:
        (OUT / "ioc-scope-matches.txt").write_text("\n".join(matches) + "\n")
        print(f"[!] Found {len(matches)} IOC matches; details written under {OUT}")
        return 1
    print(f"[+] No IOC matches found; indicator inventory written under {OUT}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[-] Execution failure: {exc}", file=sys.stderr)
        sys.exit(2)
```

### Hunt Manifest: optinmonster-supply-chain-attack-hunt-3
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with OptinMonster Supply Chain Attack?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for optinmonster-supply-chain-attack.

Searches repository trees and exported logs for literal IOC values from iocs.json.
Exit codes:
  0: no matches
  1: one or more indicators matched
  2: execution error
"""
import argparse
import fnmatch
import os
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT", "hp-optinmonster-supply-chain-attack-ioc-scope"))
CONTENT_INDICATORS = [
  "tidio[.]cc",
  "a.omappapi.com",
  "a.opmnstr.com",
  "a.optnmstr.com",
  "a.trstplse.com",
  "clientcdn.pushengage.com",
  "gmail[.]com",
  "https://a.omappapi.com/app/js/api.min.js",
  "https://a.opmnstr.com/app/js/api.min.js",
  "https://a.optnmstr.com/app/js/api.min.js",
  "https://a.trstplse.com/app/js/api.min.js",
  "https://clientcdn.pushengage.com/sdks/pushengage-web-sdk.js",
  "84.201.6.54"
]
PATH_INDICATORS = [
  "wp-content/plugins/content-delivery-helper/content-delivery-helper.php",
  "wp-content/plugins/database-optimizer/database-optimizer.php"
]
EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}

def _iter_files(root):
    root = Path(root)
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            yield Path(current) / name

def _path_matches(path):
    text = str(path)
    matches = []
    for indicator in PATH_INDICATORS:
        if not indicator:
            continue
        if indicator.startswith(("/", "~")):
            candidate = Path(os.path.expanduser(indicator))
            if candidate.exists() and path == candidate:
                matches.append(indicator)
        if indicator in text or fnmatch.fnmatch(text, indicator) or fnmatch.fnmatch(path.name, indicator):
            matches.append(indicator)
    return matches

def _content_matches(path):
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []
    return [indicator for indicator in CONTENT_INDICATORS if indicator and indicator in content]

def _scan_roots(roots):
    matches = []
    for root in roots:
        if not root:
            continue
        for path in _iter_files(root):
            for indicator in _path_matches(path):
                matches.append(f"{path}: path matched {indicator!r}")
            for indicator in _content_matches(path):
                matches.append(f"{path}: content matched {indicator!r}")
    return matches

def main():
    parser = argparse.ArgumentParser(description="Scan files and logs for Halting Problems IOC values")
    parser.add_argument("roots", nargs="*", default=["."], help="File or directory roots to scan")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log directory")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    indicator_lines = sorted(set(CONTENT_INDICATORS + PATH_INDICATORS))
    (OUT / "ioc-indicators.txt").write_text("\n".join(indicator_lines) + "\n")

    roots = list(args.roots)
    if args.log_root:
        roots.append(args.log_root)
    matches = _scan_roots(roots)
    if matches:
        (OUT / "ioc-scope-matches.txt").write_text("\n".join(matches) + "\n")
        print(f"[!] Found {len(matches)} IOC matches; details written under {OUT}")
        return 1
    print(f"[+] No IOC matches found; indicator inventory written under {OUT}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[-] Execution failure: {exc}", file=sys.stderr)
        sys.exit(2)
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Remediation and Closure

WordPress site administrators should perform the following actions to remediate the OptinMonster, TrustPulse, and PushEngage plugin supply chain attack:

1. **Preserve evidence**: Before making modifications, take a database SQL dump and create a ZIP archive of the `wp-content/plugins` folder to preserve timestamps and files.
2. **Revoke compromised accounts**: Search the database for `developer_api1` or patterns of `dev_xxxxxx` usernames and delete them.
3. **Eradicate backdoor files**: Physically delete the folders `/wp-content/plugins/content-delivery-helper` and `/wp-content/plugins/database-optimizer` from the server. Do not rely on the WordPress dashboard interface.
4. **Revoke and rotate administrative credentials**: Change the password for all legitimate administrator accounts. Rotate the database user password (update it in `wp-config.php`).
5. **Rotate salts and keys**: Generate new WordPress authentication keys and salts and update them in `wp-config.php` to invalidate all active sessions.
6. **Audit web server logs**: Review access logs for requests referencing `developer_api1_fm` or `developer_api1_eval` to see if malicious commands were executed.
7. **Close incident**: Close the incident once a complete filesystem and database audit of the OptinMonster, TrustPulse, or PushEngage installations returns zero matches.

## Sources

1. **Sansec Research**: Threat advisory detailing the supply chain attack, C2 domain, rogue users, backdoor behavior, and affected plugins. [Sansec](https://sansec.io/research/optinmonster-supply-chain-attack)
