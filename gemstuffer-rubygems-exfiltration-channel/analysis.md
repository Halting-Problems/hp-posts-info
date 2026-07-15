---
title: "GemStuffer RubyGems Exfiltration Channel"
date: 2026-05-28
severity: "medium"
tags:
  - supply-chain
  - rubygems
  - ruby
  - exfiltration
  - public-sector
summary: "GemStuffer used RubyGems package publishing as a data-staging channel, wrapping scraped UK council ModernGov portal responses into junk gem artifacts published with embedded RubyGems API keys."
sourceCount: 5
---

## Executive Summary
GemStuffer is not a classic dependency compromise: public evidence does not show existing legitimate gems being hijacked, mass developer installs, or a self-propagating installer. It is still supply-chain abuse because the actor used RubyGems' package release path as an exfiltration and storage primitive, turning ordinary gem artifacts into retrievable containers for scraped public-sector portal data [Socket](https://socket.dev/blog/gemstuffer).

Socket reports more than 100 gems in the campaign and says its tracker contains 155 affected package artifacts [Socket](https://socket.dev/blog/gemstuffer). Representative tracker rows include `agenda-sample-yard 0.1.1`, `bot9evil 0.1.0`, `fetchrootx2 0.0.1`, `soufetchabc 0.0.3`, `wandcabfetchfix21736 0.0.1`, `wandscrawlr 0.0.1`, `slnleaker5 0.0.1`, `fetchrootx1 0.0.1`, and `lambeth71b 0.0.1` [Socket tracker](https://socket.dev/supply-chain-attacks/gemstuffer). RubyGems' broader May 12 response says more than 500 malicious packages associated with the registry spam attack were yanked; that figure must not be treated as a GemStuffer-only count [RubyGems status](https://status.rubygems.org/history).

The downstream risk is registry-abuse blind spots. A `POST` to `rubygems[.]org/api/v1/gems` can look like a normal release from a developer workstation or CI runner, but in this case the uploaded binary gem carried scraped HTML responses from UK council ModernGov portals. Defenders should monitor who is allowed to publish packages, not only which packages are installed.

## Key Facts
**Threat Type**: RubyGems registry abuse as exfiltration channel

**Ecosystem**: RubyGems, Ruby

**Registry**: RubyGems.org

**Campaign Name**: GemStuffer

**Affected Package Artifacts**: 155 reported by Socket tracker; representative rows verified

**Broader Registry Response**: RubyGems reported 500+ malicious packages yanked across the wider May 12 spam attack; not all are mapped to GemStuffer

**Affected Packages Representative**:
- agenda-sample-yard
- bot9evil
- fetchrootx2
- soufetchabc
- lambeth71b
- wandscrawlr
- slnleaker5
- lambethx33zzz
- southfetchprobe42

**Malicious Versions Representative**:
- agenda-sample-yard 0.1.1
- bot9evil 0.1.0
- fetchrootx2 0.0.1
- soufetchabc 0.0.3
- lambeth71b 0.0.1

**Known Good Versions**:

**Fixed Or Safe Versions**:
- not applicable; junk packages were yanked or should be treated as malicious staging artifacts

**Execution Trigger**: unknown delivery vector; observed Ruby payload execution with embedded RubyGems publishing credentials

**Primary Impact**: scraped council portal data staged into public RubyGems package artifacts

**Public Sector Scope**:
- Lambeth ModernGov portal
- Wandsworth democratic services portal
- Southwark ModernGov portal

**Confidence**: medium

**Canonical Source**: https://socket.dev/blog/gemstuffer

**Last Verified**: 2026-06-10

## Evidence Assessment
- **confirmed:** Socket published primary research with representative Ruby code for ModernGov scraping, gem archive construction, `/tmp/gemhome` credential injection, `gem push`, and direct HTTP upload variants [Socket](https://socket.dev/blog/gemstuffer).
- **confirmed:** Socket's public campaign tracker reports 155 affected package artifacts and shows representative package/version rows with May 12, 2026 UTC publish and detection timestamps [Socket tracker](https://socket.dev/supply-chain-attacks/gemstuffer).
- **confirmed:** RubyGems documents `POST /api/v1/gems`, version metadata, SHA fields, yanking, and `timeframe_versions`, matching the registry mechanics observed in this campaign [RubyGems API](https://guides.rubygems.org/rubygems-org-api/).
- **confirmed:** RubyGems status history records temporary disabling of new user registrations from May 12, 2026 08:54 UTC to May 16, 2026 05:12 UTC during the broader spam-publishing response [RubyGems status](https://status.rubygems.org/history).
- **confirmed, broader incident only:** RubyGems said bot accounts were blocked and removed and more than 500 malicious packages from the wider spam attack were yanked; public evidence does not map all of those packages to GemStuffer [RubyGems status](https://status.rubygems.org/history).
- **unknown:** Publisher account handles, complete account-to-package mapping, initial delivery vector, and whether every tracked artifact contained scraped data versus probe or spam content.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed staging host | A host ran the Ruby payload, wrote `/tmp/gemhome/.gem/credentials`, built a gem, or posted a gem body to RubyGems. | EDR process/file telemetry, shell history, CI logs, preserved `/tmp` directories, RubyGems API key audit records. | Isolate long enough to preserve evidence, revoke RubyGems keys, review other reachable secrets, and block further gem publishing from that host. | No remaining payload files, no unauthorized gem pushes, credentials rotated, and egress controls enforce approved release runners only. |
| Presumed staging host | The host made an unauthorized `POST` to `rubygems[.]org/api/v1/gems` in the campaign window and also accessed one of the ModernGov calendar URLs. | Proxy logs with method/path, TLS inspection metadata if available, process attribution, Ruby runtime telemetry. | Treat as exfiltration-capable until proven otherwise; preserve logs and map the executing user. | Network event is explained by an approved release workflow or incident handling is complete. |
| Registry exposure only | Your organization did not execute the payload but mirrors, caches, SBOMs, or dependency tools recorded GemStuffer package artifacts. | Gem cache listings, Artifactory/Nexus logs, SBOMs, lockfiles, RubyGems mirror data. | Remove cached gems, block known names, and ensure no internal automation promoted them. | Internal package mirrors and dependency indexes no longer serve the artifacts. |
| Public-sector data exposure | Council portal pages or agenda responses appear in gem archive content or registry metadata. | Extracted `data.tar.gz`, `lib/result.txt`, README payloads, metadata descriptions, council URLs. | Notify data owners if non-public or sensitive content is observed; otherwise record bulk public-data scraping exposure. | Each recovered artifact is classified as public, sensitive, or unknown and handled accordingly. |
| Not exposed | No GemStuffer package names, payload hashes, `/tmp` artifacts, ModernGov scrape requests, or unauthorized RubyGems publish requests are present. | Source/gem-cache scans, proxy logs, EDR telemetry, CI job logs. | Keep registry publish monitoring in place. | Search coverage includes developer endpoints, CI, package mirrors, and logs for the campaign window. |

## Timeline
- **2026-05-12 02:20-03:30 UTC:** RubyGems timeframe metadata shows yanked representative versions and many suspicious May 12 package rows containing ModernGov or related selectors. Local verification used the public `timeframe_versions` API documented by RubyGems [RubyGems API](https://guides.rubygems.org/rubygems-org-api/).
- **2026-05-12 08:54 UTC:** RubyGems status history marks the start of temporary new-user registration disabling during the broader abuse response [RubyGems status](https://status.rubygems.org/history).
- **2026-05-13 03:17 UTC:** RubyGems reports that the broader spam activity stopped, bot accounts were removed, and more than 500 malicious packages were yanked [RubyGems status](https://status.rubygems.org/history).
- **2026-05-13:** Socket publishes the GemStuffer research and links it to the RubyGems spam-publishing context [Socket](https://socket.dev/blog/gemstuffer).
- **2026-05-16 05:12 UTC:** RubyGems status history marks the registration-disabling incident resolved [RubyGems status](https://status.rubygems.org/history).
- **2026-05-28:** Representative RubyGems API checks return `yanked: true` for sampled GemStuffer package versions.

## Technical Analysis

### Registry Abuse, Not Normal Package Consumption
The campaign's most important distinction is directionality. The package registry was not merely a place where victims downloaded code. The payload published new packages back to RubyGems so the actor could retrieve scraped data later with standard gem tooling [Socket](https://socket.dev/blog/gemstuffer).

Socket's representative chain collects execution context, fetches ModernGov calendar and agenda pages, writes the HTTP responses into a valid gem directory, builds a `.gem` archive, and pushes it to RubyGems. In one variant, the scraped content lands in `lib/result.txt`; in another, it is placed in a `README` inside a gem built through Ruby APIs [Socket](https://socket.dev/blog/gemstuffer). [1]

### Scraping Targets
Socket identifies three public-facing UK council portals: `moderngov[.]lambeth[.]gov[.]uk`, `democracy[.]wandsworth[.]gov[.]uk`, and `moderngov[.]southwark[.]gov[.]uk`. The code follows `mgCalendarMonthView.aspx` pages, extracts `ieList` and `mgCommittee` links, and fetches follow-on agenda pages [Socket](https://socket.dev/blog/gemstuffer).

The public evidence supports bulk scraping of public ModernGov content. It does not prove theft of private council systems, authenticated portals, or internal networks. That uncertainty matters: responders should classify recovered `lib/result.txt` or README content rather than assuming either harmless public data or confirmed sensitive data. [1]

### RubyGems Credential Handling
Some samples created `/tmp/gemhome/.gem/credentials`, wrote a hardcoded RubyGems API key, set permissions to `0600`, and overrode `HOME` so `gem push` would read that fabricated credential store. Other variants avoided the `gem` CLI and used `Net::HTTP::Post` directly with an `Authorization` header and `application/octet-stream` body [Socket](https://socket.dev/blog/gemstuffer). RubyGems' API documentation confirms that gem creation is a binary `POST` to `/api/v1/gems` authenticated with an Authorization header [RubyGems API](https://guides.rubygems.org/rubygems-org-api/).

This makes credential rotation narrower than a typical credential stealer but still urgent. Rotate observed RubyGems API keys first, then evaluate secrets reachable from the host that ran the unknown delivery vector. [1]

### Registry Metadata Verification
Direct package pages for many sampled names now return not found or yanked states, but `timeframe_versions` remains useful for retrospective scoping. Representative API rows verified on May 28, 2026 included:

**Representative Verified Rows**:
- [object Object]
- [object Object]
- [object Object]
- [object Object]
- [object Object]

RubyGems also publishes weekly sanitized PostgreSQL dumps, which are the right next source for a complete registry-scale ledger without scraping live package pages [RubyGems data](https://rubygems.org/pages/data). [1]

### Affected Assets And Blast Radius
**Affected Assets**:
  - **ecosystems**: RubyGems,Ruby
  - **packages**: agenda-sample-yard,bot9evil,fetchrootx2,soufetchabc,wandcabfetchfix21736,wandscrawlr,slnleaker5,fetchrootx1,lambeth71b,lambethx33zzz,southfetchprobe42
  - **versions**: 0.0.1,0.0.2,0.0.3,0.0.5,0.1.0,0.1.1,1.0.0,1.2.3,9.8.0,9.9.0
  - **public_sector_portals**: moderngov[.]lambeth[.]gov[.]uk,democracy[.]wandsworth[.]gov[.]uk,moderngov[.]southwark[.]gov[.]uk
  - **ci_cd_systems**: unknown; any Ruby-capable release runner with outbound RubyGems publish access should be audited
  - **developer_tools**: Ruby,RubyGems gem CLI

**Credentials At Risk**:
- RubyGems API keys embedded in payloads
- secrets reachable from hosts where the unknown delivery vector executed

**Not Currently Known To Affect**:
- Existing legitimate RubyGems packages, based on public reporting available for this post.
- Developers who only consumed normal Ruby dependencies and never executed the GemStuffer payload. [1]

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 239440c830e17530dda0a8a06ed2708860998750a1e3ed2239e919465dc59420
- c2d6bcacc88177e0f2c8c262726f86f37e671b1692c8bc135bac4b610ddcf31a
- 34212b88108cab6ded037257d6fbc79a61b4c2ea8ecddc6c513b5aad1f308638
- 2e4e099275efb8f886824a8eccdc595e624cd08ebb1772bd427710e08ff3ab24
- 94d6c0b589704c8cc75e19f7250d6bfda473266dd7dd7e23fd14bd1bb972a717

### Domains
- payload.rb
- script.rb
- evil.rb
- yardload.rb
- exploit.rb
- extconf.rb
- fetcher.rb
- x.gemspec
- rubygems[.]org
- moderngov.lambeth.gov.uk
- democracy.wandsworth.gov.uk
- moderngov.southwark.gov.uk

### Urls
- hxxps://rubygems[.]org/api/v1/gems
- hxxps://moderngov[.]lambeth[.]gov[.]uk/mgCalendarMonthView[.]aspx?M=1&Y=2026&GL=1&bcr=1
- hxxps://democracy[.]wandsworth[.]gov[.]uk/mgCalendarMonthView[.]aspx?M=1&Y=2026&GL=1&bcr=1
- hxxps://moderngov[.]southwark[.]gov[.]uk/mgCalendarMonthView[.]aspx?M=1&Y=2026&GL=1&bcr=1


## Detection and Hunting

### Hunt Manifest: gemstuffer-rubygems-exfiltration-channel-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with GemStuffer RubyGems Exfiltration Channel?
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
OUT = Path(os.environ.get("OUT", "hp-gemstuffer-rubygems-exfiltration-channel-scope"))

VERSIONS = ["agenda-sample-yard 0.1.1","bot9evil 0.1.0","fetchrootx2 0.0.1","soufetchabc 0.0.3","lambeth71b 0.0.1"]
FILES = ["payload.rb","script.rb","evil.rb","yardload.rb","yard_plugin.rb","exploit.rb","extconf.rb","fetcher.rb","/tmp/gemhome/.gem/credentials","/tmp/rubydocran_*","lib/result.txt","x.gemspec"]
DOMAINS = ["payload.rb","script.rb","evil.rb","yardload.rb","exploit.rb","extconf.rb","fetcher.rb","x.gemspec","rubygems.org","moderngov.lambeth.gov.uk","democracy.wandsworth.gov.uk","moderngov.southwark.gov.uk","mgCalendarMonthView.aspx"]
URLS = ["https://rubygems.org/api/v1/gems","https://moderngov.lambeth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1","https://democracy.wandsworth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1","https://moderngov.southwark.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1"]
HASHES = ["239440c830e17530dda0a8a06ed2708860998750a1e3ed2239e919465dc59420","c2d6bcacc88177e0f2c8c262726f86f37e671b1692c8bc135bac4b610ddcf31a","34212b88108cab6ded037257d6fbc79a61b4c2ea8ecddc6c513b5aad1f308638","2e4e099275efb8f886824a8eccdc595e624cd08ebb1772bd427710e08ff3ab24","94d6c0b589704c8cc75e19f7250d6bfda473266dd7dd7e23fd14bd1bb972a717"]

# Collect unique indicators
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "ioc-indicators.txt"
indicators = set()
for group in [VERSIONS, FILES, DOMAINS, URLS, HASHES]:
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
1. Contain systems that show GemStuffer execution or unauthorized RubyGems publishing.
2. Preserve `/tmp/gemhome`, `/tmp/rubydocran_*`, package staging directories, `.gem` archives, shell histories, CI logs, and proxy logs.
3. Revoke all RubyGems API keys observed in payloads or logs. Review key creation and usage around May 12, 2026.
4. Block RubyGems gem-create POSTs from networks and runners that should never publish gems.
5. For legitimate release automation, restrict RubyGems publishing to named runners and expected package names.
6. Remove cached GemStuffer gems from internal mirrors and dependency caches.
7. Classify any recovered council data and notify affected data owners if non-public or sensitive content appears.
8. Close the incident only after registry, endpoint, CI, proxy, and mirror checks are complete and documented.

## Sources
1. [Socket: GemStuffer Campaign Abuses RubyGems as Exfiltration Channel Targeting UK Local Government](https://socket.dev/blog/gemstuffer)
2. [Socket GemStuffer campaign tracker](https://socket.dev/supply-chain-attacks/gemstuffer)
3. [RubyGems.org API guide](https://guides.rubygems.org/rubygems-org-api/)
4. [RubyGems.org status history](https://status.rubygems.org/history)
5. [RubyGems.org data dumps](https://rubygems.org/pages/data)
