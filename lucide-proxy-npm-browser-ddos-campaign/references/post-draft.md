---
title: "Lucide Proxy: 148 npm packages used as browser DDoS and adware delivery infrastructure"
date: 2026-07-13
severity: high
tags:
  - npm
  - browser
  - registry-abuse
  - ddos
  - adware
summary: "Lucide Proxy abused 148 npm packages as static delivery artifacts for proxy pages; historical builds remotely loaded code and conscripted visiting browsers into Wisp and HTTP floods, while the latest documented wave was adware-only."
sourceCount: 7
---

## Executive Summary

JFrog tied 148 npm package names to the Lucide Proxy campaign and published an exact package/version/Xray mapping. The packages were not conventional Node libraries: they carried static proxy application assets intended to be hosted and opened in a browser. Historical May builds contained a mutable remote JavaScript loader and Wisp-compatible traffic generator, and JFrog recovered a May 30 archived payload that made visitor browsers participate in an HTTP flood. The researchers report that those modules were removed on May 31; the July 8 wave contained later adware-only builds. Current DDoS execution must therefore not be inferred from current package availability alone. [1]

SafeDep's May 27 snapshot is complementary rather than disproving the historical finding. It analyzed 141 `terminal3airport` packages as byte-identical static proxy/adware assets with no install hooks or credential stealers. JFrog later reconstructed earlier mutable-loader and flood behavior from repository history and archives, then added seven package names associated with `eerikakirk`. Package consumers and developers are not automatically compromised by installation; the primary execution path required a proxy build to be served and a user to visit it. [1] [2]

Should you care? If any of the 148 names appears in a lockfile, npm cache, hosted static bundle, deployment inventory, or exported network/browser telemetry, run the tested scope scanner and preserve the matching evidence. Treat dependency presence, hosted deployment, and browser execution as three separate states. Escalate immediately when page visits or service-worker registration overlap with campaign infrastructure, the stable Analytics identifier, or the historical May activity window.

## Key Facts

| Fact | Value |
| --- | --- |
| Affected artifacts | 148 npm package names; 398 package/version pairs in `iocs.json` |
| Registry publishers | `terminal3airport` and `eerikakirk` |
| Representative packages | `charlie-kirk`, `ilovefemboys`, `miguelphonk` |
| Execution trigger | Visiting a hosted proxy page; no npm lifecycle hook was observed |
| Historical malicious window | Remote loader added May 16; Wisp generator added May 17; HTTP flood observed May 30; malicious modules removed May 31 [1] |
| Latest documented package wave | July 8, 2026; JFrog describes it as obfuscated adware-only content [1] |
| Current registry check | On July 13, abbreviated npm metadata returned security placeholders for 147 names; `charlie-kirk` 2.0.0 and 3.0.1 remained downloadable by registry metadata. This does not prove current DDoS behavior. [7] |
| Hosting footprint | JFrog recovered 93 deployment hostnames; 90 resolved to one reported infrastructure IP during its analysis [1] |
| Immediate action | Find affected dependencies and hosted builds, preserve browser/network evidence, disable affected deployments, block precise campaign infrastructure, and clean confirmed browser service-worker/site data |

## Evidence Assessment

| Claim | Assessment | What the evidence proves | Limitation |
| --- | --- | --- | --- |
| The campaign contains 148 npm packages | Confirmed, high confidence | JFrog provides a 148-row package/version/Xray table; the locally captured table parses to exactly 148 unique names and 398 version pairs [1] | JFrog did not publish npm tarball hashes for every version |
| The May build history had a mutable loader and Wisp generator | Confirmed, high confidence | JFrog deobfuscated the builds; GitHub commit API results independently preserve the cited May 16 and May 17 commits. Static summaries of returned patches contain the loader, WebSocket, Wisp, loopback, browser-storage, and cookie terms reported by JFrog. [1] [4] [5] [6] | GitHub omitted or truncated some large patches, so absence in a returned patch would not prove absence |
| Visitor browsers generated attack traffic | Confirmed historically, high confidence | JFrog recovered an archived May 30 HTTP-flood payload and locally simulated Wisp frames without live targets [1] | No public victim count or complete visitor/session inventory is available |
| SafeDep found adware, no install hook, and no credential stealer | Confirmed for SafeDep's May package snapshot | SafeDep statically compared 141 packages and documented static proxy assets, popunder advertising, tracking, and no lifecycle execution [2] | That snapshot did not reconstruct earlier mutable repository history |
| Current packages execute DDoS code | Not observed | JFrog says the July wave used later adware-only builds; registry metadata only establishes name/version availability [1] [7] | `charlie-kirk` remains available, and later external script loading means content risk can change; a fresh artifact/browser capture would be needed |
| Credentials were stolen | Not observed | JFrog showed that mutable code could read same-origin cookies/local storage in a sandbox, but neither primary source reports confirmed credential theft [1] [2] | A confirmed page visit with beacon evidence would change the response decision |

## Impact Determination

| Exposure classification | Criteria | Required evidence | Required action | Closure gate |
| --- | --- | --- | --- | --- |
| Confirmed browser execution | Browser history, managed-browser telemetry, proxy/DNS logs, or service-worker inventory shows a campaign deployment and matching page execution | UTC browser history, service-worker origin/scope, cached asset hashes, DNS/proxy records, deployment version | Preserve evidence, isolate the hosted deployment, block precise infrastructure, unregister the affected service worker after preservation, clear that origin's data, and investigate outbound traffic | Rebuilt deployment and affected browsers scan clean; no campaign selectors in 30 days of monitoring |
| Confirmed hosted exposure | A deployment contains an affected package/version or assets mapped to the malicious May commits, but visitor evidence is incomplete | Build manifest, lockfile, deployed file hashes, CDN object metadata, source maps, deployment logs | Disable the deployment, preserve artifacts and access logs, invalidate CDN objects, rebuild from reviewed source | Clean artifact scan, cache purge evidence, and complete visitor-impact review |
| Package present, execution unproven | Affected name/version appears only in a manifest, lockfile, cache, or registry mirror | Dependency files, cache metadata, SBOM, internal registry logs | Remove the package, determine whether it was ever deployed as a web app, and rebuild only if it entered a deployment | Package/version absent from dependencies, caches selected for rebuild, and deployed artifacts |
| Not affected | Complete relevant dependency, deployment, browser, and network scopes are clean | Scanner output plus inventory proving those scopes were supplied | Retain evidence and monitor new Lucide-related package names | Recheck after the monitoring window and inventory changes |

## Minimum Evidence To Collect

- Preserve dependency manifests, lockfiles, SBOMs, npm cache metadata, and internal registry logs. These establish package exposure but do not prove that browser code executed.
- Export deployment manifests, build logs, source maps, CDN object listings, WAF logs, and static asset hashes. These map affected package content or GitHub build history to a served application.
- Export browser history, service-worker registration scope/origin, cached asset metadata, and site-data timestamps from managed endpoints. These decide whether a user actually opened the proxy and whether its service worker persisted.
- Preserve DNS, secure web gateway, HTTP proxy, firewall, and NetFlow records with UTC timestamps from March 5 through at least July 13. These correlate page visits with campaign infrastructure, the stable Analytics property, and possible flood traffic.
- Preserve the exact scanner input set, scanner JSON output, collection time, analyst identity, and SHA-256 of exported evidence. Negative results are inconclusive when one of the dependency, deployment, browser, or network scopes is missing.

## Timeline

- **2026-03-05 (time unknown)**: JFrog's earliest observed Lucide page used Analytics property `G-0VL3ZSBXDH` and reverse DNS on `geeked[.]wtf`. [1]
- **2026-03-16 (time unknown)**: JFrog first observed traffic monetized through `woofbeginner[.]com`. [1]
- **2026-05-16 17:01:27 UTC**: `lucideproxy/svg` commit `bcc9868e345b6a04e2b2b89de355d1829daf31e1` updated the build; JFrog maps this phase to addition of the mutable loader. [1] [4]
- **2026-05-17 04:26:12 UTC**: Commit `9b7ca53d6bd8c197e8fe29eabcff54b03331f98f` updated the build; JFrog maps this phase to the Wisp generator capped at 64 sockets. [1] [5]
- **2026-05-17 13:25:50 UTC**: Commit `ccc7c921bc931c93cf418a877e16fe768a201500` updated the obfuscated build; JFrog maps this phase to a 1,024-socket cap. [1] [6]
- **2026-05-27 (times vary)**: SafeDep documented 141 packages under `terminal3airport` as static proxy/adware assets with no install hook. [2]
- **2026-05-30 (time unknown)**: JFrog's Wayback analysis recovered an active HTTP-flood payload targeting an external site from visiting browsers. [1]
- **2026-05-31 (exact source/build mapping unresolved)**: JFrog reports removal of the remote loader and Wisp modules. The abbreviated source commit `cf741e982181a` did not resolve directly in the public `lucideproxy/svg` API; several build commits exist around 01:00 UTC. [1] [3]
- **2026-07-08 (times vary)**: Seven additional package names associated with `eerikakirk` brought the total to 148; JFrog describes these builds as adware-only. [1]
- **2026-07-13 21:55:38 UTC**: Static abbreviated registry metadata queries returned 147 `0.0.1-security` placeholders and left `charlie-kirk` 2.0.0/3.0.1 available. No tarballs were downloaded or executed. [7]
- **2026-07-13**: JFrog published the full historical DDoS/RCE analysis. [1]

## What Happened

The operator published batches of static proxy applications under unusual npm names, using npm as a distribution/CDN-adjacent channel rather than as a normal imported library. Deployers could host those assets as student-oriented unblocker pages. Visitors then ran the application's JavaScript and service worker in their browsers. [1] [2]

In May, the build repository briefly gained a mutable loader and a Wisp-compatible traffic generator. This gave the hosted application a remote behavior-control path and a way to create high-rate connection churn through remote Wisp proxy servers. JFrog also recovered an archived HTTP flood. The modules were later removed, leaving adware and third-party script loading in the July package wave. [1]

## Technical Analysis

### Initial Access

There is no evidence of maintainer-account compromise or typosquatting against a legitimate library. The campaign created its own package names under `terminal3airport` and `eerikakirk` and published web application assets. The supply-chain abuse is the use of a trusted public registry to distribute mutable, obfuscated browser content. [1] [2]

### Execution Trigger

Installing or caching a package did not automatically execute malware. SafeDep found no lifecycle scripts, and the package entry points were static/service-worker assets rather than usable Node modules. Browser behavior began when someone served the application and a visitor opened the page. That distinction is essential for scoping: package presence is an exposure lead, not proof of endpoint compromise. [2]

### Payload Behavior

Historical builds loaded JavaScript from a mutable CDN-backed path and generated Wisp v2-compatible control frames. JFrog reports that the configuration grew from 64 to 1,024 WebSocket connections and could produce rapid connection creation/teardown pressure on a remote Wisp server. A separate archived payload produced HTTP request floods. Later builds removed these modules but retained obfuscated advertising and external script loading. [1]

### Credential or Data Collection

JFrog demonstrated in a local sandbox that remotely supplied code could read cookies and local storage available to the proxy origin and beacon values out. This establishes capability, not observed credential theft. Same-origin browser boundaries and the exact proxy implementation determine what data was reachable. Do not order broad enterprise credential rotation without a confirmed visit plus storage/beacon evidence; invalidate sessions or tokens specifically exposed through the affected origin when that evidence exists. [1]

### Defense Evasion

The builds used obfuscation, randomized asset filenames, fake tutoring branding, hidden SEO text, and ordinary npm/CDN/browser delivery. The mutable loader separated the initially reviewed static artifact from later behavior. These techniques make package-only scanning insufficient and require deployment plus browser/network correlation. [1] [2]

### Exfiltration and Command and Control

No confirmed credential exfiltration campaign was documented. The remote loader and advertising scripts created attacker-controlled or campaign-linked network dependencies; JFrog's sandbox showed beacon capability. Treat precise URLs and payload hashes as stronger signals than broad shared CDN domains. Raw network indicators are kept in `iocs.json`; this prose defangs them. [1]

## Affected Assets and Blast Radius

The exact machine-readable set is 148 package names and 398 package/version pairs in `iocs.json`. The JFrog table includes `charlie-kirk`, `ilovefemboys`, `miguelphonk`, 141 SafeDep-era names, and seven later names. The blast radius cannot be inferred from npm download counts because the meaningful victim action was hosting or visiting the resulting proxy application. [1] [2]

| Asset class | Exposure path | Known scope | Confidence |
| --- | --- | --- | --- |
| npm package consumers | Package downloaded or mirrored | 148 names; current malicious versions unavailable for 147 names, with `charlie-kirk` still available by metadata | High for identity, medium for current content |
| Hosted proxy deployments | Package assets served as a static web application | JFrog recovered 93 hostnames | High for reported count; complete list unavailable |
| Browser users | Visited a deployed proxy page and ran its scripts/service worker | Unknown visitor count | Exposure-dependent |
| GitHub build history | `lucideproxy/svg` commits retained historical build transitions | Public repository and cited immutable commits | High |

## Indicators of Compromise

Use `iocs.json` for raw, typed values. Important human-readable pivots include:

| Type | Value | Context |
| --- | --- | --- |
| npm publishers | `terminal3airport`, `eerikakirk` | Campaign publishing accounts |
| repository | `lucideproxy/svg` | Public build history |
| Analytics ID | `G-0VL3ZSBXDH` | Stable cross-deployment campaign identifier |
| historical infrastructure | `lucideon[.]top`, `woofbeginner[.]com`, `wisp[.]breadarchive[.]dpdns[.]org` | Page, advertising, and Wisp pivots |
| primary infrastructure IP | `92[.]38[.]177[.]17` | Ninety reported deployments resolved here during JFrog's analysis |
| payload SHA-256 | `4b188d179e50e8208a6efec85e273e88d8fc390c836f299ba12915e0840408fd` | Archived HTTP-flood payload |

## Detection and Hunting

Run [`scripts/scan_lucide_proxy_exposure.py`](scripts/scan_lucide_proxy_exposure.py) against a reader-owned repository or a directory containing exported dependency, deployment, browser, DNS, proxy, CDN, WAF, or hosting evidence:

```bash
python3 scripts/scan_lucide_proxy_exposure.py "$HOME/ir-exports/lucide-scope" --out "$HOME/ir-exports/lucide-scan.json"
```

The script embeds all 148 names, their exact malicious version mapping, campaign publishers/repositories, payload hashes, precise URLs/domains/IPs, and stable identifiers. It does not make network requests or execute located content.

- Exit `0`: no selector was found in the supplied scope. This is clean only for the evidence types actually included.
- Exit `1`: at least one selector matched. Preserve the matching file/log and correlate package, deployment, browser, and network evidence.
- Exit `2`: collection failed or the scope was invalid. Do not interpret this as clean.

Package-name-only matches can be noisy because some names are generic. A package/version pair in a lockfile is stronger, but still does not prove that a web page was hosted or visited. A positive page-origin or service-worker match plus proxy/DNS traffic is the strongest available exposure evidence.

For a read-only forensic copy of a Chromium or Chrome user-data directory, run [`scripts/collect_chromium_lucide_evidence.py`](scripts/collect_chromium_lucide_evidence.py):

```bash
python3 scripts/collect_chromium_lucide_evidence.py "$HOME/ir-exports/chromium-user-data" --out "$HOME/ir-exports/lucide-browser-evidence.json"
```

This collector queries History SQLite databases read-only and searches service-worker/cache files for exact campaign selectors without emitting unrelated browsing records. Exit codes use the same `0` clean, `1` match, and `2` collection-failure contract.

## Downstream Abuse Audits

This event supports browser and hosting audits, not a generic cloud/OIDC or developer-workstation compromise runbook. Collect the affected origin's service-worker registration, cache/site-data timestamps, browser history, and outbound proxy/DNS records. Map those timestamps to deployment artifacts and the historical May commits. If a user visited only a July adware build, document advertising/privacy impact separately from DDoS participation.

If beacon logs prove that a sensitive same-origin session or token left the browser, revoke that specific session/token from a clean administrative environment and audit its subsequent use. Neither primary source justifies rotating unrelated GitHub, npm, cloud, SSH, or workstation credentials based solely on package presence. [1] [2]

## Remediation and Recovery Gates

1. Preserve lockfiles, build artifacts, hosted files, browser/service-worker records, proxy/DNS logs, and UTC timestamps before cleanup.
2. Disable confirmed Lucide-derived deployments and prevent further access while evidence is collected.
3. Block the precise campaign domains, URLs, and IPs in `iocs.json`; avoid blocking shared CDN domains without path-level controls.
4. Remove all affected package/version pairs from dependency manifests, lockfiles, registry mirrors, and caches selected for rebuild.
5. Rebuild hosted proxy applications from reviewed source without mutable loaders or campaign advertising scripts, then invalidate CDN objects.
6. On confirmed visitor browsers, unregister the affected-origin service worker and clear that origin's cached assets/cookies/site data after evidence preservation.
7. Revoke only sessions or tokens shown to be reachable and transmitted; record why broader rotation is not applicable when there is no such evidence.
8. Run the tested scanner across rebuilt artifacts and complete dependency, deployment, browser, and network evidence scopes.
9. Close only after the rebuilt deployment and affected browsers are clean and 30 days of monitoring show no campaign selector, with package consumers and page visitors counted separately.

## Open Questions

- Does the currently available `charlie-kirk` 2.0.0 or 3.0.1 content contain any live mutable behavior beyond the July adware build? This run did not download package tarballs.
- What are the complete 93 deployment hostnames and their first/last served timestamps?
- Which public build commit exactly corresponds to JFrog's abbreviated `cf741e982181a` module-removal reference?
- How many deployments served a malicious May build, and how many unique browsers visited them?

## Sources

[1] https://research.jfrog.com/post/lucide-proxy-npm-malware-campaign/ — Primary reverse engineering, timeline, package/version table, hosting footprint, and IOC appendix; published July 13, 2026.

[2] https://safedep.io/malicious-npm-terminal3airport-proxy-adware-spam/ — Primary static package analysis of the 141-package May snapshot; documents adware/static assets and absence of install hooks or credential stealers.

[3] https://github.com/lucideproxy/svg — Direct public build repository metadata and history.

[4] https://github.com/lucideproxy/svg/commit/bcc9868e345b6a04e2b2b89de355d1829daf31e1 — Direct May 16 build commit referenced by the historical loader phase.

[5] https://github.com/lucideproxy/svg/commit/9b7ca53d6bd8c197e8fe29eabcff54b03331f98f — Direct May 17 build commit referenced by the Wisp-generator phase.

[6] https://github.com/lucideproxy/svg/commit/ccc7c921bc931c93cf418a877e16fe768a201500 — Direct May 17 obfuscated build commit referenced by the higher socket-cap phase.

[7] https://registry.npmjs.org/charlie-kirk — Direct npm registry metadata for the package that remained available during the July 13 static status check; the complete 148-name query result is preserved in the research packet.
