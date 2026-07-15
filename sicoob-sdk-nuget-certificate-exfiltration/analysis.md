---
title: "Sicoob.Sdk NuGet Certificate Exfiltration"
date: 2026-05-28
severity: "critical"
tags:
  - nuget
  - dotnet
  - package-impersonation
  - certificate-theft
  - credential-theft
  - financial-services
summary: "Malicious Sicoob.Sdk NuGet releases impersonated a banking SDK and exfiltrated Sicoob client IDs, PFX passwords, and base64-encoded PFX certificate archives through a hardcoded Sentry endpoint."
sourceCount: 6
---
## Executive Summary

Socket published research on May 28, 2026 showing that NuGet package `Sicoob.Sdk` versions `2.0.0` through `2.0.4` impersonated an official Sicoob .NET SDK and exfiltrated banking API authentication material through Sentry telemetry [1]. Halting Problems downloaded the available NuGet artifacts and confirmed that the affected DLLs contain the hardcoded Sentry destination plus static selectors for `SentrySdk`, `CaptureMessage`, `ReadAllBytes`, `ToBase64String`, `cliend_id:`, and `pass:` in `lib/net8.0/Sicoob.Sdk.dll` [2], [3]. The package's public source repository presents ordinary SDK behavior for loading a PFX certificate into an mTLS HTTP client, but the inspected `SicoobClient.cs` source does not contain the Sentry initialization or capture path observed in the distributed NuGet DLL [6].

This should be treated as a malicious package impersonation event, not a benign telemetry mistake. Any organization that installed or executed `Sicoob.Sdk@2.0.0` through `2.0.4` with real Sicoob credentials should assume the supplied client ID, PFX archive contents, and PFX password were exposed unless local network and endpoint telemetry proves otherwise [1].

## Key Facts

**Threat Type**: NuGet package impersonation and credential exfiltration

**Ecosystem**: NuGet, .NET

**Registry**: NuGet

**Affected Packages**:
- Sicoob.Sdk

**Malicious Versions**:
- 2.0.0
- 2.0.1
- 2.0.2
- 2.0.3
- 2.0.4

**Known Non Malicious Versions**:
- 1.0.0

**Related Nuget Owner**: sicoob

**Related Github Org**: Sicoob-Cooperativa

**Exfiltration Endpoint Defanged**: hxxps://d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232[.]ingest[.]de[.]sentry[.]io/4511337546317904

**Credentials At Risk**:
- Sicoob API client IDs
- PFX certificate archives
- PFX passwords
- Sicoob access tokens derived from exposed client credentials
- raw boleto API response data

**Confidence**: high

**Attribution**: unknown

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| `Sicoob.Sdk` versions `2.0.0` through `2.0.4` exfiltrate client IDs, PFX passwords, and base64-encoded PFX contents through Sentry telemetry. | confirmed | Socket static and dynamic analysis, plus local artifact string verification for the affected NuGet packages [1], [2], [3]. |
| The NuGet package set currently includes `1.0.0`, `2.0.0`, `2.0.1`, `2.0.2`, `2.0.3`, and `2.0.4`. | confirmed | NuGet flat-container index and registration metadata [2], [3]. |
| The public GitHub repository is a source-to-package mismatch for the malicious behavior. | confirmed | The public `SicoobClient.cs` loads PFX material into `X509Certificate2`, while local package inspection and Socket's IL excerpt show Sentry capture behavior in the DLL [1], [6]. |
| `Sicoob-Cooperativa` should not be treated as an authorized Sicoob source without direct Sicoob confirmation. | likely | The GitHub org was created on 2026-05-04, is unverified, has zero followers, and differs from the older `github[.]com/Sicoob` account created in 2017 [4], [5]. |
| Downstream financial API abuse, confirmed victims, or actor identity are known. | not_observed | No primary evidence in this collection names victims, successful fraud, or a threat actor. |

## What Happened

The malicious package used the trust position of a banking SDK. Socket reported that `Sicoob.Sdk` advertised itself as an official C# SDK for Sicoob API integrations and accepted a client ID, PFX file path, and PFX password as normal constructor inputs [1]. That is a plausible shape for an mTLS-based financial API client: a PFX archive can contain the client certificate and private key needed to authenticate the integration.

The abuse is in what happened next. Socket found that production-mode `SicoobClient` construction initialized Sentry, read the supplied PFX file from disk, base64-encoded it, and captured a Sentry message containing the client ID, plaintext PFX password, and encoded certificate material [1]. Our local package inspection confirmed that `2.0.0` through `2.0.4` carry the Sentry destination and the static string set needed to support that behavior in `lib/net8.0/Sicoob.Sdk.dll` [2], [3].

NuGet metadata and package contents also support the impersonation assessment. The package uses Sicoob branding, depends on many `Sicoob-Cooperativa.Sicoob.*` modules, and includes a `Sentry` dependency in the `.nuspec` files [3]. The linked GitHub organization `Sicoob-Cooperativa` was created on 2026-05-04, is not GitHub-verified, exposes no public members through the API, and has zero followers [4]. That posture is materially different from the older `github[.]com/Sicoob` account, created in 2017 and presenting itself as "Confederacao Nacional das Cooperativas do Sicoob" with a `www.sicoob.com.br` link [5].

## Technical Analysis

Halting Problems downloaded the available `Sicoob.Sdk` package artifacts from NuGet's flat-container API on May 28, 2026. The package index still listed all six observed versions at collection time [2]. The SHA-256 values of the downloaded `.nupkg` files were:

**Artifact Hashes Sha256**:
  - **Sicoob.Sdk@1.0.0**: 87b66028e491573b787ee00bc81916241047e035d152dfbf4807b57c1bbbb043
  - **Sicoob.Sdk@2.0.0**: 7d2332e76c266509cdec8b552ccc839f50c28e6b01070071257bd3f57d1d9da2
  - **Sicoob.Sdk@2.0.1**: f0dff53969080584560b2971411415bdf9064d5a5a50185c4ae018943e7d5cbe
  - **Sicoob.Sdk@2.0.2**: 94eb8da6703dd073184015c9e3cb34e9b6153fc499c9cb1a7db6e4361ec349dd
  - **Sicoob.Sdk@2.0.3**: ac9dc55f13d973e05865e9674c8b8e6744e7fbfca3355199b292f614f13ac7bc
  - **Sicoob.Sdk@2.0.4**: 190dbcafa776e8cc221106414b8fbd68252d98438c5e46b8449788fbe70316a4 [1]

The extracted `.nuspec` files include repository commit values, but not a repository URL. The public GitHub repository does have a `SicoobClient.cs` file that handles `clientId`, `pfxPath`, and `pfxPassword` for mTLS, but the inspected source lacks `SentrySdk.Init`, `SentrySdk.CaptureMessage`, the Sentry ingestion host, and a direct source-level PFX file exfiltration path [6]. That mismatch is a key reason this incident is classified as supply-chain abuse instead of a normal SDK defect.

## Impact Determination

| Classification | Criteria | Required action | Closure condition |
| --- | --- | --- | --- |
| Confirmed compromise | `Sicoob.Sdk@2.0.0` through `2.0.4` executed and endpoint, proxy, EDR, or Sentry-ingest telemetry shows outbound activity to the listed Sentry host. | Isolate the executing host or runner, preserve package and network evidence, revoke Sicoob client IDs where possible, revoke and replace PFX certificates, and rotate PFX passwords from a clean system. | Replaced certificates and client IDs are in use, old material is rejected by Sicoob-side controls, and no suspicious token issuance or API activity remains unresolved. |
| Presumed exposed | Affected package version was installed, restored, built, imported, or used by an app or CI job that had real Sicoob PFX material, but telemetry cannot prove network exfiltration. | Treat the PFX archive, password, client ID, and any derived tokens as exposed. Rebuild from clean dependencies and audit financial API activity. | Every credential reachable from the affected runtime has been rotated or explicitly accepted by the risk owner. |
| Potentially exposed | `Sicoob.Sdk` appears in manifests, caches, lockfiles, packages, or code, but execution with real credentials is not established. | Collect package restore logs, application startup logs, endpoint telemetry, and secret-store access logs for the relevant period. | Each hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected versions or indicators appear in source, lockfiles, package caches, build artifacts, endpoints, CI logs, proxy logs, or deployed services. | Preserve negative search output and block future use of the package identity. | Coverage includes developer endpoints, CI runners, production hosts, and NuGet caches. |
| Unknown | Package inventory, endpoint telemetry, network logs, Sicoob logs, or CI logs are unavailable. | Keep the asset in scope and prefer credential rotation for production banking credentials. | Missing evidence is recovered or the residual risk is formally accepted. |

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 7d2332e76c266509cdec8b552ccc839f50c28e6b01070071257bd3f57d1d9da2
- f0dff53969080584560b2971411415bdf9064d5a5a50185c4ae018943e7d5cbe
- 94eb8da6703dd073184015c9e3cb34e9b6153fc499c9cb1a7db6e4361ec349dd
- ac9dc55f13d973e05865e9674c8b8e6744e7fbfca3355199b292f614f13ac7bc
- 190dbcafa776e8cc221106414b8fbd68252d98438c5e46b8449788fbe70316a4
- d565e3f03d0b1a7c8935d7ff94237316

### Domains
- o4511335034847232[.]ingest[.]de[.]sentry[.]io

### Urls
- hxxps://d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232[.]ingest[.]de[.]sentry[.]io/4511337546317904


## Detection and Hunting

### Hunt Manifest: sicoob-sdk-nuget-certificate-exfiltration-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Sicoob.Sdk NuGet Certificate Exfiltration?
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
OUT = Path(os.environ.get("OUT", "hp-sicoob-sdk-nuget-certificate-exfiltration-scope"))

DOMAINS = ["Sicoob.Sdk.dll","o4511335034847232[.]ingest[.]de[.]sentry[.]io"]
URLS = ["https://d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232.ingest.de.sentry.io/4511337546317904"]
HASHES = ["7d2332e76c266509cdec8b552ccc839f50c28e6b01070071257bd3f57d1d9da2","f0dff53969080584560b2971411415bdf9064d5a5a50185c4ae018943e7d5cbe","94eb8da6703dd073184015c9e3cb34e9b6153fc499c9cb1a7db6e4361ec349dd","ac9dc55f13d973e05865e9674c8b8e6744e7fbfca3355199b292f614f13ac7bc","190dbcafa776e8cc221106414b8fbd68252d98438c5e46b8449788fbe70316a4","d565e3f03d0b1a7c8935d7ff94237316"]

# Collect unique indicators
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

    if PACKAGES:
        registry_dir = OUT / "registry"
        registry_dir.mkdir(exist_ok=True)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Remediation and Closure

Containment: block `Sicoob.Sdk` in NuGet package policy, remove the package from source and lockfiles, isolate hosts or runners that executed affected versions with real credentials, and preserve the affected `.nupkg`, build logs, process telemetry, and network logs.

Eradication: replace the dependency only through a Sicoob-controlled and independently verified source path. Delete affected NuGet caches on developer workstations, CI runners, build images, and deployment hosts. Rebuild release artifacts from clean dependency state.

Credential recovery: revoke and replace any PFX certificates supplied to affected versions, rotate PFX passwords, rotate or disable exposed client IDs where Sicoob controls allow it, invalidate derived access tokens, and review Sicoob API audit logs for suspicious token issuance or financial operations.

Closure gates: all affected versions are absent from source, lockfiles, caches, images, and deployments; old certificates and passwords no longer authenticate; Sicoob API logs have been reviewed for the exposure window; and package allowlist controls prevent accidental reintroduction.

## Sources

1. [Socket: Malicious NuGet Package Impersonates Sicoob SDK to Exfiltrate Banking Certificates and Passwords](https://socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk)
2. [NuGet flat-container index for Sicoob.Sdk](https://api.nuget.org/v3-flatcontainer/sicoob.sdk/index.json)
3. [NuGet registration index for Sicoob.Sdk](https://api.nuget.org/v3/registration5-gz-semver2/sicoob.sdk/index.json)
4. [GitHub API: Sicoob-Cooperativa organization](https://api.github.com/orgs/Sicoob-Cooperativa)
5. [GitHub API: Sicoob account](https://api.github.com/users/Sicoob)
6. [Sicoob-Cooperativa public SicoobClient.cs source](https://raw.githubusercontent.com/Sicoob-Cooperativa/sicoob_sdk_csharp/main/SicoobClient.cs)
