# Sicoob.Sdk NuGet Certificate Exfiltration Claim Ledger

## Decision

`new_incident_post`: publishable as a standalone supply-chain impersonation and malicious NuGet package incident. No existing Halting Problems post matched `pkg:nuget/Sicoob.Sdk`, `campaign:sicoob-sdk-nuget-certificate-exfiltration`, or the Socket source URL.

## Claim Ledger

| Claim | Status | Evidence |
| --- | --- | --- |
| Socket published primary research on May 28, 2026 about malicious `Sicoob.Sdk` NuGet releases exfiltrating certificate material and passwords through Sentry telemetry. | confirmed | Socket article title, byline date, summary, technical analysis, and IOCs. |
| NuGet flat-container index currently lists `Sicoob.Sdk` versions `1.0.0`, `2.0.0`, `2.0.1`, `2.0.2`, `2.0.3`, and `2.0.4`. | confirmed | `https://api.nuget.org/v3-flatcontainer/sicoob.sdk/index.json` returned those six versions on 2026-05-28. |
| NuGet registration metadata records `Sicoob.Sdk` as authored by `Sicoob.Sdk`, with `Sicoob-Cooperativa.*` module dependencies and `Sentry` `4.4.0`. | confirmed | Downloaded registration index and extracted nuspec files for all six versions. |
| Versions `2.0.0` through `2.0.4` contain the hardcoded Sentry DSN `https://d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232.ingest.de.sentry.io/4511337546317904`. | confirmed | Downloaded package artifacts from NuGet; `strings -el lib/net8.0/Sicoob.Sdk.dll` shows the DSN in each affected version. |
| Versions `2.0.0` through `2.0.4` contain static selectors consistent with PFX/client credential exfiltration: `cliend_id:`, `pass:`, `ReadAllBytes`, `ToBase64String`, `CaptureMessage`, and `SentrySdk`. | confirmed | Downloaded package artifacts; UTF-16LE string extraction from `lib/net8.0/Sicoob.Sdk.dll`. |
| Version `1.0.0` has the Sentry dependency and boleto response strings but did not show the hardcoded Sentry DSN or `cliend_id`/`pass` strings in the same local static extraction. | confirmed with limited static method | Local artifact scan on downloaded `1.0.0`; not a full decompilation proof of benign behavior. |
| Public GitHub source in `Sicoob-Cooperativa/sicoob_sdk_csharp` loads a PFX via `X509Certificate2` and configures HTTP clients, but the inspected `main` branch `SicoobClient.cs` does not contain Sentry initialization or capture calls. | confirmed | Raw `SicoobClient.cs` fetched from GitHub on 2026-05-28. |
| NuGet package metadata points to specific repository commits but does not include a repository URL in the extracted nuspec. | confirmed | Extracted nuspec files contain `repository type="git" commit="..."` with no URL attribute. |
| `Sicoob-Cooperativa` impersonation risk is high: organization was created 2026-05-04, is not verified, has zero followers, and claimed Sicoob developer portal association by self-declared blog link. | confirmed for GitHub properties; authorization unknown | GitHub organization API response. |
| Older `github.com/Sicoob` account exists, was created in 2017, names "Confederacao Nacional das Cooperativas do Sicoob", lists Brasilia-DF, and links to `www.sicoob.com.br`. | confirmed | GitHub user API response. |
| Sicoob, Sentry, or NuGet have publicly attributed an actor. | not_observed | Socket article does not name an actor; no advisory found in local collection. |
| Confirmed victim organizations or successful financial API abuse are known. | not_observed | Socket describes potential impact and exfiltration behavior but not victim counts or downstream abuse. |

## Artifact Hashes

| Version | SHA-256 |
| --- | --- |
| `Sicoob.Sdk@1.0.0` | `87b66028e491573b787ee00bc81916241047e035d152dfbf4807b57c1bbbb043` |
| `Sicoob.Sdk@2.0.0` | `7d2332e76c266509cdec8b552ccc839f50c28e6b01070071257bd3f57d1d9da2` |
| `Sicoob.Sdk@2.0.1` | `f0dff53969080584560b2971411415bdf9064d5a5a50185c4ae018943e7d5cbe` |
| `Sicoob.Sdk@2.0.2` | `94eb8da6703dd073184015c9e3cb34e9b6153fc499c9cb1a7db6e4361ec349dd` |
| `Sicoob.Sdk@2.0.3` | `ac9dc55f13d973e05865e9674c8b8e6744e7fbfca3355199b292f614f13ac7bc` |
| `Sicoob.Sdk@2.0.4` | `190dbcafa776e8cc221106414b8fbd68252d98438c5e46b8449788fbe70316a4` |

## Collection Gaps

- NuGet package page UI download counts and package blocking banner were not captured from the NuGet web UI in this run; rely on Socket for those UI-only observations.
- No authenticated Sentry, NuGet, or Sicoob incident statement was available.
- No victim telemetry was available; downstream abuse guidance is conditional on each defender's Sicoob, CI/CD, EDR, proxy, and secret-store logs.
