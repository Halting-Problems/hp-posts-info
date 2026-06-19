# Claim Ledger — JetBrains Marketplace Malicious Plugin Incident

## Confirmed

- JetBrains says it received reports on 2026-06-16, removed 15 plugins, banned 7 publisher accounts, and disabled the plugins through backend controls.
- StepSecurity identified 15 plugin IDs, seven publisher handles, an approximate late-2025-to-June-2026 exposure window, and exfiltration to `39.107.60.51`.
- Sample JetBrains Marketplace listing checks for representative IDs now return 404 after the purge.

## Likely

- The ~70,000-install figure is a campaign-level estimate from StepSecurity, not a JetBrains-confirmed count.

## Unclear

- The initial account-compromise method is not publicly established in the reviewed sources.
- The exact number of API keys stolen is not public.

## Not Observed

- JetBrains says its internal systems and source code were not compromised.
- Public sources reviewed here do not show GitHub, cloud, or CI/CD compromise as the direct incident path.
