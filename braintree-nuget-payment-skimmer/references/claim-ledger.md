# Claim Ledger

| Claim | Status | Source | Notes |
| --- | --- | --- | --- |
| Affected package/version set in `iocs.json` | confirmed | https://socket.dev/blog/braintree-nuget-typosquat-skims-credit-cards | Source-listed selectors only |
| Execution trigger: .NET module initialization, production gateway configuration, and payment API calls | confirmed | https://socket.dev/blog/braintree-nuget-typosquat-skims-credit-cards | Static/source analysis |
| Payload behavior: intercepts PAN/CVV, steals Braintree merchant keys, and harvests environment, config, cloud, and container secrets | confirmed | https://socket.dev/blog/braintree-nuget-typosquat-skims-credit-cards | Do not infer successful theft for every install |
| Verified victim count | unknown | https://socket.dev/blog/braintree-nuget-typosquat-skims-credit-cards | No organizational victim count established |
