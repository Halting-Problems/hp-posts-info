# Claim Ledger

| Claim | Status | Source | Notes |
| --- | --- | --- | --- |
| Affected package/version set in `iocs.json` | confirmed | https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps | Source-listed selectors only |
| Execution trigger: npm SDK method use when an API key is configured; PyPI package import | confirmed | https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps | Static/source analysis |
| Payload behavior: fingerprints hosts and exfiltrates environment variables whose names contain key, secret, token, pass, auth, or api | confirmed | https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps | Do not infer successful theft for every install |
| Verified victim count | unknown | https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps | No organizational victim count established |
