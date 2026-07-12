# Claim Ledger

| Claim | Status | Source | Notes |
| --- | --- | --- | --- |
| Affected package/version set in `iocs.json` | confirmed | https://socket.dev/blog/jscrambler-supply-chain-attack | Source-listed selectors only |
| Execution trigger: npm preinstall in 8.14.0/8.16.0/8.17.0; import or CLI execution in 8.18.0/8.20.0 | confirmed | https://socket.dev/blog/jscrambler-supply-chain-attack | Static/source analysis |
| Payload behavior: drops a detached native Linux, Windows, or macOS credential and wallet stealer from dist/intro.js | confirmed | https://socket.dev/blog/jscrambler-supply-chain-attack | Do not infer successful theft for every install |
| Verified victim count | unknown | https://socket.dev/blog/jscrambler-supply-chain-attack | No organizational victim count established |
| Independent corroboration of core artifact behavior | confirmed | https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary | Second research team |
