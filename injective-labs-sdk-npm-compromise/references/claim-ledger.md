# Claim Ledger

| Claim | Status | Source | Notes |
| --- | --- | --- | --- |
| Affected package/version set in `iocs.json` | confirmed | https://socket.dev/blog/compromised-injective-sdk-npm-package | Source-listed selectors only |
| Execution trigger: runtime calls to PrivateKey.fromMnemonic() or PrivateKey.fromHex() | confirmed | https://socket.dev/blog/compromised-injective-sdk-npm-package | Static/source analysis |
| Payload behavior: base64-encodes wallet recovery material and sends it in X-Request-Id on a disguised gRPC-Web POST | confirmed | https://socket.dev/blog/compromised-injective-sdk-npm-package | Do not infer successful theft for every install |
| Verified victim count | unknown | https://socket.dev/blog/compromised-injective-sdk-npm-package | No organizational victim count established |
| Independent corroboration of core artifact behavior | confirmed | https://www.stepsecurity.io/blog/injective-npm-supply-chain-attack-18-packages-backdoored-to-steal-crypto-wallet-keys | Second research team |
