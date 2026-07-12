#!/usr/bin/env python3
"""Read-only IOC scanner for exported text/CSV/JSON evidence. Never installs packages."""
import argparse,json,re,sys
IOCS={'packages': ['@injectivelabs/sdk-ts', '@injectivelabs/utils', '@injectivelabs/networks', '@injectivelabs/ts-types', '@injectivelabs/exceptions', '@injectivelabs/wallet-base', '@injectivelabs/wallet-core', '@injectivelabs/wallet-cosmos', '@injectivelabs/wallet-private-key', '@injectivelabs/wallet-evm', '@injectivelabs/wallet-trezor', '@injectivelabs/wallet-cosmostation', '@injectivelabs/wallet-ledger', '@injectivelabs/wallet-wallet-connect', '@injectivelabs/wallet-magic', '@injectivelabs/wallet-strategy', '@injectivelabs/wallet-turnkey', '@injectivelabs/wallet-cosmos-strategy'], 'versions': ['@injectivelabs/sdk-ts@1.20.21', '@injectivelabs/utils@1.20.21', '@injectivelabs/networks@1.20.21', '@injectivelabs/ts-types@1.20.21', '@injectivelabs/exceptions@1.20.21', '@injectivelabs/wallet-base@1.20.21', '@injectivelabs/wallet-core@1.20.21', '@injectivelabs/wallet-cosmos@1.20.21', '@injectivelabs/wallet-private-key@1.20.21', '@injectivelabs/wallet-evm@1.20.21', '@injectivelabs/wallet-trezor@1.20.21', '@injectivelabs/wallet-cosmostation@1.20.21', '@injectivelabs/wallet-ledger@1.20.21', '@injectivelabs/wallet-wallet-connect@1.20.21', '@injectivelabs/wallet-magic@1.20.21', '@injectivelabs/wallet-strategy@1.20.21', '@injectivelabs/wallet-turnkey@1.20.21', '@injectivelabs/wallet-cosmos-strategy@1.20.21'], 'files': ['src/utils/key-derivation-telemetry.ts', 'dist/esm/accounts-jQ1GSgaW.js', 'dist/cjs/accounts-Cy0p4lLW.cjs'], 'domains': ['testnet.archival.chain.grpc-web.injective.network'], 'ips': [], 'hashes': ['103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0', '9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9']}
def scan(path):
 text=path.read_text(errors="replace").lower(); hits=[]
 for kind,vals in IOCS.items():
  for value in vals:
   if value.lower() in text: hits.append({"type":kind,"value":value,"path":str(path)})
 return hits
def main():
 from pathlib import Path
 ap=argparse.ArgumentParser(); ap.add_argument("paths",nargs="+"); ap.add_argument("--json",action="store_true"); a=ap.parse_args(); hits=[]
 for raw in a.paths:
  p=Path(raw)
  if p.is_file(): hits += scan(p)
  elif p.is_dir():
   for f in p.rglob("*"):
    if f.is_file(): hits += scan(f)
 if a.json: print(json.dumps({"hits":hits},indent=2))
 else:
  for h in hits: print(f"{h['type']}\t{h['value']}\t{h['path']}")
 return 2 if hits else 0
if __name__=="__main__": raise SystemExit(main())
