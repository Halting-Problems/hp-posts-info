#!/usr/bin/env python3
"""Read-only IOC scanner for exported text/CSV/JSON evidence. Never installs packages."""
import argparse,json,re,sys
IOCS={'packages': ['paysafe-checkout', 'paysafe-vault', 'neteller', 'skrill-payments', 'paysafe-js', 'paysafe-api', 'paysafe-node', 'paysafe-cards', 'paysafe-fraud', 'paysafe-kyc', 'skrill', 'skrill-sdk', 'paysafe-payments'], 'versions': ['paysafe-checkout@1.0.0', 'paysafe-checkout@1.0.1', 'paysafe-checkout@1.0.2', 'paysafe-checkout@1.0.3', 'paysafe-vault@1.0.0', 'paysafe-vault@1.0.1', 'paysafe-vault@1.0.2', 'paysafe-vault@1.0.3', 'neteller@1.0.0', 'neteller@1.0.1', 'neteller@1.0.2', 'neteller@1.0.3', 'skrill-payments@1.0.0', 'skrill-payments@1.0.1', 'skrill-payments@1.0.2', 'skrill-payments@1.0.3', 'paysafe-js@1.0.0', 'paysafe-js@1.0.1', 'paysafe-js@1.0.2', 'paysafe-js@1.0.3', 'paysafe-api@1.0.0', 'paysafe-api@1.0.1', 'paysafe-api@1.0.2', 'paysafe-api@1.0.3', 'paysafe-node@1.0.0', 'paysafe-node@1.0.1', 'paysafe-node@1.0.2', 'paysafe-node@1.0.3', 'paysafe-cards@1.0.0', 'paysafe-cards@1.0.1', 'paysafe-cards@1.0.2', 'paysafe-cards@1.0.3', 'paysafe-fraud@1.0.0', 'paysafe-fraud@1.0.1', 'paysafe-fraud@1.0.2', 'paysafe-fraud@1.0.3', 'paysafe-kyc@1.0.0', 'paysafe-kyc@1.0.1', 'paysafe-kyc@1.0.2', 'paysafe-kyc@1.0.3', 'skrill@1.0.0', 'skrill@1.0.1', 'skrill@1.0.2', 'skrill@1.0.3', 'skrill-sdk@1.0.0', 'skrill-sdk@1.0.1', 'skrill-sdk@1.0.2', 'skrill-sdk@1.0.3', 'paysafe-payments@1.0.0', 'paysafe-payments@1.0.1', 'paysafe-payments@1.0.2', 'paysafe-payments@1.0.3', 'pypi:paysafe-kyc@1.0.0', 'pypi:paysafe-payments@1.0.0', 'pypi:paysafe-sdk@1.0.0', 'pypi:paysafe-api@1.0.0'], 'files': ['index.js', '__init__.py'], 'domains': ['caliber-spinner-finishing.ngrok-free.dev'], 'ips': [], 'hashes': []}
def scan(path):
 try:
  text=path.read_text(errors="replace").lower()
 except OSError:
  return []
 hits=[]
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
