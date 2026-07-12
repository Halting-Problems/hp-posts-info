#!/usr/bin/env python3
"""Read-only IOC scanner for exported text/CSV/JSON evidence. Never installs packages."""
import argparse,json,re,sys
IOCS={'packages': ['Braintree.Net', 'DependencyInjector.Core', 'SipNet', 'SipNet.OpenAI.Realtime'], 'versions': ['Braintree.Net@3.35.8', 'Braintree.Net@3.35.9', 'Braintree.Net@3.36.0', 'Braintree.Net@3.36.1', 'DependencyInjector.Core@1.0.0', 'DependencyInjector.Core@1.3.0', 'DependencyInjector.Core@1.4.0', 'DependencyInjector.Core@1.4.1', 'SipNet@12.8.4', 'SipNet@12.8.5', 'SipNet@12.8.6', 'SipNet@12.8.7', 'SipNet.OpenAI.Realtime@12.8.3'], 'files': ['Braintree.dll', 'DependencyInjector.Core.dll'], 'domains': ['api.348672-shakepay.com'], 'ips': ['104.21.89.51', '172.67.188.32'], 'hashes': []}
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
