#!/usr/bin/env python3
"""Read-only IOC scanner for exported text/CSV/JSON evidence. Never installs packages."""
import argparse,json,re,sys
IOCS={'packages': ['jscrambler'], 'versions': ['jscrambler@8.14.0', 'jscrambler@8.16.0', 'jscrambler@8.17.0', 'jscrambler@8.18.0', 'jscrambler@8.20.0'], 'files': ['dist/setup.js', 'dist/intro.js'], 'domains': ['check.torproject.org', 'archive.torproject.org'], 'ips': ['37.27.122.124', '57.128.246.79'], 'hashes': ['a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60', 'a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86', 'fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd', 'b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903', 'c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd']}
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
