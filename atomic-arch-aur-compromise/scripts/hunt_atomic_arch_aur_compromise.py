#!/usr/bin/env python3
"""Static scanner for atomic-arch-aur-compromise; never executes artifacts."""
import pathlib,sys,json
SELECTORS=['PKGBUILD', 'atomic-lockfile', 'atomic-lockfile unknown', 'bun install', 'js-digest', 'js-digest unknown', 'lockfile-js', 'lockfile-js unknown', 'npm install atomic-lockfile', 'package.json']
def scan(root):
 out=[]
 for p in pathlib.Path(root).rglob('*'):
  if not p.is_file(): continue
  try: text=p.read_text(errors='ignore').lower()
  except OSError: continue
  hits=[s for s in SELECTORS if s.lower() in text]
  if hits: out.append({'path':str(p),'selectors':hits})
 return out
if __name__=='__main__':
 if len(sys.argv)!=2: raise SystemExit('usage: hunt_atomic_arch_aur_compromise.py PATH')
 hits=scan(sys.argv[1]); print(json.dumps(hits,indent=2)); raise SystemExit(2 if hits else 0)
