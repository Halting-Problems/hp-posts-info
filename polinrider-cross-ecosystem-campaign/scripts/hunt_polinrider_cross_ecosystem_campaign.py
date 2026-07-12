#!/usr/bin/env python3
"""Static scanner for polinrider-cross-ecosystem-campaign; never executes artifacts."""
import fnmatch,pathlib,sys,json
SELECTORS=['*.woff2', '.vscode/tasks.json', 'Aptos RPC', 'BNB Smart Chain RPC', 'TRON RPC', 'code --folder-uri', 'eval(']
def matches(selector,p,text):
 if any(ch in selector for ch in '*?['):
  return fnmatch.fnmatch(p.name.lower(),selector.lower()) or selector.lower() in text
 return selector.lower() in text
def scan(root):
 out=[]
 for p in pathlib.Path(root).rglob('*'):
  if not p.is_file(): continue
  try: text=p.read_text(errors='ignore').lower()
  except OSError: continue
  hits=[s for s in SELECTORS if matches(s,p,text)]
  if hits: out.append({'path':str(p),'selectors':hits})
 return out
if __name__=='__main__':
 if len(sys.argv)!=2: raise SystemExit('usage: hunt_polinrider_cross_ecosystem_campaign.py PATH')
 hits=scan(sys.argv[1]); print(json.dumps(hits,indent=2)); raise SystemExit(2 if hits else 0)
