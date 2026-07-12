#!/usr/bin/env python3
"""Static scanner for operation-muck-and-load-github-go; never executes artifacts."""
import pathlib,sys,json
SELECTORS=['dnsub-scanning-tool', 'github.com/kaleidora/dnsub-scanning-tool', 'github.com/kaleidora/dnsub-scanning-tool unknown', 'go.mod', 'go.sum', 'muckcoding.com', 'muckdeveloper.com', 'powershell.exe', 'protected archive download', 'public dead-drop retrieval']
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
 if len(sys.argv)!=2: raise SystemExit('usage: hunt_operation_muck_and_load_github_go.py PATH')
 hits=scan(sys.argv[1]); print(json.dumps(hits,indent=2)); raise SystemExit(2 if hits else 0)
