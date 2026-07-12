#!/usr/bin/env python3
"""Offline incident-specific selector hunt for shapedplugin-pro-update-channel-compromise."""
import json, os, sys
from pathlib import Path
SELECTORS=['ShapedPlugin', 'Real Testimonials Pro 3.2.5', 'Product Slider Pro before 3.5.4', 'Smart Post Pro before 4.0.2', 'LicenseLoader.php', 'wp-content/plugins/woocommerce-subscription/', '/wp-json/wc/v3/settings/apply', 'generate.2faplugin.org', '194.76.217.28:2871']
TEXT_SUFFIXES={'.csv','.json','.jsonl','.txt','.log','.yaml','.yml','.xml','.js','.map','.har','.php','.ini','.conf'}
def scan(root):
 matches=[]
 paths=[root] if root.is_file() else root.rglob('*')
 for p in paths:
  if p.is_file() and (not p.suffix or p.suffix.lower() in TEXT_SUFFIXES):
   try:
    text=p.read_text(errors='ignore').lower()
   except OSError:
    continue
   hits=sorted(s for s in SELECTORS if s.lower() in text)
   if hits: matches.append({'path':str(p),'hits':hits})
 return matches
def main():
 root=Path(sys.argv[1] if len(sys.argv)>1 else '.'); matches=scan(root); report={'incident':'shapedplugin-pro-update-channel-compromise','match_count':len(matches),'matches':matches}
 out=Path(os.environ.get('OUT','hp-shapedplugin-pro-update-channel-compromise-hunt')); out.mkdir(parents=True,exist_ok=True); target=out/'report.json'; target.write_text(json.dumps(report,indent=2)); print(json.dumps({'match_count':len(matches),'report':str(target)})); return 2 if matches else 0
if __name__=='__main__': raise SystemExit(main())
