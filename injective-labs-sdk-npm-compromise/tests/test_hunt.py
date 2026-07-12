import json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).parents[1]; SCRIPT=ROOT/'scripts/hunt.py'
def run(f): return subprocess.run([sys.executable,str(SCRIPT),'--json',str(f)],text=True,capture_output=True)
def test_dirty_matches():
 r=run(ROOT/'fixtures/dirty/evidence.txt'); assert r.returncode==2; assert json.loads(r.stdout)['hits']
def test_clean_is_clear():
 r=run(ROOT/'fixtures/clean/evidence.txt'); assert r.returncode==0; assert json.loads(r.stdout)['hits']==[]
def test_manifest_script_exists():
 assert SCRIPT.exists(); assert 'scripts/hunt.py' in (ROOT/'manifest.yaml').read_text()
def test_ioc_contract():
 d=json.loads((ROOT/'iocs.json').read_text())
 packages=d['affected_assets']['packages']
 assert all(isinstance(x,str) and x.startswith('@injectivelabs/') for x in packages)
 assert all(x.count('@') == 1 for x in packages), 'scoped package coordinates must not include a trailing version'
 assert all(isinstance(x,str) for x in d['iocs']['package_versions'])
