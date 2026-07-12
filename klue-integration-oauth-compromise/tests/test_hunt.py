import json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; SCRIPT=ROOT/'scripts/hunt_klue-integration-oauth-compromise.py'
def run(name):
 env=dict(os.environ); env['OUT']=str(ROOT/'fixtures'/('out-'+name)); return subprocess.run([sys.executable,str(SCRIPT),str(ROOT/'fixtures'/name)],capture_output=True,text=True,env=env)
def test_clean(): assert run('clean').returncode==0
def test_dirty():
 r=run('dirty'); assert r.returncode==2; assert json.loads(r.stdout)['match_count']>=1
