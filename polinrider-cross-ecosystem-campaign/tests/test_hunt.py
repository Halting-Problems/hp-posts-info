import importlib.util,pathlib
P=pathlib.Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('hunt',P/'scripts/hunt_polinrider_cross_ecosystem_campaign.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def test_clean(): assert m.scan(P/'fixtures/clean')==[]
def test_dirty(): assert m.scan(P/'fixtures/dirty')
def test_literals(): assert len(m.SELECTORS)>0
def test_woff2_filename_selector(tmp_path):
 (tmp_path/'font.woff2').write_bytes(b'not executed')
 assert m.scan(tmp_path)==[{'path':str(tmp_path/'font.woff2'),'selectors':['*.woff2']}]
