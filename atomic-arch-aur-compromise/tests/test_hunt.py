import importlib.util,pathlib
P=pathlib.Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('hunt',P/'scripts/hunt_atomic_arch_aur_compromise.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def test_clean(): assert m.scan(P/'fixtures/clean')==[]
def test_dirty(): assert m.scan(P/'fixtures/dirty')
def test_literals(): assert len(m.SELECTORS)>0
