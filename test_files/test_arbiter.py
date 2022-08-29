import unittest

from pathlib import Path

from arbiter import Recon
from arbiter import Arbiter
from arbiter import VDGraph
from arbiter import FirstArg, RetNode

class ArbiterTest(unittest.TestCase):
    def test_single_func_data_flow(self):
        vd = VDGraph()
        src = RetNode('strlen')
        dst = FirstArg('malloc')
        vd.add_edge(src, dst)

        p = Arbiter(filename=Path(__file__ ).parent / 'build/single_func_data_flow.elf', vd=vd)
        recon = Recon(p.storage)
        recon.analyze_all()
    
    def test_multi_func_data_flow(self):
        vd = VDGraph()
        src = RetNode('strlen')
        dst = FirstArg('malloc')
        vd.add_edge(src, dst)

        p = Arbiter(filename=Path(__file__ ).parent / 'build/multi_func_data_flow.elf', vd=vd)
        recon = Recon(p.storage)
        recon.analyze_all()

