import unittest

from pathlib import Path

from arbiter import Recon
from arbiter import Arbiter
from arbiter import VDGraph
from arbiter import FirstArg, RetNode

class ArbiterTest(unittest.TestCase):
    def test_simple_example(self):
        vd = VDGraph()
        src = RetNode('strlen')
        dst = FirstArg('malloc')
        vd.add_edge(src, dst)

        p = Arbiter(filename=Path(__file__ ).parent / 'simple_example.elf', vd=vd)
        recon = Recon(p.storage)
        recon.analyze_all()

