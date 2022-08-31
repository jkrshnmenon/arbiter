import unittest

from pathlib import Path

from arbiter import ControlFlow
from arbiter import Arbiter
from arbiter import VDGraph
from arbiter import FirstArg, ThirdArg, RetNode

class ArbiterTest(unittest.TestCase):
    def test_single_func_data_flow(self):
        vd = VDGraph()
        src = RetNode('strlen')
        dst = FirstArg('malloc')
        vd.add_edge(src, dst)

        p = Arbiter(filename=Path(__file__ ).parent / 'build/single_func_data_flow.elf', vd=vd)
        control_flow = ControlFlow(p.storage)
        control_flow.analyze_all()

        ctr = 0
        for pp in p.storage.iter_sinks():
            # print(pp)
            ctr += 1
            self.assertEqual(len(pp.nodes), 2)
            sm1, sm2 = pp.nodes
            self.assertEqual(sm1.function, sm2.function)
            self.assertNotEqual(sm1.block, sm2.block)
        self.assertEqual(ctr, 1)
    
    def test_multi_func_data_flow(self):
        vd = VDGraph()
        src = RetNode('strlen')
        dst = FirstArg('malloc')
        vd.add_edge(src, dst)

        p = Arbiter(filename=Path(__file__ ).parent / 'build/multi_func_data_flow.elf', vd=vd)
        control_flow = ControlFlow(p.storage)
        control_flow.analyze_all()

        ctr = 0
        for pp in p.storage.iter_sinks():
            ctr += 1
            # print(pp)
            self.assertEqual(len(pp.nodes), 2)
            sm1, sm2 = pp.nodes
            self.assertNotEqual(sm1.block, sm2.block)
            self.assertNotEqual(sm1.function, sm2.function)
        self.assertEqual(ctr, 1)
    
    def test_multi_data_flow(self):
        vd = VDGraph()
        ptr = RetNode('malloc')
        sz = FirstArg('malloc')
        ptr_dst = FirstArg('memcpy')
        sz_dst = ThirdArg('memcpy')
        vd.add_edge(ptr, ptr_dst)
        vd.add_edge(sz, sz_dst)
        malloc_meta = vd.unify_nodes(ptr, sz)
        memcpy_meta = vd.unify_nodes(ptr_dst, sz_dst)

        p = Arbiter(filename=Path(__file__ ).parent / 'build/multi_data_flow.elf', vd=vd)
        control_flow = ControlFlow(p.storage)
        control_flow.analyze_all()

        ctr = 0
        for pp in p.storage.iter_sinks():
            # print(pp)
            ctr += 1
            self.assertEqual(len(pp.nodes), 2)
            sm1, sm2 = pp.nodes
            self.assertEqual(sm1.function, sm2.function)
            self.assertNotEqual(sm1.block, sm2.block)
        self.assertEqual(ctr, 1)
        self.assertEqual(malloc_meta.edge_targets(ptr, incoming=False), [ptr_dst])
        self.assertEqual(malloc_meta.edge_targets(sz, incoming=False), [sz_dst])
        # self.assertEqual(memcpy_meta.edge_targets(ptr_dst, incoming=True), [ptr])
        # self.assertEqual(memcpy_meta.edge_targets(sz_dst, incoming=True), [sz])

