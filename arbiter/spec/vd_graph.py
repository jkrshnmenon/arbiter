from typing import Optional, Tuple, Type
from networkx import DiGraph

from .vd_node import *

E = Tuple[N, N]



class VDGraph(object):
    """
    This class is used to represent a VD
    Each node should be an object of one of the classes in vd_node.py
    """
    def __init__(self):
        self.graph = DiGraph()
        self._sinks = []
        self._sources = []

    def __str__(self) -> str:
        out = ""
        for src, dst in self.graph.edges():
            out += f"{src} -> {dst}\n"
        return out

    @property
    def sinks(self) -> list[N]:
        return list(set(self._sinks))

    @property
    def sources(self) -> list[N]:
        return list(set(self._sources))

    def add_node(self, n: N) -> None:
        assert n not in self.graph.nodes, f"Node ({n}) is already a node in the graph"
        self.graph.add_node(n)
        if n.is_sink:
            self._sinks.append(n)
        else:
            self._sources.append(n)

    def add_edge(self, src: N, dst: N) -> None:
        assert src != dst, "Cannot have self edges"
        src.is_source = True
        assert (src, dst) not in self.graph.edges, f"Edge ({src} -> {dst}) is already in the graph"
        self.graph.add_edge(src, dst)
        if dst.is_sink:
            self._sinks.append(dst)
        else:
            self._sources.append(dst)
        self._sources.append(src)

    def _get_flows_to(self, dst: N) -> list[E]:
        return list(self.graph.in_edges(dst))

    def _get_flows_from(self, src: N) -> list[E]:
        return list(self.graph.out_edges(src))

    def _get_flows_between(self, src: N, dst: N) -> list[E]:
        flows = []
        for u, v in self.graph.edges():
            if src == u and dst == v:
                flows.append((src, dst))
        return flows

    def get_flows(self, src: Optional[N] = None, dst: Optional[N] = None) -> list[E]:
        if src is None:
            assert dst is not None, "SRC and DST cannot both be None"
            return self._get_flows_to(dst)
        elif dst is None:
            assert src is not None, "SRC and DST cannot both be None"
            return self._get_flows_from(src)
        else:
            return self._get_flows_between(src, dst)

    def get_nodes(self, name: str, sink: bool = True) -> list[N]:
        nodes = []
        for n in self.graph.nodes:
            if n.name == name and n.is_sink == sink:
                nodes.append(n)
        return nodes


V = Type[VDGraph]

def test_graph():
    vd = VDGraph()
    src = RetNode('strlen')
    dst = FirstArg('malloc')
    vd.add_edge(src, dst)
    assert len(vd.get_flows(src, dst)) == 1
    assert len(vd.get_nodes('strlen', sink=False)) == 1
    assert len(vd.get_nodes('malloc')) == 1
    import IPython; IPython.embed()


def test_graph2():
    vd = VDGraph()
    ptr = RetNode('malloc')
    sz = FirstArg('malloc')
    ptr_dst = FirstArg('memcpy')
    sz_dst = ThirdArg('memcpy')
    vd.add_edge(ptr, ptr_dst)
    vd.add_edge(sz, sz_dst)
    assert len(vd.get_nodes('malloc')) == 2
    assert len(vd.get_nodes('memcpy')) == 2


def test_graph3():
    vd = VDGraph()
    a = RetNode('strlen')
    b = RetNode('strlen')
    c = FirstArg('strlen')
    d = SecondArg('strlen')
    vd.add_node(a)
    try:
        vd.add_node(b)
    except AssertionError:
        pass
    vd.add_node(c)
    vd.add_node(d)
    assert len(vd.get_nodes('strlen')) == 3
    try:
        vd.add_edge(a, b)
    except AssertionError:
        pass
    vd.add_edge(a, c)
    try:
        vd.add_edge(a, c)
    except AssertionError:
        pass


if __name__ == '__main__':
    pass
    # test_graph3()
    test_graph()