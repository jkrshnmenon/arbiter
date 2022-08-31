from typing import Optional, Tuple, Type
from networkx import DiGraph, all_simple_paths

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
    
    def unify_nodes(self, *args: list[N]) -> N:
        """Create meta node with nodes.
        Use this function when multiple args/return values of same sink/source is required
        """
        meta_node = MetaNode(*args)
        in_nodes, out_nodes = {}, {}
        for n in args:
            assert n in self.graph.nodes, f"Node ({n}) is not a node in the graph"

            for src, _ in self.graph.in_edges(n):
                if n not in in_nodes:
                    in_nodes[n] = []
                in_nodes[n].append(src)

            for _, dst in self.graph.out_edges(n):
                if n not in out_nodes:
                    out_nodes[n] = []
                out_nodes[n].append(dst)

            self.remove_node(n)
        
        self.add_node(meta_node)

        tmp = []
        for n in in_nodes:
            for src in set(in_nodes[n]):
                if src in tmp:
                    continue
                tmp.append(src)
                self.add_edge(src, meta_node)
                meta_node.link_incoming(src, n)

        tmp = []
        for n in out_nodes:
            for dst in set(out_nodes[n]):
                if dst in tmp:
                    continue
                tmp.append(dst)
                self.add_edge(meta_node, dst)
                meta_node.link_outgoing(n, dst)
        
        if len(out_nodes) == 0:
            meta_node.is_sink = True
        else:
            meta_node.is_source = True
        
        return meta_node

    def add_node(self, n: N) -> None:
        assert n not in self.graph.nodes, f"Node ({n}) is already a node in the graph"
        self.graph.add_node(n)
        if n.is_sink:
            self._sinks.append(n)
        else:
            self._sources.append(n)
        
    def remove_node(self, n: N) -> None:
        assert n in self.graph.nodes, f"Node ({n}) is not a node in the graph"
        self.graph.remove_node(n)
        if n in self._sinks:
            self._sinks.remove(n)
        if n in self._sources:
            self._sources.remove(n)

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
    
    def remove_edge(self, src: N, dst: N) -> None:
        assert src != dst, "Cannot have self edges"
        assert (src, dst) in self.graph.edges, f"Edge ({src} -> {dst}) is not in the graph"
        self.graph.remove_edge(src, dst)
        if len(self.graph.out_edges(src)) == 0:
            self.graph.remove_node(src)
            self._sources.remove(src)
        if len(self.graph.in_edges(dst)) == 0:
            self.graph.remove_node(dst)
            if dst in self._sinks:
                self._sinks.remove(dst)
            else:
                self._sources.remove(dst)


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
    
    def iterate_paths(self) -> list[list[N]]:
        roots = [x for x in self.graph.nodes if self.graph.in_degree(x) == 0]
        leaves = [x for x in self.graph.nodes if self.graph.out_degree(x) == 0]
        all_paths = []
        for src in roots:
            for dst in leaves:
                all_paths.extend(all_simple_paths(self.graph, src, dst))

        return all_paths

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