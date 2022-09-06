import angr
from typing import Type, List

from ..utils import *
from ..spec import VDNode

from .control_flow_detection import M, SinkMarker

B = Type[angr.block.Block]



class DataResolution(object):
    def __init__(self, block: B, node: N) -> None:
        """Class to store the details of a data-flow for a vd node

        Args:
            block (B): The angr basic block object
            node (N): The VD node
        """
        self._block = block
        assert isinstance(node, VDNode)
        assert not isinstance(node, MetaNode), "MetaNode not supported in DataResolution class"
        self._node = node

        self._resolution = {'insn_addr': 0, 'insn': None, 'vex_idx': 0, 'vex_stmt': None}
    
    def __str__(self) -> str:
        out = f"DataResolution(\n\tnode={self._node},\n\tblock={hex(self._block.addr)},\n"
        out += f"\t<{prGreen(self.vex_stmt)}> <= {prRed(self.insn)} : {prYellow(self.vex_idx)},\n)"
        return out
    
    @property
    def insn(self):
        return self._resolution['insn']
    
    @property
    def insn_addr(self):
        return self._resolution['insn_addr']
    
    @property
    def vex_stmt(self):
        return self._resolution['vex_stmt']
    
    @property
    def vex_idx(self):
        return self._resolution['vex_idx']
    
    @property
    def resolution(self) -> dict:
        return self._resolution
    
    @resolution.setter
    def resolution(self, value_dict) -> None:
        assert all([True for x in ['insn', 'insn_addr', 'vex_stmt', 'vex_idx'] if x in value_dict])
        assert isinstance(value_dict['insn_addr'], int)
        assert isinstance(value_dict['vex_idx'], int)
        assert value_dict['insn'] is not None
        assert value_dict['vex_stmt'] is not None
        self._resolution = value_dict


DR = Type[DataResolution]


class DataMarker():
    def __init__(self, marker: M) -> None:
        """
        Args:
            marker (M): The SinkMarker object
        """
        self._marker = marker
        assert isinstance(self._marker, SinkMarker)
        self._node = marker.marker
        assert isinstance(self._node, VDNode)
        self._block = self._marker.block

        if isinstance(self._node, MetaNode):
            self._data = {x: None for x in self._node.nodes}
        else:
            self._data = {self._node: None}
        
        for x in self._data:
            self._data[x] = DataResolution(block=self.block, node=x)
            self._data[x].resolution = resolve_data_marker(block=self.block, vd_node=x, function=self._marker.function)
    
    def __str__(self) -> str:
        out = f"DataMarker(\n\tmarker={self._marker},\n"
        for x in self.vd_nodes:
            out += f"{self.resolved_marker(x)}\n"
        out += ")\n"
        return out
    
    @property
    def vd_nodes(self) -> list[N]:
        return list(self._data.keys())
    
    @property
    def block(self) -> B:
        return self._block
    
    @property
    def marker(self) -> M:
        return self._marker
    
    @property
    def resolution(self):
        if isinstance(self.marker, MetaNode):
            return self._data
        else:
            assert len(self.vd_nodes) == 1
            return self._data[self.vd_nodes[0]]
    
    def resolved_marker(self, vd_node: N) -> DR:
        assert vd_node in self._data
        return self._data[vd_node]



DM = Type[DataMarker]
    


class DataFlow():
    def __init__(self, path: List[DM]):
        self._marker = path
    
    @property
    def marker(self) -> M:
        return self._marker
    
    def __str__(self) -> str:
        out = ">>>>>>>>\n"
        for node in self.marker:
            out += "--------\n"
            out += f"{str(node)}\n"
        out += "--------\n"
        out += "<<<<<<<<\n"
        return out

    @property
    def nodes(self) -> list[M]:
        return self.marker

    
DF = Type[DataFlow]    
