import angr
from typing import Type, Optional

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

        # self._resolution = {'insn_addr': None, 'insn': None, 'vex_idx': None, 'vex_stmt': None}
        self._resolution = resolve_data_marker(block=self._block, vd_node=node)
    
    @property
    def insn(self):
        return self._resolution['insn']
    
    @property
    def insn_idx(self):
        return self._resolution['insn_idx']
    
    @property
    def vex_stmt(self):
        return self._resolution['vex_stmt']
    
    @property
    def vex_idx(self):
        return self._resolution['vex_idx']


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
    
    @property
    def vd_nodes(self) -> list[N]:
        return list(self._data.keys())
    
    @property
    def block(self) -> B:
        return self._block
    
    @property
    def marker(self) -> M:
        return self._marker
    
    def resolved_marker(self, vd_node: N) -> DR:
        assert vd_node in self._data
        return self._data[vd_node]
    
    
