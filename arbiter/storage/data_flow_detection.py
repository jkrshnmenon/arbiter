import angr
from typing import Type, Optional

from ..utils import *
from ..spec import VDNode

from .control_flow_detection import M, SinkMarker


class Marker(object):
    def __init__(self, marker: M):
        """Base class for storing data flow results

        Args:
            marker (M): The SinkMarker object

        Raises:
            NotImplementedError: This class should not be used directly
        """
        self._marker = marker
        raise NotImplementedError


class DataMarker(Marker):
    def __init__(self, marker: M) -> None:
        """
        Args:
            marker (M): The SinkMarker object
        """
        self._marker = marker
        assert isinstance(self._marker, SinkMarker)
        self._vd_node = marker.marker
        assert isinstance(self._vd_node, VDNode)
        self._block = marker.block

        self.vex_stmt_idx = resolve_data_marker(block=self._block, vd_node=self._vd_node)
    
    