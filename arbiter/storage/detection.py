import angr
from typing import Union, Type, Optional, TypeVar

from ..spec import N

B = Type[angr.block.Block]
F = Type[angr.knowledge_plugins.functions.function.Function]



class Marker(object):
    def __init__(self, marker: N):
        """
        Base class for storing results from Arbiter analysis steps
        """
        self._marker = marker
        raise NotImplementedError

    @property
    def marker(self) -> N:
        return self._marker

    @property
    def sinks(self) -> Optional[N]:
        if self.marker.is_sink:
            return self.marker

    @property
    def sources(self) -> Optional[N]:
        if self.marker.is_source:
            return self.marker



class SinkMarker(Marker):
    def __init__(self, node: N, block: B, function: F) -> None:
        self._marker = node
        self._block = block
        self._function = function

    def __str__(self) -> str:
        return f"{str(self.marker)} in {hex(self.function.addr)} @ {hex(self.block.addr)}"

    @property
    def block_addr(self) -> int:
        return self._block.addr

    @property
    def block(self) -> B:
        return self._block

    @property
    def function_addr(self) -> int:
        return self._function.addr

    @property
    def function(self) -> F:
        return self._function


M = Type[SinkMarker]



class SinkFlow(Marker):
    def __init__(self, path: list[Type[M]]) -> None:
        self._marker = path

    def __str__(self) -> str:
        out = ">>>>>>>>\n"
        for node in self.marker:
            out += "--------\n"
            out += f"{str(node)}\n"
            out += "--------\n"
        out += "<<<<<<<<\n"
        return out

    @property
    def sinks(self) -> list:
        return [x for x in self.marker if x.is_sink is True]

    @property
    def sources(self) -> list:
        return [x for x in self.marker if x.is_source is True]


S = Type[SinkFlow]
