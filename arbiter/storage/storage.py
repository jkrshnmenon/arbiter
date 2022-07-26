from optparse import Option
import angr
from typing import Union, Type, Optional, Iterable

from .detection import *

from ..spec import V

P = Type[angr.project.Project]
C = Type[angr.analyses.cfg.cfg.CFG]
K = Type[angr.knowledge_base.knowledge_base.KnowledgeBase]
X = Union[S, M]

SINK = 'sink'
FLOW = 'flow'
EXEC = 'exec'
REDUCE = 'reduce'



class Storage(object):
    def __init__(self, project: Optional[P] = None,
                vd: Optional[V] = None, cfg : Optional[C] = None,
                kb : Optional[K] = None) -> None :
        self.project = project
        self.vd = vd
        self.cfg = cfg
        self.kb = kb
        self._results = {}.fromkeys([SINK, FLOW, EXEC, REDUCE])
        for key in self._results:
            self._results[key] = []

    def iter_sinks(self) -> Iterable[S]:
        for thing in self._results[SINK]:
            yield thing

    def _add_sinkflow(self, thing: S) -> None:
        self._results[SINK].append(thing)

    def add_result(self, thing: X) -> None :
        if isinstance(thing, SinkFlow):
            self._add_sinkflow(thing)



S = Type[Storage]