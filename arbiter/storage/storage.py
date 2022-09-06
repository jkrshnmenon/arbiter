import angr
from typing import Union, Type, Optional, Iterable

from .control_flow_detection import *
from .data_flow_detection import *
from ..spec import V

from ..utils import *

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
    
    def dbg_pp(self):
        output = ""
        output += f"[*] Project={self.project}\n"
        output += f"[*] VD: \n"
        output += f"{self.vd}\n"
        output += f"[*] Results: \n"
        for x in self._results:
            output += f"[*] RESULT <{x}>\n"
            for idx, y in enumerate(self._results[x]):
                output += f"[{idx}] : \n{y}\n"
        print(prGreen(output))
        

    def iter_sinks(self) -> Iterable[S]:
        for thing in self._results[SINK]:
            yield thing

    def _add_sinkflow(self, thing: S) -> None:
        self._results[SINK].append(thing)

    def add_result(self, thing: X) -> None :
        if isinstance(thing, SinkFlow):
            self._add_sinkflow(thing)

