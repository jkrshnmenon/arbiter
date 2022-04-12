import json
import angr
import claripy
import logging
import threading

from tqdm import tqdm

from ..target import *
from ..utils import FatalError
from .sa_base import StaticAnalysis


logger = logging.getLogger(name=__name__)



class Pensieve(StaticAnalysis, ConstraintHook):
    '''
    Replay reports from SymExec to identify target instructions
    '''
    def __init__(self, se, json_dir=None):
        '''
        :param se           :The SymExec object
        '''
        self.se = se
        super(Pensieve, self).__init__(se.project)
        self.replay_targets = se.verified_reports

        self._verbose = True if json_dir is not None else False
        self._json_dir = json_dir
        self._statistics = {}

        self._statistics['replay_targets'] = len(self.replay_targets)

        if len(self.replay_targets) <= 0:
            raise FatalError("No targets for replay analysis")
        
        self.memories = {}
    

    def _add_to_memories(self, report, obj):
        self.memories[report.bbl] = obj

    
    def replay_one(self, report):
        sink_addr = report.bbl
        func_addr = report.function
        pass
    
    def replay_all(self):
        for report in self.verified_reports:
            obj = self.replay_one(report)
            self._add_to_memories(report, obj)

