import json
import angr
import claripy
import logging
import threading

from tqdm import tqdm

from ..target import *
from ..utils import FatalError
from .symbolic_execution import SymExec


logger = logging.getLogger(name=__name__)



class Pensieve(SymExec, ConstraintHook):
    '''
    Replay reports from SymExec to identify target instructions
    '''
    def __init__(self, se, json_dir=None):
        '''
        :param se           :The SymExec object
        '''
        self.se = se
        super(Pensieve, self).__init__(se.project)

        self._verbose = True if json_dir is not None else False
        self._json_dir = json_dir
        self._statistics = {}

        self.replay_targets = []
        for x in self.se.reports:
            sa_obj = self._target_from_addr(self.func_from_state(x.state))
            self.replay_targets.append(PensieveObj(x, sa_obj))

        self._statistics['replay_targets'] = len(self.replay_targets)
        if len(self.replay_targets) <= 0:
            raise FatalError("No targets for replay analysis")
        
        self.memories = {}
    

    def _check_state(self, state, site, target=None, obj=None):
        return

    def _set_up_bp(self, state):
        pass

    def _add_to_memories(self, obj, output):
        self.memories[obj.bbl] = output

    
    def replay_one(self, obj):
        for state in self.generate_states(obj.sa_obj, obj.sym_report.site):
            self._explore_one(obj.sa_obj, obj.sym_report.site, state)
        pass
    
    def replay_all(self):
        for obj in self.replay_targets:
            output = self.replay_one(obj)
            self._add_to_memories(obj, output)

