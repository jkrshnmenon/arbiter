import os
import re
import json
import time
import angr
import logging
from ..target import SA1_Target
from ..utils import FatalError
from .sa_base import StaticAnalysis

logger = logging.getLogger(name=__name__)


class SA_Recon(StaticAnalysis):
    '''
    A class which performs the basic static analysis
    Analyse the function at func_addr and search for calls to sinks
    '''
    def __init__(self, p, sinks, maps={}, json_dir=None):
        '''
        :param p:           The angr Project instance
        :param sinks:       A list of sinks to look for
        :param maps:        A dictionary that maps the functions to the
                            argument description as provided in utils.py
        '''
        super(SA_Recon, self).__init__(p)

        self.map = {}
        self._statistics = {}
        self._verbose = True if json_dir is not None else False
        self._json_dir = json_dir

        for x in sinks:
            if x in maps.keys():
                self.map[x] = maps[x]
            elif x in self.utils.func_map.keys():
                self.map[x] = self.utils.func_map[x]
            else:
                logger.error("I don't know the arguments for %s" % x)
                raise FatalError

        for x in self.map.keys():
            if self._is_ret(self.map[x]):
                continue
            elif 'n' not in self.map[x]:
                logger.error("""Please specify the argument to be tracked for \
                the sinks %s by denoting it as `n`""" % x)
            elif self.map[x].count('n') > 1:
                logger.warn("Multiple arguments specified for sink %s" % x)
                logger.warn("Defaulting to use the first one")

        logger.debug("Creating CFG")
        start_time = time.time()
        try:
            self._cfg = self._project.analyses.CFG()
        except AttributeError:
            logger.error("Cannot create CFG")
            raise FatalError
        end_time = time.time()

        self._statistics['cfg_creation'] = int(end_time - start_time)
        self._statistics['cfg_blocks'] = len(self._cfg.graph.nodes())
        self._statistics['cfg_edges'] = len(self._cfg.graph.edges())
        self._statistics['recovered_functions'] = len(self._cfg.functions.items())
        self._statistics['identified_functions'] = 0
    
    def __str__(self):
        return f"SA_Recon(project={self.project}, sinks={self.sinks}, maps={self.map}, targets={len(self.targets)})"

    def _dump_stats(self):
        '''
        Print some numbers about this step of the analysis
        Should be invoked only after analyze
        '''
        if not self._verbose:
            return

        with open(f'{self._json_dir}/Recon.json', 'w') as f:
            json.dump(self._statistics, f, indent=2)

    def _is_ret(self, arglist):
        return 'r' in arglist

    @property
    def sinks(self):
        return self.map.keys()

    def _check_callees(self, func, target, sinks):
        """
        Check the `func` in the `target` for any call to any function name in set `sinks`
        """

        for site in sorted(func.get_call_sites()):
            name = self._callee_name(func, site)

            for callee in sinks:
                if callee not in name:
                    continue
                arglist = self.map[callee]

                if self._is_ret(arglist):
                    logger.debug("Finding ret block for %s @ 0x%x" % (callee, site))
                    site = self._find_ret_block(func)
                    if site is None:
                        # No ret instruction
                        continue

                target.add_node(site, None, self._cfg, arglist)

    def _check_sinks(self, func):
        target = SA1_Target(func)

        self._check_callees(func, target, self.sinks)

        if target.node_count > 0:
            self._targets.append(target)
            return True

        return False
    
    def analyze_one(self, identifier):
        func = None

        if isinstance(identifier, int):
            func = self._cfg.functions.function(identifier)
            addr = identifier
        elif isinstance(identifier, str):
            for a, f in self._cfg.functions.items():
                if f.name == identifier:
                    func = f
                    addr = a
                    break

        if func is None:
            logger.error("Could not find function for %s" % identifier)
            return

        logger.info("Starting recon of 0x%x" % addr)
        try:
            if self._check_sinks(func) is True:
                logger.debug('Adding target function %s:0x%x' % (func.name,
                                                                 addr))
        except angr.AngrCFGError as e:
            logger.error(e)
            return

    def analyze(self):
        for addr, func in self._cfg.functions.items():
            logger.info("Starting recon of 0x%x" % addr)
            try:
                if self._check_sinks(func) is True:
                    logger.debug('Adding target function %s:0x%x' % (func.name,
                                                                     addr))
                    self._statistics['identified_functions'] += 1
            except angr.AngrCFGError as e:
                logger.error(e)
                continue

        self._dump_stats()
