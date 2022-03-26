import os
import json
import time
import angr
import signal
import claripy
import logging
import traceback
import threading
import networkx as nx
from ..target import *
from archinfo import Endness
from .sa_base import StaticAnalysis
from ..utils import Utils, FatalError
from .sa_advanced import SA_Adv

logger = logging.getLogger(name=__name__)


class SymExec(StaticAnalysis, DerefHook):
    '''
    A class which performs symbolic execution on the target function.
    If the advanced static analysis was able to detect a source for the input,
    use that to create a state.
    '''
    def __init__(self, sa, constrain, require_dd=None, json_dir=None):
        '''
        :param sa           :The SA_Adv object
        :param constrain    :A function that takes in a state, the expression
                            representing the argument and a list of expressions
                            that influence the final expression.
                            This function should apply the constraints on the
                            list of expressions that indicate the presence of a
                            bug
        :param require_dd   :A boolean that tells Arbiter to discard situations
                            without data dependency between initial and final
                            expressions
        '''
        self.sa = sa
        self.constrain = constrain
        super(SymExec, self).__init__(sa.project)
        self._targets = sa.targets
        self.sinks = sa.sinks
        self._cfg = sa.cfg
        self._require_dd = sa._require_dd if require_dd is None else require_dd
        self._verbose = True if json_dir is not None else False
        self._json_dir = json_dir

        self._statistics = {}
        self._stats_filename = 'UCSE.json'
        self._statistics['identified_functions'] = len(self._targets)

        # Used to synchronize with the watchdog
        self._watchdog_event = threading.Event()

        if len(self._targets) <= 0:
            raise FatalError("No targets for SymExec")

        self._set_up_hooks()
        signal.signal(signal.SIGALRM, self._signal_handler)

        self.reports = {}

    def __str__(self):
        return f"SymExec(project={self._project}, targets={len(self.targets)}, reports={len(self.reports)})"

    @staticmethod
    def mem_derefs(state):
        if state.globals.get('derefs', 0) == 0:
            return []
        else:
            return state.globals['derefs']

    def _dump_stats(self):
        '''
        Print some numbers about this step of the analysis
        Should be invoked only after run_all
        '''
        if not self._verbose:
            return

        with open(f'{self._json_dir}/{self._stats_filename}', 'w') as f:
            json.dump(self._statistics, f, indent=2)

    def _watchdog(self, timeout):
        logger.debug(f"Watchdog started, waiting for {timeout}s")
        # When we timeout, Event.wait will return False
        if not self._watchdog_event.wait(timeout):
            logger.debug(f"Watchdog timed out, sending SIG_ALARM to self")
            os.kill(os.getpid(), signal.SIGALRM)

    def _hook_checkpoint(self, target, cname):
        cfunc = self.cfg.functions.get(cname)
        if cfunc is None:
            logger.warn(f"Could not hook checkpoint {cname}")
            return
        if self._project.is_hooked(cfunc.addr):
            return
        self._project.hook(cfunc.addr, CheckpointHook(kwargs={'arg_num': target.source[cname]}))
        logger.debug(f'Hooked checkpoint {cname}')

    def _set_up_hooks(self):
        self._project.hook_symbol('strlen', StrlenHook())
        self._project.hook_symbol('strchr', StrchrHook())
        self._project.hook_symbol('getenv', GetenvHook())

        funcs = ['strdup', 'gettext', 'dcgettext', 'dgettext']

        for x in funcs:
            self._project.hook_symbol(x, FirstArgHook())

    def _set_up_bp(self, state):
        state.inspect.b('mem_read', when=angr.BP_AFTER,
                        action=self._mem_read_hook)
        state.inspect.b('mem_write', when=angr.BP_BEFORE,
                        action=self._mem_write_hook)

        return state

    def _signal_handler(self, signum, frame):
        logger.debug("Signal handler invoked")
        raise TimeoutException("Timeout", errors="Timed out")

    def _first_bbl(self, state):
        return list(state.history.bbl_addrs)[0]

    def _eliminate_false_positives(self, expr, init_val, state):
        # TODO : Generalize for all archs instead of just x64
        # The false positive occurs when all the bits in init_vals are not
        # present in the expr
        children = [x for x in set(expr.recursive_children_asts) if x.symbolic]

        if len(children) <= 1:
            return

        for x in init_val:
            upper = 0
            flag = False
            for y in children[::-1]:
                if type(y) != claripy.ast.bv.BV:
                    continue
                elif x.length == y.length:
                    result = x == y
                    if result.is_true():
                        flag = True
                        continue
                elif self._find_child_in_list(y, [x]) is False:
                    continue
                for z in range(y.length-1, 0, -1):
                    idx = self._find_bit_in_ast(y[z], x)
                    if idx is not None:
                        upper = max(upper, idx)
                        break
                if upper == self.project.arch.bits - 1:
                    break
                elif upper == 0 and flag is True:
                    upper = self.project.arch.bits - 1
                    break
                elif upper >= self.project.arch.bits:
                    upper = self.project.arch.bits - 1
                    break
            if upper >= 32 and upper < 64:
                upper = 63
            elif upper >= 0 and upper < 32:
                upper = 31

            logger.debug("Max used bit : %d" % (upper+1))
            state.solver.add(x <= 2**(upper+1) - 1)

    def _apply_sz_constraints(self, state, expr, site, obj):
        val = None
        init_val = state.globals.get('sym_vars')

        self._eliminate_false_positives(expr, init_val, state)

        s = self.constrain(state=state, expr=expr, init_val=init_val, site=site)
        if s is not None:
            state = s

        obj['sat_states'] = 0
        for x in init_val:
            try:
                val = state.solver.eval(x)
                logger.info("Satisfied state : 0x%x" % val)
                obj['sat_states'] += 1
                self._dump_stats()
                if site.bbl not in self.reports.keys():
                    self.reports[site.bbl] = Report(state, site)
            except angr.SimUnsatError:
                val = None
                logger.info("Got Unsat")

        if len(init_val) == 0:
            if state.satisfiable():
                val = state.solver.eval(expr)
                logger.info("Satisfied state: 0x%x" % val)
                obj['sat_states'] += 1
                self._dump_stats()
                if site.bbl not in self.reports.keys():
                    self.reports[site.bbl] = Report(state, site)
            else:
                val = None
                logger.info("Got Unsat")

        return val is not None

    def _check_state(self, state, site, target=None, obj=None):
        if obj is None:
            assert target is not None
            obj = self._statistics[target.addr]

        sym_vars = state.globals.get('sym_vars', 0)
        obj['expressions_tracked'] = len(sym_vars)
        name = site.callee
        if name == "EOF":
            arg_num = [0]
        elif any([x for x in self.sinks if x in name]):
            arg_num = [site.sz]
        else:
            raise angr.AngrAnalysisError("New condition for %s" % name)

        assert len(arg_num) >= 1, "No args for %s" % name
        new_expr = None
        filtered_sym_vars = []

        if target is not None:
            new_expr = target.expr_from_state(self._project, state, arg_num[0])
        if new_expr is None:
            new_expr = self._nth_arg(state, arg_num[0])

        if len(sym_vars) > 1:
            filtered_sym_vars = []
            for child in list(set(new_expr.recursive_leaf_asts)):
                if self._find_in_list(child, sym_vars):
                    filtered_sym_vars.append(child)
            if len(filtered_sym_vars) == 0 and self._require_dd is False:
                filtered_sym_vars = sym_vars
        else:
            # Double checking the result of SA_advanced
            # At least one of the leaf ast of new_expr should be in sym_vars
            if self._find_child_in_list(new_expr, sym_vars) is False:
                logger.warn("Couldn't find expression in sym vars")
                if self._require_dd is True:
                    self._dump_stats()
                    return

            filtered_sym_vars = sym_vars

        obj['filtered_expressions'] = len(filtered_sym_vars)

        state.globals['sym_vars'] = filtered_sym_vars

        logger.info("Applying constraints for sink : %s" % name)

        self._dump_stats()
        return self._apply_sz_constraints(state, new_expr, site, obj)

    def _explore_one(self, target, site, init_state):
        self._statistics[target.addr]['paths_found'] = 0
        self._statistics[target.addr]['paths_timedout'] = 0
        try:
            block = target.cfg.get_any_node(site.bbl).block
        except AttributeError:
            logger.warn("Could not find target sink")
            return
        name = site.callee

        if name == "EOF":
            init_state.globals['track_write'] = True
        pg = self._project.factory.simulation_manager(init_state)
        counter = 0
        start = time.time()
        logger.info("Starting exploration 0x%0x => 0x%0x" % (init_state.addr, site.bbl))
        self._watchdog_event.clear()

        t = threading.Thread(target=self._watchdog, args=(300,))
        t.start()
        try:
            pg.explore(find=sorted(block.instruction_addrs)[-1])

            if len(pg.found) == 0:
                self._watchdog_event.set()
                t.join()
                raise angr.AngrAnalysisError("No paths found")

            if len(pg.active) == 0:
                logger.debug("Found %d paths; No active paths" % len(pg.found))
                self._statistics[target.addr]['paths_found'] += len(pg.found)
                for pp in pg.found:
                    self._watchdog_event.set()
                    if self._check_state(pg.found[0], site, target) is True:
                        logger.debug("Waiting for watchdog to join")
                        t.join()
                        return

            while len(pg.active) > 0 and counter < 3:
                logger.debug("Found %d paths; active paths remaining" % len(pg.found))
                counter += len(pg.found)
                self._statistics[target.addr]['paths_found'] += len(pg.found)
                end = time.time()
                self._statistics[target.addr]['exploration_time'] = int(end - start)
                for pp in pg.found:
                    if self._check_state(pp, site, target):
                        self._watchdog_event.set()
                        logger.debug("Waiting for watchdog to join")
                        t.join()
                        return
                pg.drop(stash='found')
                # adamd: I don't know if this is necessary, the watchdog should be able to wake us up
                #signal.alarm(300)
                logger.debug("Wrapping up %d active paths" % len(pg.active))
                pg.explore(find=sorted(block.instruction_addrs)[-1])
        except (TimeoutException, KeyboardInterrupt) as e:
            self._watchdog_event.set()
            logger.debug("Waiting for watchdog to join")
            t.join()
            logger.debug("Got an exception")
            self._statistics[target.addr]['paths_timedout'] += 1
            logger.error(e)

        end = time.time()
        logger.debug("Found %d paths" % len(pg.found))
        self._statistics[target.addr]['exploration_time'] = int(end - start)
        self._statistics[target.addr]['paths_found'] += len(pg.found)
        for pp in pg.found:
            self._check_state(pp, site, target)

        self._watchdog_event.set()
        logger.debug("Waiting for watchdog to join")
        t.join()
        del init_state
        del pg

    def _create_ret_states(self, target, name):
        sources = []
        states = []
        for x in target.func.get_call_sites():
            if name == self._callee_name(target.func, x):
                return_addr = target.func.get_call_return(x)
                if return_addr == x:
                    b = self.cfg.model.get_any_node(x).block
                    sources.append(b.addr+b.size)
                else:
                    sources.append(target.func.get_call_return(x))
                logger.debug("Adding checkpoint address %s:0x%0x" % (name, sources[-1]))

        for addr in set(sources):
            s = self._project.factory.blank_state(addr=addr)
            expr = claripy.BVS('ret', self.utils.arch.bits)
            setattr(s.regs, self.utils.arch.register_names[self.utils.ret_reg],
                    expr)
            s.globals['sym_vars'] = [expr]
            s.globals['derefs'] = []
            states.append(self._set_up_bp(s))

        return states

    def _create_checkpoint_states(self, target, name):
        sources = []
        states = []
        for x in target.func.get_call_sites():
            if name == self._callee_name(target.func, x):
                bl = target.cfg.get_any_node(x)
                sources.append(sorted(bl.instruction_addrs)[-1])
                logger.debug("Adding checkpoint address %s:0x%0x" % (name, sources[-1]))

        for addr in set(sources):
            s = self._project.factory.blank_state(addr=target.addr)
            sm = self._project.factory.simulation_manager(s)
            sm.explore(find=addr)
            states += sm.found

        for state in states:
            arg_num = target.source[name]
            expr = target.expr_from_state(self._project, state, arg_num)

            if expr is None:
                expr = self._nth_arg(state, arg_num)

            if len(list(expr.recursive_leaf_asts)) > 1:
                logger.info('Checkpoint parameter is a composite AST.')
                logger.info('This might lead to incorrect results.')

            state.globals['sym_vars'] = [expr]
            state.globals['derefs'] = []
            self._set_up_bp(state)

        return states

    def _get_checkpoint_state(self, target, site):
        logger.debug("Creating checkpoint states for %s" % target.name)
        states = []
        if not isinstance(target.source, dict):
            logger.debug("No checkpoint present")
            return states
        for x in target.source:
            if target.checkpoint_is_ret(x):
                states += self._create_ret_states(target, x)
            else:
                states += self._create_checkpoint_states(target, x)
            self._hook_checkpoint(target, x)

        logger.debug("Created %d states" % len(states))
        return states

    def _create_entry_state(self, target, site):
        logger.debug("Creating initial state for %s" % target.name)
        sym_vars = []
        if site.source is None:
            for x in range(10):
                sym_vars.append(claripy.BVS('var_'+str(x),
                                            self.utils.arch.bits))
            init_state = self._project.factory.call_state(target.addr,
                                                          *sym_vars)
        else:
            exprs = []
            for x in range(site.source - 1):
                exprs.append(claripy.BVS('var_'+str(x), self.utils.arch.bits))
            sym_vars = [claripy.BVS('src', self.utils.arch.bits)]
            init_state = self._project.factory.call_state(target.addr,
                                                          *(exprs+sym_vars))

        init_state.globals['sym_vars'] = sym_vars
        init_state.globals['derefs'] = []
        return self._set_up_bp(init_state)

    def _execute_one(self, target, site):
        if target.source == target.addr and site.callee != 'EOF':
            # Case 1
            if 'entry_state' not in self._statistics[target.addr]:
                self._statistics[target.addr]['entry_state'] = 0
            self._statistics[target.addr]['entry_state'] += 1
            init_state = self._create_entry_state(target, site)
            self._explore_one(target, site, init_state)
        else:
            if 'checkpoint_state' not in self._statistics[target.addr]:
                self._statistics[target.addr]['checkpoint_state'] = 0
            self._statistics[target.addr]['checkpoint_state'] += 1
            init_states = self._get_checkpoint_state(target, site)
            for x in init_states:
                try:
                    self._explore_one(target, site, x)
                except angr.AngrAnalysisError as e:
                    logger.exeception(e)
                    continue

    def run_one(self, target):
        for x in target.nodes:
            try:
                self._statistics[target.addr] = {}
                self._execute_one(target, target._nodes[x])
            except angr.AngrAnalysisError as e:
                logger.exception(e)
                continue
            except (KeyboardInterrupt, AssertionError, AttributeError) as e:
                logger.exception(e)
                continue

    def run_all(self):
        for x in self._targets:
            self.run_one(x)

        self._dump_stats()


    def _blocks_in_func(self, func, call_sites):
        func_blocks = []
        snode = func.get_node(func.addr)
        for addr in call_sites:
            cur_blocks = []
            tnode = func.get_node(addr)
            if tnode is None:
                continue

            if nx.has_path(func.graph, snode, tnode) is False:
                continue

            cur_blocks = [x.addr for x in func.graph.nodes if
                          nx.has_path(func.graph, snode, x) and
                          nx.has_path(func.graph, x, tnode)]

            func_blocks += cur_blocks

        return list(set(func_blocks))

    def _get_blocks_between(self, src, dst):
        funcs = []
        blocks = []
        call_sites = []
        avoid_blocks = []
        callgraph = self.cfg.kb.callgraph

        if nx.has_path(callgraph, src, dst) is False:
            logger.error("No path from 0x%x to 0x%x" % (src, dst))
            return None, None

        funcs = [x for x in callgraph.nodes if nx.has_path(callgraph, src, x)
                 and nx.has_path(callgraph, x, dst)]

        if len(funcs) == 0:
            logger.error("No functions found")
            return None, None

        for addr in funcs:
            if addr == dst:
                continue
            func = self.cfg.functions.function(addr)
            if func is None:
                continue

            call_sites = [x for x in func.get_call_sites()
                          if func.get_call_target(x) in funcs]

            find_blocks = self._blocks_in_func(func, call_sites)
            avoid_blocks += func.block_addrs_set - set(find_blocks)
            blocks = list(set(blocks+find_blocks))

        return list(set(blocks)), list(set(avoid_blocks))

    def _get_call_paths(self, func_addr, level):
        if level == 0:
            # start from main
            main = self.cfg.functions.function(name='main')
            if main is None:
                if self._project.arch.bits == 64:
                    try:
                        f = self.cfg.functions.function(self._project.entry)
                        assert f is not None
                        name = self._callee_name(f, self._project.entry)
                    except angr.AngrCFGError:
                        logger.error('Could not identify call target')
                        name = ''
                    except AssertionError:
                        logger.error("Could not find _start")
                        name = ''
                    if name == '__libc_start_main':
                        bbl = self.cfg.get_any_node(f.addr)
                        idx = self.get_target_ins(bbl, 1)
                        rhs = bbl.block.vex.statements[idx].data
                        starts = [rhs.constants[0].value]
                        self.cfg.functions.function(starts[0]).name = 'main'
                    else:
                        # Probably a shared object.
                        logger.error("Couldn't find main.")
                        logger.error(name)
                        starts = [self._project.entry]
                else:
                    logger.error("Not implemented yet")
                    starts = [self._project.entry]
            else:
                starts = [main.addr]
        else:
            # Get callers from call stack
            starts = [func_addr]
            preds = []
            for y in range(level):
                for x in starts:
                    z = list(self.cfg.kb.functions.callgraph.predecessors(x))
                    preds = list(set(preds+z))
                if len(preds) == 0:
                    break
                starts = preds
                preds = []

        block_dict = {}
        for src in set(starts):
            if self._cfg.functions.function(src).name == 'main':
                continue
            x, y = self._get_blocks_between(src, func_addr)
            if x is None:
                continue
            block_dict[src] = {}
            block_dict[src]['find'] = x
            block_dict[src]['avoid'] = y

        return block_dict

    def _reach_sink(self, state, report):
        args = []
        new_args = []
        sym_vars = []
        second_target = report.state.addr

        if report.site.source is not None:
            # Account for saved PC
            args = [self._nth_arg(state, report.site.source, saved_pc=True)]
            for x in range(report.site.source - 1):
                new_args.append(self._nth_arg(state, x+1, saved_pc=True))
        else:
            for x in range(10):
                args.append(self._nth_arg(state, x+1))

        for x in args:
            sym_arg = claripy.BVS('arg', self.utils.arch.bits)
            state.solver.add(sym_arg == x)
            sym_vars.append(sym_arg)
            new_args.append(sym_arg)

        new_state = self._project.factory.call_state(state.addr,
                                                     *new_args,
                                                     base_state=state)
        new_state.globals['sym_vars'] = state.globals.get('sym_vars', [])
        new_state.globals['sym_vars'].extend(sym_vars)
        new_state.globals['derefs'] = []
        new_state.globals['no_create'] = True
        new_state = self._set_up_bp(new_state)

        sm = self._project.factory.simulation_manager(new_state)
        logger.info("Starting exploration to sink @ 0x%x" % report.sink)
        sm.explore(find=second_target)

        return sm.found

    def verify_one(self, report, start, block_dict):
        avoid = block_dict['avoid']
        first_target = self._cfg.functions.floor_func(report.state.addr)

        if first_target is None:
            logger.error("Could not find the function for 0x%x" % report.state.addr)

        assert first_target.addr != start, "Not a caller function"

        self._statistics[first_target.addr][start] = {}
        logger.info("Starting verification from 0x%x" % start)
        init_state = self._project.factory.blank_state(addr=start)

        if self.cfg.functions.function(start).name == 'main':
            # ARG_MAX
            if self.utils.arch.bits == 64:
                init_state.solver.add(init_state.regs.rdi < 0x200000)

        final_states = []
        sat_states = []

        pg = self._project.factory.simulation_manager(init_state)
        self._watchdog_event = threading.Event()
        t = threading.Thread(target=self._watchdog, args=(600,))
        t.start()
        try:
            logger.info("Starting exploration to 0x%x" % first_target.addr)
            start_time = time.time()
            pg.explore(find=first_target.addr, avoid=avoid)

            self._statistics[first_target.addr][start]['paths_from_callers'] = len(pg.found)
            assert len(pg.found) > 0, "No paths found"

            end = time.time()
            logger.debug("Found %d paths" % len(pg.found))
            self._statistics[first_target.addr][start]['exploring_callers'] = int(end - start_time)
            self._watchdog_event.set()
            t.join()

            self._watchdog_event.clear()
            t = threading.Thread(target=self._watchdog, args=(600,))
            t.start()
            start_time = time.time()
            for pp in pg.found:
                final_states += self._reach_sink(pp, report)

            self._statistics[first_target.addr][start]['paths_to_sink'] = len(final_states)
            assert len(final_states) > 0, "No paths found"

            end = time.time()
            self._statistics[first_target.addr][start]['reaching_sink'] = int(end - start_time)
            logger.debug("Found %d states" % len(final_states))

            self._watchdog_event.set()
            t.join()
            for state in final_states:
                if self._check_state(state, report.site, None, self._statistics[first_target.addr][start]) is True:
                    sat_states.append(state)
        except (TimeoutException, KeyboardInterrupt, AssertionError) as e:
            self._watchdog_event.set()
            t.join()
            logger.debug("Got an exception")
            logger.error(e)

        if len(sat_states) == 0:
            return None

        # output = {'function': first_target.addr, 'bbl': report.site.bbl,
        #           'bbl_history': list(sat_states[0].history.bbl_addrs),
        #           'callstack': [x.current_function_address for x in sat_states[0].callstack]
        #           }
        output = ArbiterReport(bbl=report.site.bbl, function=first_target.addr,
                                bbl_history=list(sat_states[0].history.bbl_addrs),
                                function_history=[x.current_function_address for x in sat_states[0].callstack])
        if report.site.callee == 'EOF':
            # output['bbl'] = self._first_bbl(report.state)
            output.bbl = self._first_bbl(report.state)
        return output

    def convert_reports(self):
        TP = []
        for sink in self.reports:
            report = self.reports[sink]
            try:
                func_addr = self._cfg.functions.floor_func(report.state.addr).addr
            except AttributeError:
                func_addr = 0
            bbl_history = list(report.state.history.bbl_addrs)
            TP.append(ArbiterReport(sink, func_addr, bbl_history, [func_addr]))

        return TP

    def verify(self, report, blocks):
        output = None
        for x in blocks:
            try:
                output = self.verify_one(report, x, blocks[x])
                if output is not None:
                    break
            except AssertionError as e:
                self._watchdog_event.set()
                logger.error(e)
                continue

        return output

    def postprocessing(self, pred_level=1):
        '''
        Return a list of ArbiterReport's
        '''
        if pred_level == -1:
<<<<<<< HEAD
            TP = self.convert_reports()
            return
=======
            return self.convert_reports()
>>>>>>> bc6c263 (modifying arguments to constrain function)

        logger.info("Starting postprocessing")
        self._stats_filename = 'FP.json'
        TP = []

        self._statistics = {}
        self._statistics['satisfied_states'] = len(self.reports)
        if len(self.reports) == 0:
            logger.error("No targets for postprocessing")
            return

        signal.alarm(0)
        symbols = ['strlen', 'strchr']
        for x in symbols:
            if self._project.is_symbol_hooked(x):
                self._project.unhook_symbol(x)
                self._project.hook_symbol(x, angr.SIM_PROCEDURES['libc'][x]())

        symbols = ['strdup', 'getenv']
        obj = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']()
        for x in symbols:
            if self._project.is_symbol_hooked(x):
                self._project.hook_symbol(x, obj)

        func_sink_map = {}
        for sink in self.reports:
            report = self.reports[sink]
            try:
                func_addr = self._cfg.functions.floor_func(report.state.addr).addr
            except AttributeError:
                if self._cfg.functions.floor_func(report.state.addr) is None:
                    logger.error("Could not find function 0x%x" % report.state.addr)
                    continue
            if func_addr not in func_sink_map:
                func_sink_map[func_addr] = []
            func_sink_map[func_addr].append(report)

        for func_addr in func_sink_map:
            self._statistics[func_addr] = {}
            logger.info("Finding callers for function @ %#x" % func_addr)
            blocks = self._get_call_paths(func_addr, pred_level)
            if len(blocks) == 0:
                logger.error("No paths to function @ 0x%x" % func_addr)
                continue

            if len(blocks) == 1 and func_addr in blocks.keys():
                logger.error("No callers found for func @ 0x%x" % func_addr)
                continue

            self._statistics[func_addr]['callers'] = len(blocks)
            for report in func_sink_map[func_addr]:
                is_tp = self.verify(report, blocks)
                if is_tp is not None:
                    TP.append(is_tp)
            logger.info("Done with function @ %#x" % func_addr)

        logger.info("Finished postprocessing")

        self._dump_stats()

        return TP



class TimeoutException(Exception):
    def __init__(self, message, errors):
        super(TimeoutException, self).__init__(message)
        self.errors = errors
