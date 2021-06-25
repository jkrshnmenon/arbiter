import os
import re
import json
import time
import angr
import logging
from ..utils import Utils, FatalError, DataDependencyError, ConstantDataError
from ..target import SA2_Target
from angr.sim_options import refs
from .sa_base import StaticAnalysis

logger = logging.getLogger('SA_advanced')


class SA_Adv(StaticAnalysis):
    def __init__(self, sa_recon, checkpoint={}, require_dd=True, call_depth=None, verbose=False):
        '''
        :param sa_recon:        The StaticAnalysisRecon object
        :param checkpoint       A dictionary that maps a function name to the
                                variable that ends up being used in the sink
                                [0 for return value and 1-n for arguments]
        '''
        self.sa_recon = sa_recon
        super(SA_Adv, self).__init__(sa_recon.project)

        self._statistics = {}

        self._checkpoint = {} 
        for x in checkpoint:
            name = x
            if x.startswith("SYS_"):
                name = x[len("SYS_"):]
                logger.info("Converting %s to %s" % (x, name))
            self._checkpoint[name] = checkpoint[x]

        self.map = sa_recon.map
        self._cfg = sa_recon.cfg
        self._targets = sa_recon.targets
        self._require_dd = require_dd
        self._call_depth = call_depth
        self._verbose = verbose

        self._statistics['identified_functions'] = len(self._targets)
        if len(self._targets) <= 0:
            self._dump_stats()
            raise FatalError("No targets for SA advanced")

        self._final_targets = []

    @property
    def sinks(self):
        return self.map.keys()

    @property
    def targets(self):
        return self._final_targets
    
    def _dump_stats(self):
        '''
        Print some numbers about this step of the analysis
        Should be invoked only after analyze_all
        '''
        with open(f'{os.path.basename(self._project.filename)}_DDA.json', 'w') as f:
            json.dump(self._statistics, f, indent=2)

    def get_slice_target(self, node, target):
        site = target.cfg.get_any_node(node.bbl)

        arg = node.sz

        return site, self.get_target_ins(site, arg)

    def _is_bp_write(self, target, bbl, idx):
        b = target.cfg.get_any_node(bbl).block
        stmt = b.vex.statements[idx]
        if self.utils.is_reg_write(stmt) is False:
            return False
        return self.utils.target_reg(stmt) == self.utils.name_to_vex('bp')

    def _parse_binop(self, stmt):
        treg = None
        val = 0
        for x in stmt.args:
            if self.utils.is_const(x):
                val = self.utils.target_const(x)
            elif self.utils.is_tmp_read(x):
                treg = self.utils.target_tmp(x)
        return treg, val

    def _find_tmp_write(self, treg, block, whitelist):
        '''
        This depends heavily on VEX
        Assumes that a temporary register will not be initialised outside a
        block in which it is used
        '''
        retval = None
        for idx in whitelist[::-1]:
            stmt = block.vex.statements[idx]
            if self.utils.is_tmp_write(stmt) is False:
                continue
            if self.utils.target_tmp(stmt) == treg:
                retval = idx
        assert retval is not None
        return retval

    def _find_reg_write(self, reg, block, whitelist):
        retval = None
        for idx in whitelist[::-1]:
            stmt = block.vex.statements[idx]
            if self.utils.is_reg_write(stmt) is False:
                continue
            if self.utils.target_reg(stmt) == reg:
                retval = self.utils.target_tmp(stmt.data)
                break

        if retval is not None:
            return self._find_tmp_write(retval, block,
                                        whitelist[:whitelist.index(idx)])

    def _find_tmp_store(self, treg, block, whitelist):
        retval = None
        for idx in whitelist[::-1]:
            stmt = block.vex.statements[idx]
            if self.utils.is_tmp_store(stmt) is False:
                continue
            if self.utils.target_tmp(stmt.addr) == treg:
                retval = self.utils.target_tmp(stmt.data)
                break

        if retval is not None:
            return self._find_tmp_write(retval, block,
                                        whitelist[:whitelist.index(idx)])

    def _handle_tmp_store(self, rhs, block, whitelist):
        if self.utils.is_const(rhs):
            raise ConstantDataError("Got constant value")
        treg = self.utils.target_tmp(rhs)
        return self._find_tmp_write(treg, block, whitelist)

    def _handle_reg_write(self, rhs, block, whitelist):
        if self.utils.is_const(rhs):
            raise ConstantDataError("Got constant value")
        treg = self.utils.target_tmp(rhs)
        return self._find_tmp_write(treg, block, whitelist)

    def _handle_tmp_write(self, rhs, block, whitelist):
        '''
        Three cases here
        1) tmp_reg1 = func(tmp_reg2) ; binop/unop
        2) tmp_reg1 = load(tmp_reg2)
        3) tmp_reg1 = GET(asm_reg)
        '''
        retval = None
        flag = False
        if self.utils.is_tmp_unop(rhs):
            flag = True
            if self.utils.is_const(rhs.args[0]):
                retval = None
            else:
                retval = self.utils.target_tmp(rhs.args[0])
        elif self.utils.is_tmp_binop(rhs):
            flag = True
            retval = None
            for x in rhs.args:
                if self.utils.is_tmp_read(x):
                    retval = self.utils.target_tmp(x)
                    break
        elif self.utils.is_tmp_read(rhs):
            retval = self.utils.target_tmp(rhs)
        elif self.utils.is_ite(rhs):
            if self.utils.is_tmp_read(rhs.iftrue):
                retval = self.utils.target_tmp(rhs.iftrue)
            elif self.utils.is_tmp_read(rhs.iffalse):
                retval = self.utils.target_tmp(rhs.iffalse)

        if retval is not None:
            return self._find_tmp_write(retval, block, whitelist)
        elif flag is True:
            raise ConstantDataError("Got constant value")

        if self.utils.is_reg_read(rhs):
            retval = self._find_reg_write(self.utils.target_reg(rhs), block,
                                          whitelist)
        elif self.utils.is_tmp_load(rhs):
            retval = self._find_tmp_store(self.utils.target_tmp(rhs.addr),
                                          block,
                                          whitelist)

        return retval

    def _handle_binop(self, rhs, block, whitelist):
        offset = 0
        treg, val = self._parse_binop(rhs)
        if self.utils.is_add(rhs):
            if val > 2 ** (self.utils.arch.bits - 2):
                val = -1 * ((2 ** self.utils.arch.bits) - val)
            offset += val
        elif self.utils.is_sub(rhs):
            if val > 2 ** (self.utils.arch.bits - 2):
                val = ((2 ** self.utils.arch.bits) - val)
            else:
                val = -1 * val
            offset += val
        else:
            pass
        return self._find_tmp_write(treg, block, whitelist), offset

    def _handle_unop(self, rhs, block, whitelist):
        treg = self.utils.target_tmp(rhs.args[0])
        return self._find_tmp_write(treg, block, whitelist)

    def _track_stack(self, stmt, target, cur_block):
        '''
        If we've reached here, it means that there was a load stmt without
        a corresponding store.
        It happens when an argument is passed via the stack
        Or when you pass a pointer as an argument
        '''
        b = target.cfg.get_any_node(cur_block).block
        acfg = target._bs.annotated_cfg()
        whitelist = acfg.get_whitelisted_statements(cur_block)
        idx = None
        for x in whitelist:
            tstmt = b.vex.statements[x]
            if self.utils.is_imark(tstmt):
                continue
            if tstmt.data == stmt:
                idx = x
                break
        idx = self._find_tmp_write(self.utils.target_tmp(stmt.addr), b,
                                   whitelist[:whitelist.index(idx)])
        filtered = whitelist[:whitelist.index(idx)+1]
        offset = 0
        while len(filtered) > 0:
            cur_idx = filtered.pop()
            cur_stmt = b.vex.statements[cur_idx]

            assert self.utils.is_tmp_write(cur_stmt)

            if self.utils.is_tmp_binop(cur_stmt.data):
                next_idx, val = self._handle_binop(cur_stmt.data, b,
                                                   filtered)
                offset += val
            elif self.utils.is_reg_read(cur_stmt.data):
                reg = self.utils.target_reg(cur_stmt.data)
                return offset, b.addr, cur_idx
            elif self.utils.is_tmp_load(cur_stmt.data):
                return offset, b.addr, cur_idx
            elif self.utils.is_tmp_read(cur_stmt.data):
                next_idx = self._handle_tmp_write(cur_stmt.data, b,
                                                  filtered)
            elif self.utils.is_tmp_unop(cur_stmt.data):
                next_idx = self._handle_unop(cur_stmt.data, b,
                                             filtered)
            else:
                raise angr.AngrAnalysisError("This should not have happened")

            filtered = filtered[:filtered.index(next_idx)+1]

    def _filter_preds(self, block, idx, target):
        rhs = block.vex.statements[idx].data
        dnode = target.get_any_ddg_node(block.addr, idx)
        preds = list(target.ddg.data_graph.predecessors(dnode))

        if self.utils.is_reg_read(rhs):
            treg = self.utils.target_reg(rhs)
            if treg == self.utils.ret_reg:
                sim_proc = None
                for node in preds:
                    if node.location.sim_procedure is not None:
                        sim_proc = node
                        # break here ??
                if sim_proc is not None:
                    # This sim_proc should've been called from the preceding
                    # bbl. Change my mind.
                    name = sim_proc.location.sim_procedure.display_name
                    if type(target.source) == int:
                        arg = self.utils.misc_src(name)
                        prev = target.prev_block(block.addr)
                        site = target.cfg.get_any_node(prev)
                        return prev, self.get_target_ins(site, arg)
                    else:
                        if name in target.source:
                            # Reached the return value of the checkpoint
                            return None, None
                        else:
                            try:
                                arg = self.utils.misc_src(name)
                            except KeyError:
                                raise DataDependencyError("Return value belongs to a different sim_proc")

                            prev = target.prev_block(block.addr)
                            site = target.cfg.get_any_node(prev)
                            return prev, self.get_target_ins(site, arg)

            for node in preds:
                stmt = target.stmt_from_ddg_node(node)
                taddr, tidx = node.location.block_addr, node.location.stmt_idx
                if self.utils.is_reg_write(stmt) is False:
                    continue
                elif taddr > block.addr:
                    continue
                elif taddr == block.addr and tidx >= idx:
                    continue
                elif self.utils.target_reg(stmt) == treg:
                    return node.location.block_addr, node.location.stmt_idx

        elif self.utils.is_tmp_load(rhs):
            flag = False
            retval = None
            for node in preds:
                stmt = target.stmt_from_ddg_node(node)
                taddr, tidx = node.location.block_addr, node.location.stmt_idx
                if self.utils.is_tmp_store(stmt):
                    flag = True
                    if taddr < block.addr:
                        retval = (taddr, tidx)
                        break
                    elif taddr == block.addr and tidx < idx:
                        retval = (taddr, tidx)
                        break

            if retval is not None:
                if type(target.source) == int:
                    return retval
                
                call_sites = [x for x in target.get_call_sites() if x < block.addr]
                callees = {x: self._callee_name(x) for x in call_sites}

                matches = []
                for x in target.source:
                    matches += list(filter(lambda y: x in y, callees))
                
                if len(matches) == 0:
                    return retval
                
            if flag is True:
                # Couldn't find a correct store stmt
                # Track the address of the store
                acfg = target._bs.annotated_cfg()
                whitelist = acfg.get_whitelisted_statements(block.addr)
                filtered = whitelist[:whitelist.index(idx)]
                treg = self.utils.target_tmp(rhs.addr)
                return block.addr, self._find_tmp_write(treg, block, filtered)

        return None, None

    def _step_block(self, target, bbl, idx):
        acfg = target._bs.annotated_cfg()
        whitelist = acfg.get_whitelisted_statements(bbl)
        assert idx in whitelist

        filtered = whitelist[:whitelist.index(idx)+1]

        while len(filtered) > 0:
            cur_idx = filtered.pop()
            cur_block = target.cfg.get_any_node(bbl).block
            cur_stmt = cur_block.vex.statements[cur_idx]

            if self.utils.is_reg_write(cur_stmt):
                next_idx = self._handle_reg_write(cur_stmt.data, cur_block,
                                                  filtered)
            elif self.utils.is_tmp_write(cur_stmt):
                next_idx = self._handle_tmp_write(cur_stmt.data,
                                                  cur_block,
                                                  filtered)
                if next_idx is None:
                    bbl, idx = self._filter_preds(cur_block, cur_idx, target)

                    return bbl, idx, cur_stmt.data

            elif self.utils.is_tmp_store(cur_stmt):
                next_idx = self._handle_tmp_store(cur_stmt.data,
                                                  cur_block,
                                                  filtered)

            filtered = filtered[:filtered.index(next_idx)+1]

        logger.info("This should never be printed")

    def _find_source(self, target, node):
        tslice = self.get_slice_target(node, target)

        if tslice[1] is None:
            # Could not find vex stmt
            if node.callee == "EOF":
                prev = target.prev_block(node.bbl)
                while prev not in target.func.get_call_sites():
                    # There should be a call site in this function
                    # So, this shouldn't result in an infinite loop
                    try:
                        prev = target.prev_block(prev)
                    except IndexError:
                        raise DataDependencyError("No call sites found")
                    
                if self._callee_name(target.func, prev) in target.source:
                    # 0 indicates that the source is the return value of some sim_proc
                    target._nodes[node.bbl].source = 0
                else:
                    raise DataDependencyError("Could not find data dependency")
            else:
                raise angr.AngrAnalysisError("Could not find target instruction")

        target._bs = self._project.analyses.BackwardSlice(target.cfg,
                                                          target.cdg,
                                                          target.ddg,
                                                          targets=[tslice])

        cur_block, cur_idx = tslice[0].addr, tslice[1]
        source = None
        off = 0

        while True:
            x, y, z = self._step_block(target,
                                       cur_block,
                                       cur_idx)
            if x is None:
                assert y is None
                if self.utils.is_reg_read(z):
                    treg = self.utils.target_reg(z)
                    if treg == self.utils.name_to_vex('sp'):
                        if self._is_bp_write(target, cur_block, cur_idx):
                            off -= self.utils.arch.bytes
                        source = off / self.utils.arch.bytes
                        if self.utils.arch.bytes == 8:
                            source += 6
                        break
                    source = self.utils.reg_to_arg(self.utils.target_reg(z))
                    break
                elif self.utils.is_tmp_load(z):
                    off, cur_block, cur_idx = self._track_stack(z, target,
                                                                cur_block)
                    continue
                else:
                    raise angr.AngrAnalysisError("New situation. Handle it")

            cur_block, cur_idx = x, y

        target._nodes[node.bbl].source = source
        logger.info("Found source at arg num : %d" % node.source)

    def _prepare_target(self, sa1):
        my_kb = angr.knowledge_base.KnowledgeBase(self._project, None)
        self._statistics[sa1.addr] = {'sink_count': len(sa1._nodes)}

        logger.debug("Creating CFGEmulated for function @ 0x%x" % sa1.addr)
        start_time = time.time()
        cfg = self._project.analyses.CFGEmulated(kb=my_kb,
                                                 keep_state=True,
                                                 starts=[sa1.addr],
                                                 state_add_options=refs,
                                                 call_depth=self._call_depth)
        end_time = time.time()
        self._statistics[sa1.addr]['cfg_creation'] = int(end_time - start_time)

        logger.debug("Creating DDG for function @ 0x%x (call_depth=%s)" % (sa1.addr, self._call_depth))
        start_time = time.time()
        ddg = self._project.analyses.DDG(cfg, start=sa1.addr, call_depth=self._call_depth)
        end_time = time.time()
        self._statistics[sa1.addr]['ddg_creation'] = int(end_time - start_time)

        logger.debug("Creating CDG for function @ 0x%x" % sa1.addr)
        start_time = time.time()
        cdg = self._project.analyses.CDG(cfg, start=sa1.addr)
        end_time = time.time()
        self._statistics[sa1.addr]['cdg_creation'] = int(end_time - start_time)

        func = cfg.functions.function(sa1.addr)
        assert func is not None

        if len(self._checkpoint) != 0:
            names = [self._callee_name(func, x) for x in func.get_call_sites()]

            all_matches = []
            for x in self._checkpoint:
                all_matches += list(filter(lambda y: x in y, names))
            
            self._statistics[sa1.addr]['sources'] = len(all_matches)

            if len(all_matches) == 0:
                logger.warn("No checkpoint present in function")
                # if self._require_dd is True:
                #     raise angr.AngrCFGError()
                #     return
        
        self._statistics[sa1.addr]['constants'] = 0

        target_obj = SA2_Target(cfg, cdg, ddg, func)
        target_obj._nodes = sa1._nodes

        return target_obj

    def analyze_one(self, sa1):
        logger.debug("Analysis of function @ 0x%x" % sa1.addr)
        target = self._prepare_target(sa1)

        if len(self._checkpoint) == 0:
            # Start from function entry point
            target.source = target.addr
        else:
            # Filter down the checkpoints
            func = target.func
            checkpoints = self._checkpoint.copy()
            names = [self._callee_name(func, x) for x in func.get_call_sites()]
            for x in checkpoints.copy():
                if x not in names:
                    checkpoints.pop(x)
            if len(checkpoints) == 0:
                # Default to function entry
                target.source = target.addr
            else:
                target.source = checkpoints

            filtered_checkpoints = {}
            for x in checkpoints.copy():
                for y in names:
                    if x in y:
                        filtered_checkpoints[y] = self._checkpoint[x]
            
            target.source = filtered_checkpoints if len(filtered_checkpoints) > 0 else target.addr

        for n in target.nodes:
            logger.debug("Starting back tracking for 0x%x" % n)
            try:
                self._find_source(target, target._nodes[n])
            except angr.AngrAnalysisError as e:
                logger.error(e)
                target.remove(n)
                continue
            except DataDependencyError as e:
                if target.sink_name(n) == "EOF" and self._require_dd is True:
                    logger.error(e)
                    target.remove(n)
                    continue
            except ConstantDataError as e:
                self._statistics[sa1.addr]['constants'] += 1
                logger.error(e)
                target.remove(n)
                continue
            except (KeyError, TypeError, AssertionError) as e:
                target._nodes[n].source = -1
                continue
            except AttributeError as e:
                target._nodes[n].source = -1
    
    
        if target.flag is False:
            logger.info("No valid sinks in function @ 0x%x" % target.addr)
        else:
            logger.info("%d sinks in function @ 0x%x" % (target.node_count,
                                                         target.addr))

        self._dump_stats()
        return target

    def analyze_all(self):
        for x in self._targets:
            try:
                obj = self.analyze_one(x)
                if obj.flag is True:
                    self._final_targets.append(obj)
                else:
                    del obj
            except (angr.AngrCFGError, angr.errors.SimEngineError) as e:
                logger.error(e)
                continue
            except (KeyError, TypeError, StopIteration, OverflowError, MemoryError) as e:
                logger.error(e)
                continue

        if self._verbose is True:
            self._dump_stats()
