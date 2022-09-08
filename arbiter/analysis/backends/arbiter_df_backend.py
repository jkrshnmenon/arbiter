import angr
from angr.sim_options import refs

from ...utils import *
from ...storage import *

CALL_DEPTH = 1



class ArbiterBackend():
    def __init__(self, storage: S):
        """Arbiter backend for data flow analysis
        """
        self.storage = storage
    
    @property
    def project(self):
        return self.storage.project
    
    @property
    def cfg(self):
        return self.storage.cfg

    def _is_bp_write(self, dst_node: DM, bbl: int, idx: int) -> bool:
        b = self.cfg.get_any_node(bbl).block
        stmt = b.vex.statements[idx]
        if is_reg_write(stmt) is False:
            return False
        return target_reg(stmt) == dst_node.marker.get_register_offset('bp')

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
            cur_block = self.cfg.get_any_node(bbl).block
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

        # logger.info("This should never be printed")

    def verify_edge_flow(self, src_node: DM, dst_node: DM) -> bool:
        assert not isinstance(src_node, MetaNode)
        assert not isinstance(dst_node, MetaNode)

        dst_cfg_node = self.cfg.get_any_node(dst_node.block.addr)
        dst_func = self.cfg.functions.floor_func(dst_node.block.addr)
        
        if dst_func is None:
            return False

        tmp_kb = angr.knowledge_base.KnowledgeBase(self.project, None)
        dst_cfg = self.project.analyses.CFGEmulated(kb=tmp_kb,
                                                    keep_state=True,
                                                    starts=[dst_func.addr],
                                                    state_add_options=refs,
                                                    call_depth=CALL_DEPTH)
        dst_ddg = self.project.analyses.DDG(dst_cfg, start=dst_func.addr, call_depth=CALL_DEPTH)
        dst_cdg= self.project.analyses.CDG(dst_cfg, start=dst_func.addr)
        # src_cfg_node = self.cfg.functions.floor_func(src_node.block.addr)
        # src_func = self.cfg.functions.floor_func(src_node.block.addr)

        tslice = (dst_cfg_node, dst_node.resolution.vex_idx)

        if tslice[1] is None:
            # Could not find vex stmt
            # if node.callee == "EOF":
            if isinstance(dst_node, EOFNode):
                raise NotImplemented
                prev = target.prev_block(node.bbl)
                while prev not in target.func.get_call_sites():
                    # There should be a call site in this function
                    # So, this shouldn't result in an infinite loop
                    try:
                        prev = target.prev_block(prev)
                    except IndexError:
                        # raise DataDependencyError("No call sites found")
                        return False

                if self._callee_name(target.func, prev) in target.source:
                    # 0 indicates that the source is the return value of some sim_proc
                    target._nodes[node.bbl].source = 0
                else:
                    # raise DataDependencyError("Could not find data dependency")
                    return False
            else:
                # raise angr.AngrAnalysisError("Could not find target instruction")
                return False

        dst_bs = self.project.analyses.BackwardSlice(dst_cfg,
                                                    cdg=dst_cdg,
                                                    ddg=dst_ddg,
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
                if is_reg_read(z):
                    treg = target_reg(z)
                    if treg == dst_node.marker.sp_offset:
                        if self._is_bp_write(dst_node=dst_node, bbl=cur_block, idx=cur_idx):
                            off -= (dst_node.marker.bits // 8)
                        source = off / (dst_node.marker.bits // 8)
                        if dst_node.marker.bits == 64:
                            source += 6
                        break
                    if target_reg(z) == dst_node.marker.ret_offset:
                        source = 0
                    else:
                        source = dst_node.marker.argument_register_positions[target_reg(z)]+1
                    break
                elif is_tmp_load(z):
                    off, cur_block, cur_idx = self._track_stack(z, target,
                                                                cur_block)
                    continue
                else:
                    raise angr.AngrAnalysisError("New situation. Handle it")

            cur_block, cur_idx = x, y

        target._nodes[node.bbl].source = source
        # logger.info("Found source at arg num : %d" % node.source)