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
    
    @classmethod
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
        dst_cdg= self.project.analyses.CDG(cfg, start=dst_func.addr)
        # src_cfg_node = self.cfg.functions.floor_func(src_node.block.addr)
        # src_func = self.cfg.functions.floor_func(src_node.block.addr)

        tslice = (dst_cfg_node, dst_node.resolution.vex_idx)

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
                    if treg == name_to_vex('sp'):
                        if self._is_bp_write(target, cur_block, cur_idx):
                            off -= arch.bytes
                        source = off / arch.bytes
                        if arch.bytes == 8:
                            source += 6
                        break
                    source = reg_to_arg(self.utils.target_reg(z))
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