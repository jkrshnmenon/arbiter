from optparse import Option
from typing import Optional
import angr
from ..spec import *

def prGreen(skk): 
    print(f"\033[92m {skk}\033[00m")


def is_reg_write(stmt):
    return stmt.tag == 'Ist_Put'

def is_imark(stmt):
    return stmt.tag == 'Ist_IMark'

def stmt_addr(stmt):
    return stmt.addr

def target_reg_offset(stmt):
    return stmt.offset

def vex_is_reg_write(stmt, reg_vex_offset: int):
    return is_reg_write(stmt) and target_reg_offset(stmt) == reg_vex_offset

def resolve_data_marker(block, vd_node) -> dict:
    assert isinstance(block, angr.block.Block)
    assert isinstance(vd_node, VDNode)

    insn_addr: int = None
    insn = None
    vex_id: int = None
    vex_stmt = None

    if isinstance(vd_node, RetNode):
        # Get the vex id of instruction from next block
        pass
    elif isinstance(vd_node, EOFNode):
        # Get the vex id of instruction that sets return_register
        pass
    else:
        register_vex_offset: int = vd_node.register_offset
        for idx, stmt in enumerate(block.vex.statements):
            if is_imark(stmt):
                insn_addr = stmt_addr(stmt)
            if vex_is_reg_write(stmt, register_vex_offset):
                vex_id = idx
                vex_stmt = stmt
        
    for ins in block.capstone.insns:
        if ins.address == insn_addr:
            insn = ins
            break
        
    return {'insn_addr': insn_addr, 'insn': insn, 'vex_idx': vex_id, 'vex_stmt': vex_stmt}
