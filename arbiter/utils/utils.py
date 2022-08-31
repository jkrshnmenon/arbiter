from optparse import Option
from typing import Optional
import angr
from ..spec import *

def prGreen(skk): 
    print(f"\033[92m {skk}\033[00m")


def is_reg_write(stmt):
    return stmt.tag == 'Ist_Put'

def target_reg_offset(stmt):
    return stmt.offset

def vex_is_reg_write(stmt, reg_vex_offset: int):
    return is_reg_write(stmt) and target_reg_offset(stmt) == reg_vex_offset

def resolve_data_marker(block, vd_node) -> int:
    assert isinstance(block, angr.block.Block)
    assert isinstance(vd_node, VDNode)

    if isinstance(vd_node, RetNode):
        # Get the vex id of instruction from next block
        pass
    elif isinstance(vd_node, EOFNode):
        # Get the vex id of instruction that sets return_register
        pass
    else:
        register_vex_offset: int = vd_node.register_offset
        vex_id = None
        for idx, stmt in enumerate(block.vex.statements):
            if vex_is_reg_write(stmt, register_vex_offset):
                vex_id = idx
        
        return vex_id
