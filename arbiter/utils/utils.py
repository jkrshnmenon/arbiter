from optparse import Option
from typing import Optional
import angr
from ..spec import *

def prGreen(skk): return f"\033[92m {skk}\033[00m"

def prRed(skk): return "\033[91m {}\033[00m" .format(skk)
 
def prYellow(skk): return "\033[93m {}\033[00m" .format(skk)
 
def prLightPurple(skk): return "\033[94m {}\033[00m" .format(skk)
 
def prPurple(skk): return "\033[95m {}\033[00m" .format(skk)
 
def prCyan(skk): return "\033[96m {}\033[00m" .format(skk)
 
def prLightGray(skk): return "\033[97m {}\033[00m" .format(skk)
 
def prBlack(skk): return "\033[98m {}\033[00m" .format(skk)
 

def is_reg_write(stmt):
    return stmt.tag == 'Ist_Put'

def is_reg_read(stmt):
    return stmt.tag == 'Iex_Get'

def is_imark(stmt):
    return stmt.tag == 'Ist_IMark'

def stmt_addr(stmt):
    return stmt.addr

def target_reg_offset(stmt):
    return stmt.offset

def vex_is_reg_write(stmt, reg_vex_offset: int):
    return is_reg_write(stmt) and target_reg_offset(stmt) == reg_vex_offset

def vex_is_reg_read(stmt, reg_vex_offset: int):
    return is_reg_read(stmt) and target_reg_offset(stmt) == reg_vex_offset

def resolve_data_marker(block, vd_node, function) -> dict:
    assert isinstance(block, angr.block.Block)
    assert isinstance(vd_node, VDNode)

    insn_addr: int = None
    insn = None
    vex_id: int = None
    vex_stmt = None

    if isinstance(vd_node, RetNode):
        # Convert block to function blocknode
        blocknode = None
        for tmp in function.graph.nodes:
            if tmp.addr == block.addr:
                blocknode = tmp
                break
        assert blocknode is not None

        # Get the successor block
        out_edges = function.graph.out_edges(blocknode)
        assert len(out_edges) == 1

        _, next_blocknode = list(out_edges)[0]

        # Convert blocknode back to block
        for tmp in function.blocks:
            if tmp.addr == next_blocknode.addr:
                block = tmp
                break
        
        # Find the instruction that reads from the return register
        register_vex_offset: int = vd_node.register_offset
        for idx, stmt in enumerate(block.vex.statements):
            if is_imark(stmt):
                insn_addr = stmt_addr(stmt)
            if not hasattr(stmt, "data"):
                continue
            if vex_is_reg_read(stmt.data, register_vex_offset):
                vex_id = idx
                vex_stmt = stmt
                # Break because we want the first instance here
                break

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
                # No break here because we want the last
        
    for ins in block.capstone.insns:
        if ins.address == insn_addr:
            insn = ins
            break
        
    return {'insn_addr': insn_addr, 'insn': insn, 'vex_idx': vex_id, 'vex_stmt': vex_stmt}
