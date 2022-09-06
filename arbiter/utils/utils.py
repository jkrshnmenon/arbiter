import angr
from capstone.x86 import *
from typing import Optional

from ..spec import *

def prGreen(skk): return f"\033[92m {skk}\033[00m"

def prRed(skk): return f"\033[91m {skk}\033[00m"
 
def prYellow(skk): return f"\033[93m {skk}\033[00m"
 
def prLightPurple(skk): return f"\033[94m {skk}\033[00m"
 
def prPurple(skk): return f"\033[95m {skk}\033[00m"
 
def prCyan(skk): return f"\033[96m {skk}\033[00m"
 
def prLightGray(skk): return f"\033[97m {skk}\033[00m"
 
def prBlack(skk): return f"\033[98m {skk}\033[00m"
 
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

def op_is_reg(self, op):
    '''
    Check whether the operand type is register or not
    '''
    if op.type == X86_OP_REG:
        return True

    return False


def is_add32(self, stmt):
    return stmt.tag == 'Iex_Binop' and stmt.op == 'Iop_Add32'

def is_add(self, stmt):
    return stmt.op == 'Iop_Add32' or stmt.op == 'Iop_Add64'

def is_sub(self, stmt):
    return stmt.op == 'Iop_Sub32' or stmt.op == 'Iop_Sub64'

def is_mul(self, stmt):
    return stmt.op == 'Iop_Mul32' or stmt.op == 'Iop_Mul64'

def is_div(self, stmt):
    return stmt.op == 'Iop_Div32' or stmt.op == 'Iop_Div64'

def is_imark(self, stmt):
    return stmt.tag == 'Ist_IMark'

def is_ite(self, stmt):
    return stmt.tag == 'Iex_ITE'

def is_const(self, stmt):
    return stmt.tag == 'Iex_Const'

def is_reg_write(self, stmt):
    return stmt.tag == 'Ist_Put'

def is_reg_read(self, stmt):
    return stmt.tag == 'Iex_Get'

def is_tmp_write(self, stmt):
    return stmt.tag == 'Ist_WrTmp'

def is_tmp_read(self, stmt):
    return stmt.tag == 'Iex_RdTmp'

def is_tmp_unop(self, stmt):
    return stmt.tag == 'Iex_Unop'

def is_tmp_binop(self, stmt):
    return stmt.tag == 'Iex_Binop'

def is_arith(self, stmt):
    return self.is_tmp_unop(stmt) or self.is_tmp_binop(stmt)

def is_tmp_load(self, stmt):
    return stmt.tag == 'Iex_Load'

def is_tmp_store(self, stmt):
    return stmt.tag == 'Ist_Store'

def target_reg(self, stmt):
    return stmt.offset

def target_tmp(self, stmt):
    return stmt.tmp

def target_const(self, stmt):
    return stmt.con.value

def is_stack_var(self, variable):
    return type(variable) == angr.sim_variable.SimStackVariable

def store_in_stack(self, ins):
    '''
    Check if ins corresponds to `mov dword[esp+x], {r/imm}`
    '''
    if ins.insn.mnemonic != 'mov':
        return False

    if len(ins.insn.operands) < 1:
        return False

    first = ins.insn.operands[0]
    if first.mem.base == X86_REG_ESP or first.mem.base == X86_REG_RSP:
        return True

    return False

def disp(self, ins):
    return ins.insn.disp
