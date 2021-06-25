import angr
from capstone.x86 import *
from angr import archinfo
from archinfo.arch_x86 import ArchX86
from archinfo.arch_amd64 import ArchAMD64


class Utils:
    def __init__(self, project):
        self.project = project
        self.arch = self.project.arch

        # This should constantly be updated to accomodate all libc functions
        self.func_map = {'strcpy': ['o', 'i'],
                         'stpcpy': ['o', 'i'],
                         'strncpy': ['o', 'i', 'n'],
                         'sprintf': ['o', 'fmt'],
                         'sprintf_chk': ['o', 'c', 'n', 'fmt'],
                         'memcpy': ['o', 'i', 'n'],
                         'malloc': ['n'],
                         'realloc': ['p', 'n'],
                         'calloc': ['n', 'n'],
                         'ret': ['r']}
        self.misc_map = {'strlen': ['i'],
                         'strdup': ['i'],
                         'strndup': ['i', 'n']}

    def dst(self, func_name):
        '''
        The argument of the func_name which contains the destination
        '''
        return self.func_map[func_name].index('o') + 1

    def src(self, func_name):
        '''
        The argument of the func_name which contains the source
        '''
        return self.func_map[func_name].index('i') + 1

    def fmt(self, func_name):
        '''
        The argument of the func_name which contains the format string
        '''
        return self.func_map[func_name].index('fmt') + 1

    def sz(self, func_name):
        return self.func_map[func_name].index('n') + 1

    def misc_src(self, func_name):
        if 'n' in self.misc_map[func_name]:
            return self.misc_map[func_name].index('n') + 1
        else:
            return self.misc_map[func_name].index('i') + 1

    @property
    def ret_reg(self):
        return self.arch.ret_offset

    def arg_to_offset(self, arg_num):
        for key in self.arch.argument_register_positions:
            if self.arch.argument_register_positions[key] + 1 == arg_num:
                return key

    def arg_to_reg(self, arg_num, sz=8):
        return self.vex_to_name(self.arg_to_offset(arg_num), sz)

    def reg_to_arg(self, regnum):
        if regnum == self.ret_reg:
            return 0
        return self.arch.argument_register_positions[regnum] + 1

    def arg_index(self, reg):
        '''
        Returns the argument number corresponding to reg
        '''
        return self.arch.argument_register_positions[reg] + 1

    def op_is_reg(self, op):
        '''
        Check whether the operand type is register or not
        '''
        if op.type == X86_OP_REG:
            return True

        return False

    def name_to_vex(self, reg_name):
        '''
        Return the VEX representation of the register reg_name
        Note: This is different from the capstone representation of registers
        '''
        return self.arch.registers[reg_name][0]

    def vex_to_name(self, reg, sz):
        '''
        Return the name of the register from the VEX representation
        '''
        return self.arch.register_size_names[(reg, sz)]

    def reg_from_ddg_node(self, ddg_node, bits):
        '''
        Return the name of the register in the ddg_node
        '''
        assert type(ddg_node.variable) == angr.sim_variable.SimRegisterVariable

        return ddg_node.variable.reg

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


class FatalError(Exception):
    def __init__(self, message):
        self.message = message

class DataDependencyError(Exception):
    def __init__(self, message):
        self.message = message

class ConstantDataError(Exception):
    def __init__(self, message):
        self.message = message
