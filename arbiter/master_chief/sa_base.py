import angr
from ..utils import Utils
from ..target import *


class StaticAnalysis(object):
    '''
    The base class for the static analysis.
    This class just contains a couple of functions which are used by both the
    basic and advanced static analysis
    '''
    def __init__(self, p):
        self._targets = []
        self._project = p
        self.utils = Utils(p)

    @property
    def cfg(self):
        return self._cfg

    @property
    def project(self):
        return self._project

    @property
    def targets(self):
        return self._targets

    def _callee_name(self, func, site):
        callee = func.get_call_target(site)

        if callee is None:
            raise angr.AngrCFGError("Couldn't find call target @ %x" % site)

        target = self.cfg.functions.function(callee)

        if target is None:
            raise angr.AngrCFGError("Couldn't find function @ %x" % callee)

        return target.demangled_name
    
    def _find_ret_block(self, func):
        '''
        Return BBL that contains the ret instruction
        '''
        for addr in func.block_addrs_set:
            node = self.cfg.get_any_node(addr)
            if node is None:
                return None
            block = node.block
            if block is None:
                return None
            if self._find_ret_ins(block) is not None:
                return addr

    def _find_ret_ins(self, block):
        '''
        Return addr of ret instruction
        Hopefully the last instruction should be the ret
        '''
        last_ins = block.capstone.insns[-1]
        if last_ins.insn.mnemonic == 'ret':
            return last_ins.insn.address

        return None

    def get_target_ins(self, bbl, arg_num, flag=False):
        '''
        Returns the address of the instruction which sets the argument arg_num
        '''
        if self._project.arch.bits == 64:
            if arg_num == 0:
                reg = self.utils.ret_reg
            else:
                reg = self.utils.arg_to_offset(arg_num)

            return self.get_reg_populator(bbl, reg)

        elif self._project.arch.bits == 32:
            if arg_num == 0:
                return self.get_reg_populator(bbl, self.utils.ret_reg)

            return self.get_vex_id(bbl.block,
                                   self.get_arg_populator(bbl, arg_num),
                                   arg_num)

    def get_arg_populator(self, bbl, arg_num):
        block = bbl.block
        ins = block.capstone.insns[::-1]
        arg_ctr = 0
        '''
        Iterate over instructions in the block in reverse.
        If argument counter == arg_num, return the address of the instruction
        For each push instruction, increment the argument counter.
        If instruction is `mov [esp+x], eax`, check if arg_num == arg_ctr + x/4
        '''
        for tmp in ins:
            if tmp.insn.mnemonic == 'push':
                arg_ctr += 1
                if arg_num == arg_ctr:
                    return tmp.insn.address
                continue

            if self.utils.store_in_stack(tmp) is True:
                '''
                Assuming we're dealing with 32 bit, dividing offsets by 4
                should do
                '''
                disp = self.utils.disp(tmp)
                if arg_num == arg_ctr + disp/4 + 1:
                    return tmp.insn.address

        '''
        Could not identify the correct instruction
        Different architecture maybe ?
        '''
        raise angr.AngrAnalysisError("""Could not identify instruction which
        populates the target argument {} : {}""".format(hex(bbl), arg_num))
    
    def get_reg_populator(self, bbl, reg):
        for x in bbl.block.vex.statements[::-1]:
            if self.utils.is_reg_write(x) is False:
                continue
            if self.utils.target_reg(x) != reg:
                continue
            return bbl.block.vex.statements.index(x)

    def get_vex_id(self, block, ins, arg):
        '''
        Returns the vex ID of the statement populating the argument arg
        '''
        if self._project.arch.bits == 64:
            reg = self.utils.arg_to_reg(arg)

            assert reg is not None

            return self.get_vex_for_reg(block, ins, reg)

        else:
            return self.get_vex_for_arg(block, ins, arg)

    def get_vex_for_reg(self, block, ins, reg):
        target_stmt = None

        statements = block.vex.statements

        reg_num = self.utils.name_to_vex(reg)

        for x in range(len(statements)):
            stmt = statements[x]
            if self.utils.is_imark(stmt) is False:
                continue
            if stmt.addr == ins:
                break

        for stmt in statements[x+1:]:
            if self.utils.is_imark(stmt):
                break
            if self.utils.is_reg_write(stmt) is False:
                continue
            if self.utils.target_reg(stmt) == reg_num:
                target_stmt = stmt
                break

        assert target_stmt is not None
        return statements.index(target_stmt)

    def get_vex_for_arg(self, block, ins, arg):
        '''
        Push instructions and instructions of the form `mov [esp+x], {r/imm}`
        are translated into store instructions in VEX.
        All we need to do is to identify the store vex instruction that
        corresponds to the IMark ins
        '''
        target_stmt = None
        statements = block.vex.statements

        for x in range(len(statements)):
            stmt = statements[x]
            if self.utils.is_imark(stmt) is False:
                continue
            if stmt.addr == ins:
                break
        '''
        The required statment is the one which stores a value.
        '''
        for stmt in statements[x+1:]:
            if self.utils.is_tmp_store(stmt):
                target_stmt = stmt
                break
            if self.utils.is_imark(stmt):
                break

        assert target_stmt is not None
        return statements.index(target_stmt)

    def _format_str_types(self, fmt):
        if fmt == '%s':
            return "i"
        else:
            return "v"

    def _push_regs(self, state):
        '''
        In x64, the first 6 arguments are passed via regsiters.
        In order to maintain a similar method to retrieve these arguments,
        we'll push the registers in the reverse order to the stack
        '''
        state.stack_push(state.regs.r9)
        state.stack_push(state.regs.r8)
        state.stack_push(state.regs.rcx)
        state.stack_push(state.regs.rdx)
        state.stack_push(state.regs.rsi)
        state.stack_push(state.regs.rdi)

    def _nth_arg(self, state, n, saved_pc=False):
        '''
        Return the nth argument from the state
        We're only dealing with x86 and x64 here
        '''
        if n == 0:
            name = self.utils.vex_to_name(self.utils.ret_reg, self.utils.arch.bytes)
            return getattr(state.regs, name)

        state_copy = state.copy()
        if saved_pc is True:
            _ = state_copy.stack_pop()

        if self._project.arch.bits == 64:
            self._push_regs(state_copy)

        for x in range(n - 1):
            state_copy.stack_pop()

        return state_copy.stack_pop()
