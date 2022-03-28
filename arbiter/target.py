import angr
import claripy
from claripy.errors import ClaripyOperationError

class Sink():
    def __init__(self, bbl=0, size=0, callee='', arglist=[]):
        self._target = {'bbl': bbl,
                        'size': size,
                        'callee': callee,
                        'source': None,
                        'args': arglist}
        self._flag = False

    def __str__(self):
        return f"Sink(BBL={hex(self.bbl)}, Callee={self.callee}, args={self.args}"

    @property
    def fmt(self):
        return self._target['args'].index('fmt') + 1

    @property
    def src(self):
        return self._target['args'].index('i') + 1

    @property
    def sz(self):
        if self.callee == "EOF":
            return 0
        return self._target['args'].index('n') + 1

    @property
    def bbl(self):
        return self._target['bbl']

    @bbl.setter
    def bbl(self, addr):
        assert addr in self._func.block_addrs_set
        self._target['bbl'] = addr

    @property
    def size(self):
        return self._target['size']

    @size.setter
    def size(self, val):
        assert val >= 0
        self._target['size'] = val

    @property
    def callee(self):
        return self._target['callee']

    @callee.setter
    def callee(self, val):
        assert len(val) > 0
        self._target['callee'] = val

    @property
    def source(self):
        # if self._target['source'] is None:
        #     return -1
        return self._target['source']

    @source.setter
    def source(self, val):
        if val <= 0:
            val = None
        else:
            val = int(val)
        self._target['source'] = val

    @property
    def flag(self):
        return self._flag

    @flag.setter
    def flag(self, val):
        self._flag = val

    @property
    def args(self):
        return self._target['args']

    @args.setter
    def args(self, arg_list):
        self._target['args'] = arg_list


class SA1_Target():
    def __init__(self, func):
        self._func = func
        self._nodes = {}

    def __str__(self):
        return f"SA1_Target(func={hex(self.addr)}, nodes={self.node_count})"

    def add_node(self, site, size, cfg, arglist):
        if 'r' in arglist:
            self._nodes[site] = Sink(site, size, "EOF", arglist)
            return

        callee = self._func.get_call_target(site)
        assert callee is not None

        target = cfg.functions.function(callee)
        assert target is not None

        self._nodes[site] = Sink(site, size, target.demangled_name, arglist)

    @property
    def addr(self):
        return self._func.addr

    @property
    def func(self):
        return self._func

    @property
    def nodes(self):
        return sorted(self._nodes.keys())

    @property
    def node_count(self):
        return len(self._nodes)


class SA2_Target():
    '''
    A class to represent a target function
    Must contain a CFGAccurate object, a DDG and CDG object and a Function
    object.
    And then a dictionary which contain details of the bbl and the
    sink
    '''
    def __init__(self, cfg, cdg, ddg, func):
        '''
        :param cfg : The CFGEmulated object
        :param ddg : The DDG object
        :param cdg : The CDG object
        :param func : The Function object
        '''
        self._cfg = cfg
        self._ddg = ddg
        self._cdg = cdg
        self._func = func
        self._bs = None
        self._nodes = {}
        self._source = None

    def __str__(self):
        return f"SA2_Target(func={hex(self.addr)}, source={self.source}, nodes={self.node_count})"

    def str_ref(self, str_addr):
        for addr, val in self._func.string_references(vex_only=True):
            if addr == str_addr:
                return val

    def get_any_ddg_node(self, addr, idx):
        dnode = None
        for node in self._ddg.data_graph.nodes:
            if node.location.block_addr == addr:
                if node.location.stmt_idx == idx:
                    dnode = node
        return dnode

    def stmt_from_ddg_node(self, dnode):
        b = self._cfg.get_any_node(dnode.location.block_addr).block
        return b.vex.statements[dnode.location.stmt_idx]

    def block_idx(self, bbl):
        return sorted(list(self.func.block_addrs_set)).index(bbl)

    def prev_block(self, bbl):
        idx = self.block_idx(bbl)
        return sorted(list(self.func.block_addrs_set))[idx - 1]
    
    def next_block(self, bbl):
        idx = self.block_idx(bbl)
        if len(self.func.block_addrs_set) <= idx:
            return None
        return sorted(list(self.func.block_addrs_set))[idx + 1]

    def expr_from_state(self, project, state, arg_num):
        cca = project.analyses.CallingConvention(self._func)
        args = cca.cc.arg_locs(cca.prototype)
        if cca.cc is None or args is None:
            return None
        if arg_num == 0:
            return cca.cc.get_return_val(state)
        elif len(args) >= arg_num:
            return cca.cc.arg(state, arg_num - 1)

    def checkpoint_is_ret(self, name):
        return self.source[name] == 0

    @property
    def cfg(self):
        return self._cfg

    @property
    def cdg(self):
        return self._cdg

    @property
    def ddg(self):
        return self._ddg

    @property
    def node_count(self):
        return len(self._nodes)

    @property
    def flag(self):
        return len(self._nodes) > 0

    @property
    def addr(self):
        return self._func.addr

    @property
    def name(self):
        return self._func.name

    @property
    def func(self):
        return self._func

    @property
    def nodes(self):
        return sorted(self._nodes.keys())

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, checkpoint):
        self._source = checkpoint

    def remove(self, site):
        del self._nodes[site]

    def sink_name(self, site):
        return self._nodes[site].callee


class Report:
    def __init__(self, state, site):
        self._state = state
        self._site = site

    def __str__(self):
        return f"Report(state={self.state}, site={hex(self.sink)})"

    @property
    def state(self):
        return self._state

    @property
    def sink(self):
        return self._site.bbl

    @property
    def site(self):
        return self._site


class ArbiterReport:
    def __init__(self, bbl, function, bbl_history, function_history):
        """
        All arguments are integers/list of integers
        """
        self._bbl = bbl
        self._function = function
        self._bbl_history = bbl_history
        self._function_history = function_history
    
    
    def __str__(self):
        return f"ArbiterRepor(bbl={hex(self.bbl)}, function={hex(self.function)})"
    
    @property
    def bbl(self):
        return self._bbl
    
    @bbl.setter
    def bbl(self, val):
        self._bbl = val

    @property
    def function(self):
        return self._function

    @property
    def bbl_history(self):
        return self._bbl_history

    @property
    def function_history(self):
        return self._function_history


class DerefHook():
    def _find_in_list(self, child, sym_vars):
        for x in sym_vars:
            if child.length != x.length:
                continue
            elif not isinstance(child, type(x)):
                continue
            result = child == x
            if result.is_true():
                return True

        return False

    def _find_child_in_list(self, ast, vars):
        try:
            for child in list(set(ast.recursive_leaf_asts)):
                if self._find_in_list(child, vars):
                    return True
        except ClaripyOperationError:
            # Could not iterate over leaf ast's
            #TODO how to handle this ?
            return False

        if self._find_in_list(ast, vars):
            return True

        return False
    
    def _get_child_from_list(self, ast, sym_vars):
        for child in list(set(ast.recursive_leaf_asts)):
            if self._find_in_list(child, sym_vars):
                return child

        if self._find_in_list(ast, sym_vars):
            return ast

    def _find_bit_in_ast(self, bit, ast):
        for idx in range(0, ast.length):
            result = ast[idx] == bit
            if result.is_true():
                return idx

        return None
    
    def _mem_write_hook(self, state):
        if state.globals.get('track_write', 0) == 0:
            return
        elif state.globals['track_write'] is False:
            return

        expr = state.inspect.mem_write_address

        if type(expr) == int:
            return

        if self._find_child_in_list(expr, state.globals['sym_vars']) is False:
            return

        orig_expr = self._get_child_from_list(expr, state.globals['sym_vars'])

        if self._find_in_list(orig_expr, state.globals['derefs']) is True:
            return

        state.solver.add(orig_expr == 0)
        state.globals['derefs'].append(orig_expr)


    def _mem_read_hook(self, state):
        expr = state.inspect.mem_read_address
        val = state.inspect.mem_read_expr

        # Don't need to worry if this address is
        # 1) An address in the BSS
        # 2) Not dependent on the arguments
        # 3) Already dereferenced before
        if type(expr) == int:
            return

        if self._find_child_in_list(expr, state.globals['sym_vars']) is False:
            return

        flag1 = self._find_in_list(expr, state.globals['derefs'])
        flag2 = self._find_child_in_list(val, state.globals['sym_vars'])

        if flag1 and flag2:
            return

        if state.globals.get('no_create', 0) != 0:
            if state.globals['no_create'] is True:
                state.globals['sym_vars'].append(val)
                state.globals['derefs'].append(expr)
                return

        sym_var = claripy.BVS('df_var', state.inspect.mem_read_length*8)
        state.globals['derefs'].append(expr)
        state.globals['sym_vars'].append(sym_var)
        state.memory.store(expr, sym_var, endness=angr.archinfo.Endness.LE)
        state.inspect.mem_read_expr = sym_var
    


class DefaultHook(angr.SimProcedure, DerefHook):
    def _push_regs(self, state):
        state.stack_push(state.regs.r9)
        state.stack_push(state.regs.r8)
        state.stack_push(state.regs.rcx)
        state.stack_push(state.regs.rdx)
        state.stack_push(state.regs.rsi)
        state.stack_push(state.regs.rdi)

    def _nth_arg(self, state, n):
        state_copy = state.copy()
        if state.arch.bits == 64:
            self._push_regs(state_copy)

        for _ in range(n - 1):
            state_copy.stack_pop()

        return state_copy.stack_pop()

    def run(self):
        expr = claripy.BVS('sim_retval', self.state.project.arch.bits)
        self.state.solver.add(expr != 0)
        self.state.globals['sym_vars'].append(expr)
        return expr

class FirstArgHook(angr.SimProcedure):
    def run(self, arg):
        expr = claripy.BVS('sim_retval', self.state.project.arch.bits)
        self.state.solver.add(expr == arg)
        self.state.globals['sym_vars'].append(expr)
        return arg

class CheckpointHook(DefaultHook):
    def run(self, **kwargs):
        assert 'arg_num' in kwargs['kwargs']
        arg_num = kwargs['kwargs']['arg_num']
        if self.state.globals.get('globals', None) is None:
            self.state.globals['sym_vars'] = []
        if arg_num == 0:
            sym_var = claripy.BVS('ret', self.state.arch.bits)
            self.state.globals['sym_vars'].append(sym_var)
            return sym_var
        
        expr = self._nth_arg(self.state, arg_num)
        self.state.globals['sym_vars'].append(expr)



class StrlenHook(DefaultHook):
    def run(self):
        if self.state.project.arch.bits == 32:
            inp = self.state.stack_pop()
        elif self.state.project.arch.bits == 64:
            inp = self.state.regs.rdi
        sym_vars = self.state.globals['sym_vars']
        expr = claripy.BVS('len_retval', self.state.project.arch.bits)
        self.state.solver.add(expr < 2 ** int(self.state.project.arch.bits/2))

        if self._find_child_in_list(inp, sym_vars) is False:
            return expr

        self.state.solver.add(expr != 0)
        self.state.globals['sym_vars'].append(expr)
        return expr


class StrchrHook(DefaultHook):
    def run(self):
        if self.state.project.arch.bits == 32:
            inp = self.state.stack_pop()
        elif self.state.project.arch.bits == 64:
            inp = self.state.regs.rdi
        sym_vars = self.state.globals['sym_vars']
        expr = claripy.BVS('chr_retval', self.state.project.arch.bits)

        if self._find_child_in_list(inp, sym_vars) is False:
            return expr

        self.state.solver.add(expr != 0)
        self.state.solver.add(expr < 2 ** int(self.state.project.arch.bits/2))
        retval = expr + inp
        self.state.globals['sym_vars'].append(expr)
        return retval


class GetenvHook(DefaultHook):
    def run(self):
        expr = claripy.BVS('env_retval', self.state.project.arch.bits)
        self.state.globals['sym_vars'].append(expr)
        return expr
