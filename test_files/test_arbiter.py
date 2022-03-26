import angr
import logging

from arbiter.master_chief import *

logging.getLogger('arbiter.master_chief.sa_recon').setLevel(logging.INFO)
logging.getLogger('arbiter.master_chief.sa_advanced').setLevel(logging.INFO)
logging.getLogger('arbiter.master_chief.symbolic_execution').setLevel(logging.INFO)

logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel(logging.ERROR)

def func_entry_to_sink():
    """
    The first pattern in Arbiter where the data flow is tracked from
    the function's entry point to the sink
    This function will match all 
    """
    def constrain(state, expr, init_val, site=None):
        """
        Here, state is the angr state object currently stopped at the block
        where the target_sink is invoked.
        expr is the angr AST object of the argument of interest that will be passed to
        the target_sink
        init_val is a list of angr AST objects that correspond to the initial values
        that were combined to form the final expr AST.
        In this function, we can add constraints that try to prove the violation of some security property.
        """
        return

    sinks = ['target_sink']
    maps = {'target_sink': ['n']}

    project = angr.Project('./test.elf', auto_load_libs=False)

    sa = SA_Recon(project, sinks, maps)
    sa.analyze()
    assert len(sa.targets) == 3
    sb = SA_Adv(sa, call_depth=1, require_dd=True)
    sb.analyze_all()
    assert len(sb.targets) == 3
    se = SymExec(sb, constrain, require_dd=True)
    se.run_all()
    assert len(se.reports) == 3

def func_param_to_sink():
    """
    The second pattern in Arbiter where the data flow is tracked from
    the parameter to an initialization function to the sink
    """
    def constrain(state, expr, init_val, site=None):
        return

    sinks = ['target_sink']
    maps = {'target_sink': ['n']}
    checkpoint = {'init_param': 1}

    project = angr.Project('./test.elf', auto_load_libs=False)

    sa = SA_Recon(project, sinks, maps)
    sa.analyze()
    assert len(sa.targets) == 3
    sb = SA_Adv(sa, checkpoint=checkpoint, require_dd=True, call_depth=1)
    sb.analyze_all()
    assert len(sb.targets) == 1
    se = SymExec(sb, constrain, require_dd=True)
    se.run_all()
    assert len(se.reports) == 1


def func_return_to_sink():
    """
    The third pattern in Arbiter where the data flow is tracked from
    the return value of an initialization function to the sink
    """
    def constrain(state, expr, init_val, site=None):
        return

    sinks = ['target_sink']
    maps = {'target_sink': ['n']}
    checkpoint = {'init_return_value': 0}

    project = angr.Project('./test.elf', auto_load_libs=False)

    sa = SA_Recon(project, sinks, maps)
    sa.analyze()
    assert len(sa.targets) == 3
    sb = SA_Adv(sa, checkpoint=checkpoint, require_dd=True, call_depth=1)
    sb.analyze_all()
    assert len(sb.targets) == 1
    se = SymExec(sb, constrain, require_dd=True)
    se.run_all()
    assert len(se.reports) == 1

if __name__ == '__main__':
    func_entry_to_sink()
    func_param_to_sink()
    func_return_to_sink()
