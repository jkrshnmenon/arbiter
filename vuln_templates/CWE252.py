import os
import sys
import angr
import json
import logging
from pythonjsonlogger import jsonlogger


import arbiter
from arbiter.master_chief import *

log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 
                                       'logs'))
syscall_table = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             'syscalls_annotated.json'))


def setup_logger(name):
    fname = os.path.basename(sys.argv[1])

    formatter = jsonlogger.JsonFormatter(fmt='%(asctime)s %(levelname)s %(name)s %(message)s')
    json_handler = logging.FileHandler(log_dir+'/syswalker-{}.log'.format(fname))
    json_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.addHandler(json_handler)
    logger.setLevel(logging.DEBUG)


def parse_syscalls(syscall_table, return_filter=None):
    sinks = []
    maps = {}
    checkpoints = {}
    syscalls = {}

    with open(syscall_table) as f:
        syscalls = json.load(f)

    for syscall, s_info in syscalls.items():
        ret = s_info['ret']
        if not ret:
            continue
        if return_filter != None:
            values = ret['values']
            if str(return_filter) not in values or values[str(return_filter)] != 'error':
                continue
        print(f"syscall: {syscall}")
        sinks.append(syscall)
        maps[syscall] = ['r']
        checkpoints[syscall] = 0
 
    return sinks, maps, checkpoints

def do_stuff(fname, sinks, maps, checkpoints):
    def constrain(state, expr, init_val, site=None):
        s1 = state.copy()
        # target function returned -1 (indicating error)
        s1.solver.add(init_val[0] == 0xffffffffffffffff)
        if s1.satisfiable():
            # target function allows both (indicating absence of checks)
            state.solver.add(init_val[0] == 0)
        else:
            # Unsat the whole thing
            state.solver.add(init_val[0] == 0xffffffffffffffff)
        return  

    bin_file = fname
    project = angr.Project(bin_file, load_options={'auto_load_libs': False})

    sa = SA_Recon(project, sinks, maps, verbose=True)
    sa.analyze()

    sb = SA_Adv(sa, checkpoints, require_dd=False, call_depth=1, verbose=True)
    sb.analyze_all()

    se = SymExec(sb, constrain, verbose=True)
    se.run_all()

    return se.postprocessing(3)


if __name__ == '__main__':
    assert len(sys.argv) >= 2, "Usage : %s <binary>" % sys.argv[0]

    setup_logger("SA_recon")
    setup_logger("SA_advanced")
    setup_logger("SE_logger")

    sinks, maps, checkpoints = parse_syscalls(syscall_table, return_filter=-1)
    do_stuff(sys.argv[1], sinks, maps, checkpoints)
