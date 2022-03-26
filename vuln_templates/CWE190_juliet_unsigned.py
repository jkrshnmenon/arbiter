import os
import sys
import angr
import logging
from pythonjsonlogger import jsonlogger

SA_FLAG=False
SE_FLAG=False

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import arbiter
from arbiter.master_chief import *

bin_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                       'dataset', 'Juliet_testcases'))
log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 
                                       'logs'))


def setup_logger(name):
    fname = os.path.basename(sys.argv[1])

    formatter = jsonlogger.JsonFormatter(fmt='%(asctime)s %(levelname)s %(name)s %(message)s')
    json_handler = logging.FileHandler(log_dir+'/juliet-{}.log'.format(fname))
    json_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.addHandler(json_handler)
    logger.setLevel(logging.DEBUG)


def do_stuff(fname):
    def constrain(state, expr, init_val, site=None):
        for x in init_val:
            x = x[31:]
            expr = expr[31:]
            if x.length < expr.length:
                x = x.zero_extend(expr.length-x.length)
            state.solver.add(expr < x)

    sinks = [
        'printUnsignedLine',
        ]
    maps = {x: ['n'] for x in sinks}
    checkpoints = {'atoi': 0,
                   'rand': 0,
                   'fscanf': 3,
                   'badSource': 0}

    bin_file = os.path.join(bin_dir, fname)
    project = angr.Project(bin_file, load_options={'auto_load_libs': False})

    sa = SA_Recon(project, sinks, maps)
    sa.analyze()
    # sa.analyze_one(0x4053ac)

    sb = SA_Adv(sa, checkpoints, require_dd=SA_FLAG, call_depth=1)
    sb.analyze_all()

    se = SymExec(sb, constrain, require_dd=SE_FLAG)
    se.run_all()

    se.postprocessing(2)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    setup_logger("SA_recon")
    setup_logger("SA_advanced")
    setup_logger("SE_logger")
    do_stuff(sys.argv[1])
    import time; time.sleep(2*60)
