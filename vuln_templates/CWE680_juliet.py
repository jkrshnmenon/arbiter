import os
import sys
import angr
import logging
from pythonjsonlogger import jsonlogger

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
            if x.length < expr.length:
                x = x.zero_extend(expr.length-x.length)
            state.solver.add(expr < x)

    maps = {'malloc': ['n'], 'operator new': ['n']}
    sinks = list(maps.keys())
    checkpoints = {'atoi': 0,
                   'rand': 0,
                   'fscanf': 3,
                   'badSource': 0}

    bin_file = os.path.join(bin_dir, fname)
    project = angr.Project(bin_file, load_options={'auto_load_libs': False})

    sa = SA_Recon(project, sinks, maps)
    sa.analyze()
    # sa.analyze_one(0x805d8ba)

    sb = SA_Adv(sa, checkpoints, require_dd=False, call_depth=1)
    sb.analyze_all()

    se = SymExec(sb, constrain, require_dd=False)
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
