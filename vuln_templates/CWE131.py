import os
import sys
import angr
import logging
from pythonjsonlogger import jsonlogger

from arbiter.master_chief import *

log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                       'logs'))

VERBOSITY = False
LOG_LEVEL = logging.DEBUG

def setup_logger(name):
    fname = os.path.basename(sys.argv[1])

    formatter = jsonlogger.JsonFormatter(fmt='%(asctime)s %(levelname)s %(name)s %(message)s')
    json_handler = logging.FileHandler(log_dir+'/int_ovfl-{}.log'.format(fname))
    json_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.addHandler(json_handler)
    logger.setLevel(LOG_LEVEL)


def do_stuff(fname):
    def constrain(state, expr, init_val, site=None):
        for x in init_val:
            if x.length < expr.length:
                x = x.zero_extend(expr.length-x.length)
            state.solver.add(expr < x)
        return

    bin_file = fname
    project = angr.Project(bin_file, load_options={'auto_load_libs': False})
    maps = {'malloc': ['n'],
            'calloc': ['n'],
            'realloc': ['c', 'n']}

    sa = SA_Recon(project, list(maps.keys()), maps, verbose=VERBOSITY)
    sa.analyze()
    sb = SA_Adv(sa, call_depth=1, require_dd=True, verbose=VERBOSITY)
    sb.analyze_all()
    se = SymExec(sb, constrain, require_dd=True, verbose=VERBOSITY)
    se.run_all()

    reports = se.postprocessing(3)
    for r in reports:
        with open(f"ArbiterReport_{hex(r.bbl)}", "w") as f:
            f.write("\n".join(str(x) for x in r.bbl_history))


if __name__ == '__main__':
    assert len(sys.argv) >= 2, "Usage : %s <binary>" % sys.argv[0]

    setup_logger("arbiter.master_chief.sa_recon")
    setup_logger("arbiter.master_chief.sa_advanced")
    setup_logger("arbiter.master_chief.symbolic_execution")

    do_stuff(sys.argv[1])
