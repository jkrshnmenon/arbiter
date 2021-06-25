import os
import sys
import angr
import logging
from pythonjsonlogger import jsonlogger

from arbiter.master_chief import *

log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                       'logs'))

def setup_logger(name):
    fname = os.path.basename(sys.argv[1])

    formatter = jsonlogger.JsonFormatter(fmt='%(asctime)s %(levelname)s %(name)s %(message)s')
    json_handler = logging.FileHandler(log_dir+'/int_ovfl-{}.log'.format(fname))
    json_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.addHandler(json_handler)
    logger.setLevel(logging.DEBUG)


def do_stuff(fname):
    def constrain(state, expr, init_val):
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

    sa = StaticAnalysisRecon(project, list(maps.keys()), maps, verbose=True)
    sa.analyze()
    sb = StaticAnalysisAdvanced(sa, call_depth=1, require_dd=True, verbose=True)
    sb.analyze_all()
    se = SymbolicExecution(sb, constrain, require_dd=True, verbose=True)
    se.run_all()

    se.postprocessing(3)


if __name__ == '__main__':
    assert len(sys.argv) >= 2, "Usage : %s <binary>" % sys.argv[0]

    setup_logger("SA_recon")
    setup_logger("SA_advanced")
    setup_logger("SE_logger")

    do_stuff(sys.argv[1])
