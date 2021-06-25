import os
import sys
import angr
import logging
from pythonjsonlogger import jsonlogger

import arbiter
from arbiter.master_chief import *


log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                       'logs'))


def setup_logger(name):
    fname = os.path.basename(sys.argv[1])

    formatter = jsonlogger.JsonFormatter(fmt='%(asctime)s %(levelname)s %(name)s %(message)s')
    json_handler = logging.FileHandler(log_dir+'/fmt-{}.log'.format(fname))
    json_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.addHandler(json_handler)
    logger.setLevel(logging.DEBUG)


def do_stuff(fname):
    def constrain(state, expr, init_val, site=None):
        addr = state.solver.eval(expr, cast_to=int)
        if state.project.loader.find_section_containing(addr) is not None:
            # Force an unsat error
            state.solver.add(expr==0)
        return  

    bin_file = fname
    project = angr.Project(bin_file, load_options={'auto_load_libs': False})

    maps = {'printf': ['n'],
            'fprintf': ['c', 'n'],
            'dprintf': ['c', 'n'],
            'sprintf': ['c', 'n'],
            'vasprintf': ['c', 'n'],
            'snprintf': ['c', 'c', 'n'],
            'fprintf_chk': ['c', 'c', 'n'],
            'dprintf_chk': ['c', 'c', 'n'],
            'sprintf_chk': ['c', 'c', 'c', 'n'],
            'vasprintf_chk': ['c', 'c', 'n'],
            'asprintf_chk': ['c', 'c', 'n'],
            'snprintf_chk': ['c', 'c', 'c', 'c', 'n'],
            }
    sink = list(maps.keys())

    sa = StaticAnalysisRecon(project, sink, maps, verbose=True)
    sa.analyze()
    sb = StaticAnalysisAdvanced(sa, require_dd=True, call_depth=1, verbose=True)
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
