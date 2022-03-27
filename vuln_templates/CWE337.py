def apply_constraint(state, expr, init_val, **kwargs):
    return


<<<<<<< HEAD
def specify_sinks():
=======
import arbiter
from arbiter.master_chief import *


log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                       'logs'))


def setup_logger(name):
    fname = os.path.basename(sys.argv[1])

    formatter = jsonlogger.JsonFormatter(fmt='%(asctime)s %(levelname)s %(name)s %(message)s')
    json_handler = logging.FileHandler(log_dir+'/prng-{}.log'.format(fname))
    json_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.addHandler(json_handler)
    logger.setLevel(logging.DEBUG)


def do_stuff(fname):
    def constrain(state, expr, init_val, site=None):
        return  

    bin_file = fname
    project = angr.Project(bin_file, load_options={'auto_load_libs': False})
    sink = ['srand']
>>>>>>> f5a9c13 (additional argument for constrain function)
    maps = {'srand': ['n']}
    return maps


def specify_sources():
    checkpoints = {'time': 0}
    return checkpoints

<<<<<<< HEAD
=======
    setup_logger("arbiter.master_chief.sa_recon")
    setup_logger("arbiter.master_chief.sa_advanced")
    setup_logger("arbiter.master_chief.symbolic_execution")
>>>>>>> 85fcd35 (Fixing logging)

def save_results(reports):
    for r in reports:
        with open(f"ArbiterReport_{hex(r.bbl)}", "w") as f:
            f.write("\n".join(str(x) for x in r.bbl_history))