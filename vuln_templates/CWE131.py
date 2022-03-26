def apply_constraint(state, expr, init_val, **kwargs):
    for x in init_val:
        if x.length > expr.length:
            continue
        if x.length < expr.length:
            x = x.zero_extend(expr.length-x.length)
        state.solver.add(expr < x)
    return


<<<<<<< HEAD
def specify_sinks():
=======
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
>>>>>>> f5a9c13 (additional argument for constrain function)
    maps = {'malloc': ['n'],
            'calloc': ['n'],
            'realloc': ['c', 'n']}

    return maps


def specify_sources():
    return {}


def save_results(reports):
    for r in reports:
        with open(f"ArbiterReport_{hex(r.bbl)}", "w") as f:
            f.write("\n".join(str(x) for x in r.bbl_history))
