def apply_constraint(state, expr, init_val, **kwargs):
    addr = state.solver.eval(expr, cast_to=int)
    if state.project.loader.find_section_containing(addr) is not None:
        # Force an unsat error
        state.solver.add(expr==0)
    return


def specify_sinks():
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

    return maps


def specify_sources():
    return {}


def save_results(reports):
    for r in reports:
        with open(f"ArbiterReport_{hex(r.bbl)}", "w") as f:
            f.write("\n".join(str(x) for x in r.bbl_history))
