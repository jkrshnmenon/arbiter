def apply_constraint(state, expr, init_val, **kwargs):
    for x in init_val:
        if x.length < expr.length:
            x = x.zero_extend(expr.length-x.length)
        state.solver.add(expr < x)
    return


def specify_sinks():
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
