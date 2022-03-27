def apply_constraint(state, expr, init_val, **kwargs):
    for x in init_val:
        if x.length < expr.length:
            x = x.zero_extend(expr.length-x.length)
        state.solver.add(expr < x)


def specify_sinks():
    maps = {'malloc': ['n'], 'operator new': ['n']}
    return maps


def specify_sources():
    checkpoints = {'atoi': 0,
                   'rand': 0,
                   'fscanf': 3,
                   'badSource': 0}

    return checkpoints


def save_results(reports):
    for r in reports:
        with open(f"ArbiterReport_{hex(r.bbl)}", "w") as f:
            f.write("\n".join(str(x) for x in r.bbl_history))
