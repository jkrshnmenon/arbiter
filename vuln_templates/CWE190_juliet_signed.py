def apply_constraint(state, expr, init_val, **kwargs):
    site = kwargs['site']
    for x in init_val:
        if x.length < expr.length:
            x = x.sign_extend(expr.length-x.length)
        if site.callee == 'printHexCharLine':
            x = x[7:0]
            expr = expr[7:0]
        elif site.callee == 'printIntLine':
            x = x[31:0]
            expr = expr[31:0]
        state.solver.add(expr.SLT(x))


def specify_sinks():
    sinks = [
        'printIntLine',
        'printHexCharLine',
        'printLongLongLine',
        ]
    maps = {x: ['n'] for x in sinks}
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
