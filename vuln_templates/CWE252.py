import json


SYSCALL_TABLE = "syscalls_annotated.json"


def parse_syscalls(syscall_table, return_filter=None):
    maps = {}
    checkpoints = {}
    syscalls = {}

    with open(syscall_table) as f:
        syscalls = json.load(f)

    for syscall, s_info in syscalls.items():
        ret = s_info['ret']
        if not ret:
            continue
        if return_filter != None:
            values = ret['values']
            if str(return_filter) not in values or values[str(return_filter)] != 'error':
                continue
        print(f"syscall: {syscall}")
        maps[syscall] = ['r']
        checkpoints[syscall] = 0

    return maps, checkpoints


def apply_constraint(state, expr, init_val, **kwargs):
    s1 = state.copy()
    # target function returned -1 (indicating error)
    s1.solver.add(init_val[0] == 0xffffffffffffffff)
    if s1.satisfiable():
        # target function allows both (indicating absence of checks)
        state.solver.add(init_val[0] == 0)
    else:
        # Unsat the whole thing
        state.solver.add(init_val[0] == 0xffffffffffffffff)
    return


def specify_sinks():
    maps, _ = parse_syscalls(SYSCALL_TABLE, return_filter=-1)
    return maps


def specify_sources():
    _, checkpoints = parse_syscalls(SYSCALL_TABLE, return_filter=-1)
    return checkpoints


def save_results(reports):
    for r in reports:
        with open(f"ArbiterReport_{hex(r.bbl)}", "w") as f:
            f.write("\n".join(str(x) for x in r.bbl_history))
