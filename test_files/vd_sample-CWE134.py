#
# An example of a VD for CWE134
# In this example, we target CVE-2018-10388
# https://www.cvedetails.com/cve/CVE-2018-10388
#
# The vulnerability is a format string in the logMess function
# The format string vulnerability can lead to memory corruption and possible arbitrary code execution
#
#     void logMess(request *req, MYBYTE logLevel) {
#         ...
#         if (req->path[0])
#           sprintf(logBuff, "Client %s:%u %s, %s\n", IP2String(tempbuff, req->client.sin_addr.s_addr),  \
#                    ntohs(req->client.sin_port), req->path, req->serverError.errormessage);
#         else
#           sprintf(logBuff, "Client %s:%u, %s\n", IP2String(tempbuff, req->client.sin_addr.s_addr), \
#                    ntohs(req->client.sin_port), req->serverError.errormessage);
# 
#         syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_CRIT), logBuff);
#         ...
#
# The prototype of the syslog function is as follows
# void syslog(int priority, const char *format, ...);
# In this situation, an attacker can control the errormessage string and thereby control the format string used in syslog


#
# The VD that we can generate from this information is as follows
# Sink := syslog(c, n)
# Source := sprintf(n, c)
# Constraint := `logBuff` should not be a constant string.
# In this example, if we can identify a data-dependency between the sprintf and the syslog api's, it could lead to a vulnerability.
#


def apply_constraints(state, expr, init_val, **kwargs):
    #
    # Here, expr represents `logBuff`.
    # If logBuff was a constant string, the `addr` would contain the address of this string in the binary.
    # We then check if this address is part of the binary or not.
    # If the address is a part of the binary, it is a constant string and therefore cannot be controlled.
    # So we generate a constraint that we are sure will lead to an unsat state.
    #
    # Given that our source is sprintf, it is unlikely that we run into this problem of constant strings.
    # However, in order to be generic, we keep this constraint
    #
    addr = state.solver.eval(expr, cast_to=int)
    if state.project.loader.find_section_containing(addr) is not None:
        # Force an unsat error
        state.solver.add(expr==0)
    return


def specify_sources():
    # Our source here is sprintf
    # The first argument of sprintf is `logBuff`.
    return {'sprintf': 1}


def specify_sinks():
    # Note that the second argument of syslog denotes the format string to use.
    # This is similar to sprintf, dprintf, fprintf functions.
    maps = {'syslog': ['c', 'n']}
    return maps


def save_results(reports):
    return
