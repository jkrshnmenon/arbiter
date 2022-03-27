#
# An example of a VD for CWE131
# In this example, we target CVE-2017-1000158
# https://nvd.nist.gov/vuln/detail/CVE-2017-1000158
#
# The vulnerability is an integer overflow in PyString_DecodeEscape function
# inside stringobject.c and exists in CPython upto 2.7.13
# The integer overflow can lead to heap-based buffer overflow and possible arbitrary code execution
#
#     PyObject *PyString_DecodeEscape(const char *s, Py_ssize_t len,  const char *errors,
#                                     Py_ssize_t unicode, const char *recode_encoding) {
#         ...
# (1)     Py_ssize_t newlen = recode_encoding ? 4*len:len;
# (2)     v = PyString_FromStringAndSize((char *)NULL, newlen);
#         ...
# (3)     p = buf = PyString_AsString(v);
#         ...
# (4)     if (p-buf < newlen)
#             _PyString_Resize(&v, p - buf); /* v is cleared on error */
#         return v;
#
# (1) If recode_encoding is true (i.e., non-null), we have an integer
#       overflow here which can set newlen to be some very small value
# (2) This allows a small string to be created into v
# (3) Now p (and buf) use that small string
# (4) The small string is copied into with a larger string, thereby
#       giving a heap buffer overflow


#
# The VD that we can generate from this information is as follows
# Sink := PyString_FromStringAndSize
# Source := None
# Constraint := Value of `newlen` should not be smaller than value of `len`.
#


def apply_constraints(state, expr, init_val, **kwargs):
    #
    # Here, expr represents `newlen`.
    # The init_val can be represented a list of values that were combined to produce `newlen`
    # It can be visualized as : [len, 4]
    # However, since 4 is a constant, the actual init_val looks like : [len]
    #
    for x in init_val:
        if x.length < expr.length:
            x = x.zero_extend(expr.length-x.length)
        state.solver.add(expr < x)
    return


def specify_sources():
    return {}


def specify_sinks():
    # Note that the second argument of PyString_FromStringAndSize denotes the size of the buffer to be allocated.
    # This is similar to realloc

    maps = {'PyString_FromStringAndSize': ['c', 'n']}
    return maps


def save_results(reports):
    return
