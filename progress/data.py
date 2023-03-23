import inspect

import angr
import pprint as pp
from angr.sim_type import SimTypeFunction, \
    SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat, \
    SimTypePointer, \
    SimTypeChar, \
    SimTypeFixedSizeArray, \
    SimTypeBottom, \
    ALL_TYPES


# Save dict of simproc obj to List of int

abusable_funcs = {
    # open: [0: char* pathname, 1: int flags, 2: mode_t mode]
    angr.SIM_PROCEDURES['posix']['open'](): [0, 1],
    # fopen: [0: char* filename, 1: char* mode]
    angr.SIM_PROCEDURES['libc']['fopen'](): [0, 1],
}

if __name__ == '__main__':
    # print(abusable_funcs[0])
    # print(SimTypeFunction(
    #     [SimTypePointer(SimTypeChar(), offset=0), SimTypeInt(signed=True), SimTypeShort(signed=False, label="mode_t")],
    #     SimTypeInt(signed=True), arg_names=["filename", "flags", "mode"]))
    # print((SimTypeFunction(
    #     [SimTypePointer(SimTypeChar(), offset=0), SimTypeInt(signed=True), SimTypeShort(signed=False, label="mode_t")],
    #     SimTypeInt(signed=True), arg_names=["filename", "flags", "mode"])).__hash__())
    # Create a simproc of open
    # print(angr.SIM_PROCEDURES)
    open_simproc = angr.SIM_PROCEDURES['posix']['open']()
    print(dir(open_simproc))
    print(type(open_simproc))
    print(inspect.getmro(type(open_simproc)))
    # pp.pprint(open_simproc)
