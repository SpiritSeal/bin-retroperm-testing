import angr
# Get the address of the first instance of fopen in the dictionary
import pprint
import os
import monkeyhex

proj = angr.Project('../../executables/fauxware', load_options={'auto_load_libs': False})

# List all of the names of the functions in the binary
# print(proj.loader.main_object.symbols_by_name)
pprint.pprint(proj.loader.main_object.symbols_by_name)

# Detect what arguments are passed to printf
# print(proj.loader.main_object.get_symbol('printf').rebased_addr)
printf_addr = proj.loader.main_object.get_symbol('printf').rebased_addr
state = proj.factory.blank_state(addr=printf_addr)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=printf_addr)
found = simgr.found[0]
pprint.pprint(found.solver.eval_upto(found.regs.rdi, 10))
