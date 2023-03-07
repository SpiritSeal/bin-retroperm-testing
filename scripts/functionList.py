import angr, monkeyhex
import pyvex

proj = angr.Project('../executables/fauxware', auto_load_libs=False)

# Get all functions in the binary
cfg = proj.analyses.CFGFast()
for func in cfg.kb.functions.values():
    # print("Function: ", func)
    # print start address of function
    print("Start address: ", func.addr)

# # print(proj.loader.all_objects)
# for obj in proj.loader.all_objects:
#     print(obj)
#     print(obj.sections)
    

