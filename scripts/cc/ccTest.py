import angr

proj = angr.Project('../../executables/open_example', auto_load_libs=False)

cfg = proj.analyses.CFGFast.prep()()

open_func = cfg.functions['open']
open_addr = open_func.addr

ccca = proj.analyses[angr.analyses.CompleteCallingConventionsAnalysis](recover_variables=True)

print(ccca.kb)
print(dir(ccca.kb.functions))

for i in ccca.kb.functions:
    print(i)
    print(ccca.kb.functions[i].calling_convention)
    # name
    print(ccca.kb.functions[i].name)
    print(ccca.kb.functions[i].arguments)
    if ccca.kb.functions[i].arguments:
        breakpoint()
    print()

# print(dir(proj.analyses))

# Get calling convention
cc = proj.factory.cc()
