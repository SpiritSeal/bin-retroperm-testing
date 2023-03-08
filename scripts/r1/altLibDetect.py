import angr

# get all the matches
p = angr.Project("../executables/fauxware", auto_load_libs=False)
# note analysis is executed via the Identifier call
idfer = p.analyses.Identifier()
for funcInfo in idfer.func_info:
    print(hex(funcInfo.addr), funcInfo.name)
    # print(dir(funcInfo))
    print(funcInfo.is_plt)
    # temp = funcInfo

# print(dir(temp))

# print()

# print(p.analyses.Identifier()) 