import angr

p = angr.Project('../../executables/fauxware', auto_load_libs=False)

# Determine the function calling convention of the binary
print(dir(p.factory.cc().arg_locs))
# print(p.factory)
# print(angr.calling_conventions.CC)
