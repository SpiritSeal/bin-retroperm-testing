import angr

p = angr.Project('../../executables/fopen_example', auto_load_libs=False)


# Create CFG
cfg = p.analyses.CFGFast()

# Get the address of the first instance of fopen in the dictionary