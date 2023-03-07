import angr

project = angr.Project('../executables/fauxware', load_options={'auto_load_libs':False})

# Generate CFG
cfg = project.analyses.CFG(fail_fast=True)

