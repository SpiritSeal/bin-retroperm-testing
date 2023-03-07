import angr
import pyvex

proj = angr.Project('../executables/fauxware', auto_load_libs=False)
addr = proj.loader.main_object.get_symbol('main').rebased_addr
block = proj.factory.block(addr)
print(block.vex.pp())
