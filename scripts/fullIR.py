import angr
import pyvex

p = angr.Project('../executables/fauxware', auto_load_libs=False)

cfg = p.analyses.CFGFast()


for func in cfg.kb.functions.values():
    for block in func.blocks:
        # print irsb
        try :
            irsb = block.vex
            print(irsb.pp())
            for stmt in irsb.statements:
                # print(stmt)
                pass
        except:
            print("Error in block: ", block)
