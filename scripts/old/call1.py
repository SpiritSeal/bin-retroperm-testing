# This script is used to find all call instructions in a binary.

import angr
# p = angr.Project('../executables/fauxware', auto_load_libs=False)
p = angr.Project('../executables/objdump_ubuntu18_stripped', auto_load_libs=False)

cfg = p.analyses.CFGFast()

for func in cfg.kb.functions.values():
    for block in func.blocks:
        for instruction in block.capstone.insns:
            if instruction.mnemonic == 'call':
                print("Found call instruction at", hex(instruction.address))
                print(">",instruction)
