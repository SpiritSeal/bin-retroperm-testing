# This script is used to find all call instructions in a binary.

import angr
import pyvex

p = angr.Project('../executables/fauxware', auto_load_libs=False)
# p = angr.Project('../executables/objdump_ubuntu18_stripped', auto_load_libs=False)

cfg = p.analyses.CFGFast()

callBlocks = list()

for func in cfg.kb.functions.values():
    for block in func.blocks:
        for instruction in block.capstone.insns:
            if instruction.mnemonic == 'call':
                # print("Found call instruction at", hex(instruction.address))
                # print(">",instruction)
                callBlocks.append(block)


# Unique List without changing order
callBlocks = list(dict.fromkeys(callBlocks))


for block in callBlocks:
    # print("block: ", block)
    
    irsb = block.vex
    # print("NEW SECTION!")
    # print("irsb: ", irsb, end="\n\n")


    for stmt in irsb.statements:
        print("stmt: ", stmt)
        
        # if isinstance(stmt, pyvex.stmt.IMark) and stmt.insn_name.startswith('call'):
        #     print("* Found call instruction at", hex(stmt.addr))
    print("\n\n\n\n")
