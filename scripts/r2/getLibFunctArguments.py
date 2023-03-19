# getLibFunctArguments.py
# This script is used to get the arguments with which a function is being called

import angr
import pyvex

p = angr.Project('../../executables/fopen_example', auto_load_libs=False)

cfg = p.analyses.CFGFast()

def getCallAddrAndFuncNames():
    '''
    Get the address of the call instruction and the name of the function it calls
    '''
    callDict = {}

    for func in cfg.kb.functions.values():
        for block in func.blocks:
            try:
                irsb = block.vex
                if(irsb.jumpkind == "Ijk_Call"):
                    fromAddr = irsb.addr
                    foundFunc = cfg.kb.functions.function(addr=irsb.next.con.value)
                    if(foundFunc.is_plt or foundFunc.is_syscall):
                        callDict[fromAddr] = foundFunc.name
            except:
                pass
    return callDict

def getFOpenArguments():
    '''
    Get the arguments with which the function fopen is being called
    '''
    callDict = getCallAddrAndFuncNames()
    
    # Find the address of the first instance of fopen in the dictionary
    fopenAddr = [k for k, v in callDict.items() if v == 'fopen'][0]

    print("Address of the first instance of fopen: ", hex(fopenAddr))

    # Resolve the arguments with which fopen is being called
    fopenFunc = cfg.kb.functions.function(addr=fopenAddr)
    fopenBlock = fopenFunc.blocks[0]
    fopenIRSB = fopenBlock.vex


def main():
    getFOpenArguments()
    pass


if __name__ == '__main__':
    main()