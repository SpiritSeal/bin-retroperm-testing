import angr
import pyvex
from angr.procedures.definitions.glibc import _libc_decls

p = angr.Project('../executables/fauxware', auto_load_libs=False)

cfg = p.analyses.CFGFast()

def getCallAddrAndFuncNames():
    '''
    Get the address of the call instruction and the name of the function it calls
    '''
    callDict = {}

    for func in cfg.kb.functions.values():
        for block in func.blocks:
            try :
                irsb = block.vex
                if(irsb.jumpkind == "Ijk_Call"):
                    fromAddr = irsb.addr
                    foundFunc = cfg.kb.functions.function(addr=irsb.next.con.value)
                    if(foundFunc.is_plt or foundFunc.is_syscall):
                        # print(irsb)
                        # print("Called Function name: ", foundFunc.name)
                        callDict[fromAddr] = foundFunc.name
                        # print('\n\n\n\n')
            except:
                pass

    # for key in callDict:
    #     print("Call block address: ", hex(key))
    #     print("Called function name: ", callDict[key])
    #     print()
    return callDict

def matchFuncToSimProc():
    '''
    Match the function name to the simproc
    '''
    callDict = getCallAddrAndFuncNames()
    if not callDict:
        print("No calls found")
        return
    if not _libc_decls:
        print("No simprocs found")
        return
    
    for key in callDict:
        if callDict[key] in _libc_decls:
            print("Call block address: ", hex(key))
            print("Called function name: ", callDict[key])
            print("Simproc: ", _libc_decls[callDict[key]])
        print()
    

def main():
    matchFuncToSimProc()
    pass

if __name__ == '__main__':
    main()