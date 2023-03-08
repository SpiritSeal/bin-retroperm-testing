import angr, monkeyhex
import pyvex


def print_only_externs():
    proj = angr.Project('../executables/fauxware', auto_load_libs=False)
    # Get all functions in the binary
    cfg = proj.analyses.CFGFast()
    for func in cfg.kb.functions.values():
        
        if(func.is_plt or func.is_syscall):
            # print("Function: ", func)
            # print(func.pp())
            print("Function name: ", func.name)
            print("Start address: ", func.addr)
            print()


def main():
    proj = angr.Project('../executables/fauxware', auto_load_libs=False)
    # Get all functions in the binary
    cfg = proj.analyses.CFGFast()
    for func in cfg.kb.functions.values():
        # print("Function: ", func)
        # print(func.pp())
        # print(dir(func))
        print("Function name: ", func.name)
        print("Start address: ", func.addr)
        print("Is it a library function? ", func.is_plt)
        print("Is it a syscall? ", func.is_syscall)
        print()


if __name__ == '__main__':
    # main()
    print_only_externs()
