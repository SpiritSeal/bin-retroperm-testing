# Arg locations of functions in binary
from typing import List
import angr
from angr.analyses import CompleteCallingConventionsAnalysis


def get_arg_locations(func: angr.knowledge_plugins.functions.function.Function) -> \
        List[angr.calling_conventions.SimRegArg]:
    """
    Get the argument locations of a function
    """
    # TODO: Assert Calling Convention exists

    return func.arguments

def get_abusable_arg_locations(func: angr.knowledge_plugins.functions.function.Function) -> \
        List[angr.calling_conventions.SimRegArg]:
    """
    Get the argument locations of a function that are potentially abusable
    """




if __name__ == "__main__":
    proj = angr.Project('../executables/open_example', auto_load_libs=False)

    cfg = proj.analyses.CFGFast()

    open_func = cfg.functions['open']
    open_addr = open_func.addr

    ccca = proj.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

    # ccca = proj.analyses.CompleteCallingConventionsAnalysis(recover_variables=True)

    for i in ccca.kb.functions:
        # print(i)
        # print(ccca.kb.functions[i].calling_convention)
        print(ccca.kb.functions[i].name)
        # if ccca.kb.functions[i].arguments:
        #     print(type(ccca.kb.functions[i].arguments[0]))
        # print(type(ccca.kb.functions[i]))
        print(get_arg_locations(ccca.kb.functions[i]))
        print()
