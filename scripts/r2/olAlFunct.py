import angr
import claripy
import argparse

#angr logging is way too verbose
import logging
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

def main():
    #file_name = "/home/chris/----/binaries/crackme/crackme0x04"
    #Download crackme file from https://github.com/angr/angr-doc/raw/master/examples/CSCI-4968-MBE/challenges/crackme0x04/crackme0x04

    parser = argparse.ArgumentParser()
    parser.add_argument("File")

    args = parser.parse_args()

    file_name = args.File
    
    crack_me_good_addr = 0x80484dc
    function_name = "check"

    p = angr.Project(file_name)

    #Populates project knowledge base...
    #CFG no longer needed
    CFG = p.analyses.CFGEmulated()

    #Look at all my functions!
    find_func = None
    for func in p.kb.functions.values():
        #print(func.name)
        if function_name in func.name:
            find_func = func

    print("[+] Function {}, found at {}".format(find_func.name, hex(find_func.addr)))

    #Build function prototype
    charstar = angr.sim_type.SimTypePointer(angr.sim_type.SimTypeChar())
    prototype = angr.sim_type.SimTypeFunction((charstar,), angr.sim_type.SimTypeInt(False))

    #Calling convention
    cc = p.factory.cc(func_ty=prototype)

    check_func = p.factory.callable(find_func.addr, concrete_only=False, cc=cc)

    my_sym_arg = claripy.BVS('my_arg', 10*8) #10 byte long str

    my_args = ["abcd", "96", "87", "55", "qqqq"]

    print("[+] Running angr callable with concrete arguments")
    #Solution is "96"... or "87"
    for arg in my_args:
        ret_val = check_func(arg)
        stdout = check_func.result_state.posix.dumps(1)

        print("Input  : {}".format(arg))
        print("Stdout : {}".format(stdout))

    #The callable waits till ALL paths finish...
    #The below code will take FOREVER, since it keeps
    #Forking off new paths
    '''
    ret_val = check_func(my_sym_arg)
    stdout = check_func.result_state.posix.dumps(1)
    print("Stdout : {}".format(stdout))
    '''

    print("[+] Running modified angr callable with symbolic arguments")

    #Instead try this
    #Build a callable state using that calling convention we defined earlier
    state = p.factory.call_state(find_func.addr, my_sym_arg, cc=cc)
    simgr = p.factory.simgr(state)
    simgr.explore(find=crack_me_good_addr)

    if len(simgr.found):
        found_state = simgr.found[0]
        my_input = found_state.se.eval(my_sym_arg, cast_to=bytes).decode("utf-8", "ignore")
        print("One solution : {}".format(my_input))
        solutions = found_state.se.eval_upto(my_sym_arg, 20, cast_to=bytes)
        for soln in solutions:
            print("Many solutions : {}".format(soln.decode('utf-8', 'ignore')))


if __name__ == "__main__":
    main()