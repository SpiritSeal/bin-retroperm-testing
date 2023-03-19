import angr

proj = angr.Project('../../executables/fauxware', load_options={'auto_load_libs': False})

# Write a program that will find every call to the printf function in the binary
# and print out the arguments passed to printf.

# Start code
# Create a blank state
state = proj.factory.blank_state(addr=proj.entry)

# Create a simulation manager
simgr = proj.factory.simulation_manager(state)

# explore the binary until all states have reached a dead end
while len(simgr.active) > 0:
    # step forward in the simulation manager
    simgr.step()

    # loop over all active states and print the instruction and register values
    for active_state in simgr.active:
        # print memory address of instruction
        print("Address: {}".format(hex(active_state.addr)))
        # get the instruction at the current address from the proj variable
        instruction = proj.factory.block(active_state.addr).capstone.insns[0].mnemonic
        # print the instruction if it is a jmp
        print("Instruction: {}".format(instruction))
        if instruction == "jmp":
            print("Register values:")
            for register in active_state.arch.registers:
                value = active_state.solver.eval(active_state.regs.__getattr__(register))
                if value != 0:
                    print("{}: {}".format(register, hex(value)))
        print("-------------------------------")
