import angr

# Load the binary
proj = angr.Project("../executables/fauxware", auto_load_libs=False)

# Define a function to identify syscall instructions
def is_syscall(state):
    instruction = state.inspect.instruction
    return instruction.opcode == 0x05 and instruction.prefix == 0x0f

# Define the starting state
state = proj.factory.entry_state()

# Create the simulation manager
simgr = proj.factory.simulation_manager(state)

# Explore the binary and find all syscall instructions
simgr.explore(find=is_syscall)

# Print the address of each syscall instruction found
for found_state in simgr.found:
    print(hex(found_state.addr))
