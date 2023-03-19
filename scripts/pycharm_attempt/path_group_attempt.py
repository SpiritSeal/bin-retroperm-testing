import angr

# Set up the angr project
# project = angr.Project("../../executables/fauxware", load_options={'auto_load_libs': False})
project = angr.Project("../../executables/fauxware")

# Set the address of the instruction you want to reach
target_addr = 0x12345678

# Set up the state at the entry point of the binary
entry_state = project.factory.entry_state()

# Set up the path group starting from the entry state
path_group = project.factory.path_group(entry_state)

# Explore all possible paths to reach the target instruction
while len(path_group.active) > 0:
    path_group.step()
    for path in path_group.active:
        if path.addr == target_addr:
            # Print the path leading to the target instruction
            print(path.trace.hardcopy)