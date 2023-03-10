import angr

# Define the binary and the function to analyze
binary = "../../executables/fopen_example"
function_name = "open"

# Create an angr project and load the binary into it
project = angr.Project(binary, auto_load_libs=False)

project.analyses.CFGFast()

# # list all functions in binary
# for func in project.kb.functions.values():
#     print(func)

# exit(0)

# Define the function to analyze
function = project.kb.functions[function_name]

# Get the start address of the function
start_address = function.startpoint.addr

# Create a block at the start address of the function
block = project.factory.block(start_address)

# Create a simulation state with symbolic values for each argument
state = project.factory.call_state(start_address)

# Define a procedure that prints the values of each argument
class PrintArguments(angr.SimProcedure):
    def run(self, args):
        for i, arg in enumerate(args):
            print(f"Argument {i}: {self.state.solver.eval(arg)}")

# Execute the simulation and print the results
simulation = project.factory.simgr(state)
simulation.use_technique(angr.exploration_techniques.Explorer(find=(start_address+block.size,), avoid=()))
simulation.use_technique(angr.exploration_techniques.Veritesting())
simulation.run()

if simulation.found:
    print("Arguments:")
    simulation.found[0].eval(PrintArguments(args=function.arguments))
