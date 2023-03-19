import angr

proj = angr.Project('../../executables/fauxware')
target_addr = 0x123456

state = proj.factory.entry_state()
sm = proj.factory.simgr(state)

while len(sm.active) > 0:
    sm.step()
    for s in sm.active:
        if s.addr == target_addr:
            print("Path found:")
            print(s.posix.dumps(0)) # Print the input that reaches the target instruction
            sm.stash(from_stash='active', to_stash='found')
