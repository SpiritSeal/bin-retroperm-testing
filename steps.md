# Next steps for the project

1. [X] Create a list of libc functions I care about
2. [X] Figure out what arguments of the libc functions can enable malicious code if abused
3. [X] Create a way (likely calling angr) to determinte the calling convention of the binary
**Calling convention mapping
--x86_64: rdi, rsi, rdx, rcx, r8, r9

4. [ ] Once I have the calling convention, figure out what ends up in the libc argument I care about
5. [ ] Create a set of rules to determine if the libc argument is malicious
6. [ ] If a rule is broken, alert the user
