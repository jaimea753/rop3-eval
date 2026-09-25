"""angrop recipe — mprotect(0x1000, 0x1000, PROT_READ|WRITE|EXEC) on x86 (32-bit).

Mirror of ropchains/rop3/mprotect_x86.txt and ropchains/ropper/mprotect_x86.spec.
mprotect is syscall nr 125 on i386. Terminal syscall, no return gadget needed.
"""

MPROTECT_SYSCALL = 125         # __NR_mprotect on i386
PROT_RWX = 7                   # PROT_READ | PROT_WRITE | PROT_EXEC


def build(project, rop):
    return rop.do_syscall(MPROTECT_SYSCALL, [0x1000, 0x1000, PROT_RWX],
                          needs_return=False)
