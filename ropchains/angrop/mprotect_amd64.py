"""angrop recipe — mprotect(0x1000, 0x1000, PROT_READ|WRITE|EXEC) on x86-64.

Mirror of ropchains/rop3/mprotect_amd64.txt and ropchains/ropper/mprotect_amd64.spec:
make a page RWX by invoking the mprotect syscall (nr 10 on x86-64) with a
page-aligned base, a region length, and prot bits 7. Terminal syscall, so no
return gadget is required afterwards.
"""

MPROTECT_SYSCALL = 10          # __NR_mprotect on x86-64
PROT_RWX = 7                   # PROT_READ | PROT_WRITE | PROT_EXEC


def build(project, rop):
    return rop.do_syscall(MPROTECT_SYSCALL, [0x1000, 0x1000, PROT_RWX],
                          needs_return=False)
