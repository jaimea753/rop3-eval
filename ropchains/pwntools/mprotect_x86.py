"""pwntools recipe — mprotect(0x1000, 0x1000, PROT_READ|WRITE|EXEC) on x86 (32-bit).

Mirror of ropchains/rop3/mprotect_x86.txt and the angrop recipe. pwntools
resolves the mprotect() export and assembles the argument-register setup; the
worker calls rop.chain() afterwards. Unresolvable on a target without the symbol
(reported not-found).
"""

PROT_RWX = 7   # PROT_READ | PROT_WRITE | PROT_EXEC


def build(elf, rop):
    rop.call("mprotect", [0x1000, 0x1000, PROT_RWX])
