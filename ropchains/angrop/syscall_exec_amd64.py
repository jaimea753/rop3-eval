"""angrop recipe — execve("/bin/sh", NULL, NULL) on x86-64.

Mirror of ropchains/rop3/syscall_exec_amd64.txt and
ropchains/ropper/syscall_exec_amd64.spec (execve=/bin/sh). angrop's execve()
helper stages the "/bin/sh" string into a writable region and emits the syscall,
picking the arch-correct syscall number itself.
"""


def build(project, rop):
    return rop.execve(path=b"/bin/sh")
