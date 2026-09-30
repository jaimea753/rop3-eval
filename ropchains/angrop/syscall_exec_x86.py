"""angrop recipe — execve("/bin/sh", NULL, NULL) on x86 (32-bit).

Mirror of ropchains/rop3/syscall_exec_x86.txt and
ropchains/ropper/syscall_exec_x86.spec (execve=/bin/sh). angrop's execve() helper
stages the path string and emits the i386 execve syscall.
"""


def build(project, rop):
    return rop.execve(path="/bin/sh")
