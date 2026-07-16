/* Self-checking ptrace(2) regression test (emulator-only: qemu-user's ptrace
 * emulation is too incomplete to serve as the differential oracle, so this
 * asserts the expected behavior itself and prints a single OK/FAIL line).
 *
 * Exercises: PTRACE_TRACEME + execve stop, PTRACE_SETOPTIONS(TRACESYSGOOD),
 * PTRACE_SYSCALL entry/exit stops, GETREGSET(NT_PRSTATUS), SETREGSET identity,
 * PEEKTEXT/PEEKDATA + POKEDATA round-trip, and real child-exit collection. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#define CHILD_EXIT 42

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(int argc, char **argv) {
    if (argc > 1) {                        /* re-exec'd tracee body */
        syscall(SYS_getpid);               /* distinctive syscall to spot */
        _exit(CHILD_EXIT);
    }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("/proc/self/exe", argv[0], "tracee", (char *)NULL);
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid(exec-stop)");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        return fail("exec stop not SIGTRAP");

    struct user_regs_struct regs;
    struct iovec iov = { &regs, sizeof regs };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0)
        return fail("GETREGSET at exec stop");
    if (regs.pc == 0) return fail("exec-stop pc is 0");

    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACESYSGOOD);

    int getpid_seen = 0, peekpoke_ok = 0, setregs_ok = 0, childexit = -1;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) return fail("PTRACE_SYSCALL");
        if (waitpid(pid, &status, 0) != pid) return fail("waitpid(loop)");
        if (WIFEXITED(status)) { childexit = WEXITSTATUS(status); break; }
        if (WIFSIGNALED(status)) return fail("tracee killed by signal");
        if (!WIFSTOPPED(status)) return fail("not stopped");
        if (WSTOPSIG(status) != (SIGTRAP | 0x80)) continue;   /* not a syscall stop */

        iov.iov_base = &regs;
        iov.iov_len = sizeof regs;
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0)
            return fail("GETREGSET at syscall stop");

        /* SETREGSET identity: writing the same registers back must succeed. */
        if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0)
            setregs_ok = 1;

        /* PEEKTEXT at pc must read a word without error. */
        errno = 0;
        ptrace(PTRACE_PEEKTEXT, pid, (void *)(unsigned long)regs.pc, 0);
        int peektext_ok = (errno == 0);

        /* PEEKDATA/POKEDATA round-trip at the top of the tracee stack (restored
         * before resume, so no observable effect on the tracee). */
        unsigned long sp = (unsigned long)regs.sp;
        errno = 0;
        long saved = ptrace(PTRACE_PEEKDATA, pid, (void *)sp, 0);
        if (errno == 0 &&
            ptrace(PTRACE_POKEDATA, pid, (void *)sp, (void *)0x1234abcdUL) == 0) {
            errno = 0;
            long got = ptrace(PTRACE_PEEKDATA, pid, (void *)sp, 0);
            if (errno == 0 && got == 0x1234abcdL) peekpoke_ok = 1;
            ptrace(PTRACE_POKEDATA, pid, (void *)sp, (void *)saved);   /* restore */
        }

        if (peektext_ok && regs.regs[8] == SYS_getpid) getpid_seen = 1;
    }

    if (childexit != CHILD_EXIT) return fail("wrong child exit code");
    if (!getpid_seen)  return fail("getpid syscall stop not observed");
    if (!setregs_ok)   return fail("SETREGSET failed");
    if (!peekpoke_ok)  return fail("PEEK/POKE round-trip failed");
    printf("OK\n");
    return 0;
}
