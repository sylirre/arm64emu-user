/* Self-checking test: the ptrace options, as the kernel takes them.
 *
 * PTRACE_O_EXITKILL is 1 << 20 and PTRACE_O_SUSPEND_SECCOMP 1 << 21; any other
 * bit past the low eight is none -- SETOPTIONS says EINVAL, SEIZE EIO, as does
 * a SEIZE with an address. SUSPEND_SECCOMP is a checkpointer's: EPERM without
 * the privilege. PTRACE_O_TRACESECCOMP has a seccomp filter's RET_TRACE stop
 * the tracee with PTRACE_EVENT_SECCOMP, the filter's data as the event message,
 * where the tracer may let the call run, change it into another -- which the
 * filter judges again, a second RET_TRACE letting it through -- or skip it
 * with a result of its own; with nobody asking, RET_TRACE is ENOSYS. The
 * emulator took EXITKILL as 1 << 8, masked the real bit away and every other
 * one along with it, and answered RET_TRACE with ENOSYS whatever the tracer
 * had asked for. Architecture-neutral: the host kernel runs it the same way.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define O_TRACESECCOMP   0x80L
#define O_EXITKILL       0x100000L
#define O_SUSPEND_SECCOMP 0x200000L
#define EV_SECCOMP       7
#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

static int fail(const char *what) { printf("FAIL: %s (errno %d)\n", what, errno); return 1; }

/* The syscall number and the first register, at a stop. */
static int set_nr(pid_t k, long nr) {
#if defined(__aarch64__)
    int n = (int)nr;
    struct iovec iov = { &n, sizeof n };
    return (int)ptrace(PTRACE_SETREGSET, k, NT_ARM_SYSTEM_CALL, &iov);
#elif defined(__x86_64__)
    return (int)ptrace(PTRACE_POKEUSER, k, offsetof(struct user_regs_struct, orig_rax), nr);
#endif
}
static int set_ret(pid_t k, long v) {
#if defined(__aarch64__)
    struct user_regs_struct r;
    struct iovec iov = { &r, sizeof r };
    if (ptrace(PTRACE_GETREGSET, k, NT_PRSTATUS, &iov)) return -1;
    r.regs[0] = (unsigned long)v;
    return (int)ptrace(PTRACE_SETREGSET, k, NT_PRSTATUS, &iov);
#elif defined(__x86_64__)
    return (int)ptrace(PTRACE_POKEUSER, k, offsetof(struct user_regs_struct, rax), v);
#endif
}

/* The tracee: a filter tracing getppid (data 0x42), then three calls, whose
 * results it reports. */
static void tracee(int res) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | 0x42),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = { sizeof f / sizeof *f, f };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p)) _exit(9);
    raise(SIGSTOP);                          /* the tracer is attached */
    long r[3];
    for (int i = 0; i < 3; i++) {
        errno = 0;
        r[i] = syscall(SYS_getppid);
        if (r[i] < 0) r[i] = -errno;
    }
    if (write(res, r, sizeof r) != (ssize_t)sizeof r) _exit(8);
    _exit(0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int st;
    pid_t me = getpid();

    /* The bits. */
    pid_t k = fork();
    if (k == 0) { for (;;) pause(); }
    errno = 0;
    if (ptrace(PTRACE_SEIZE, k, 0, 0x100L) != -1 || errno != EIO) return fail("SEIZE bit 8");
    errno = 0;
    if (ptrace(PTRACE_SEIZE, k, (void *)8, 0) != -1 || errno != EIO) return fail("SEIZE addr");
    errno = 0;
    if (ptrace(PTRACE_SEIZE, k, 0, O_SUSPEND_SECCOMP) != -1 || errno != EPERM)
        return fail("SEIZE SUSPEND_SECCOMP");
    if (ptrace(PTRACE_SEIZE, k, 0, O_EXITKILL | O_TRACESECCOMP)) return fail("SEIZE EXITKILL");
    if (ptrace(PTRACE_INTERRUPT, k, 0, 0) || waitpid(k, &st, __WALL) != k) return fail("stop");
    errno = 0;
    if (ptrace(PTRACE_SETOPTIONS, k, 0, 0x100L) != -1 || errno != EINVAL)
        return fail("SETOPTIONS bit 8");
    errno = 0;
    if (ptrace(PTRACE_SETOPTIONS, k, 0, 0x400000L) != -1 || errno != EINVAL)
        return fail("SETOPTIONS bit 22");
    errno = 0;
    if (ptrace(PTRACE_SETOPTIONS, k, 0, O_SUSPEND_SECCOMP) != -1 || errno != EPERM)
        return fail("SETOPTIONS SUSPEND_SECCOMP");
    if (ptrace(PTRACE_SETOPTIONS, k, 0, O_EXITKILL)) return fail("SETOPTIONS EXITKILL");
    kill(k, SIGKILL);
    waitpid(k, &st, __WALL);

    /* RET_TRACE with nobody asking: ENOSYS, three times. */
    int rp[2];
    if (pipe(rp)) return 1;
    k = fork();
    if (k == 0) tracee(rp[1]);
    if (waitpid(k, &st, WUNTRACED) != k || !WIFSTOPPED(st)) return fail("untraced stop");
    kill(k, SIGCONT);
    long r[3];
    if (read(rp[0], r, sizeof r) != (ssize_t)sizeof r) return fail("untraced result");
    if (r[0] != -ENOSYS || r[1] != -ENOSYS || r[2] != -ENOSYS) {
        printf("FAIL: untraced RET_TRACE: %ld %ld %ld\n", r[0], r[1], r[2]);
        return 1;
    }
    waitpid(k, &st, 0);

    /* Traced with TRACESECCOMP: let the first run, turn the second into
     * getpid (judged again, allowed), skip the third with 77. */
    k = fork();
    if (k == 0) tracee(rp[1]);
    if (waitpid(k, &st, WUNTRACED) != k || !WIFSTOPPED(st)) return fail("traced stop");
    if (ptrace(PTRACE_SEIZE, k, 0, O_TRACESECCOMP)) return fail("SEIZE");
    kill(k, SIGCONT);
    unsigned long msg;
    for (int i = 0; i < 3; ) {
        if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st)) return fail("event wait");
        int ev = st >> 16;
        if (ev != EV_SECCOMP) {                    /* the stop/continue traps */
            if (ptrace(PTRACE_CONT, k, 0, WSTOPSIG(st) == SIGCONT ? SIGCONT : 0)) return fail("cont");
            continue;
        }
        if (WSTOPSIG(st) != SIGTRAP) return fail("event signal");
        if (ptrace(PTRACE_GETEVENTMSG, k, 0, &msg) || msg != 0x42) return fail("event message");
        if (i == 1 && set_nr(k, SYS_getpid)) return fail("set nr");
        if (i == 2 && (set_nr(k, -1) || set_ret(k, 77))) return fail("skip");
        if (ptrace(PTRACE_CONT, k, 0, 0)) return fail("cont event");
        i++;
    }
    if (read(rp[0], r, sizeof r) != (ssize_t)sizeof r) return fail("traced result");
    if (r[0] != me || r[1] != k || r[2] != 77) {
        printf("FAIL: traced RET_TRACE: %ld %ld %ld (want %d %d 77)\n", r[0], r[1], r[2], me, k);
        return 1;
    }
    if (waitpid(k, &st, __WALL) != k || !WIFEXITED(st)) return fail("exit");
    printf("OK\n");
    return 0;
}
