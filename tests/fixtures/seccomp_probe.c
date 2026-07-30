/* seccomp-BPF filtering of guest syscalls. The emulator dispatches every guest
 * syscall itself, so it evaluates the filter itself too (src/sys_seccomp.c).
 * Self-checking: qemu-user does not implement guest seccomp at all (every
 * install returns ENOSYS there), so it cannot be the oracle. The expected
 * block in run_tests.sh was taken from a real kernel running this same program
 * natively -- only the value left in the return register after a TRAP handler
 * returns differs, which the man page calls architecture-specific (x86 leaves
 * the syscall number, arm64 leaves -ENOSYS).
 *
 * Covers: the no_new_privs precondition, ERRNO with and without argument
 * matching, stacked filters (most severe wins, newest wins a tie), TRAP with
 * the _sigsys siginfo a handler reads, KILL, strict mode, inheritance across
 * fork, PR_GET_SECCOMP, and the programs the kernel rejects.
 *
 * Buffering: stdout is block-buffered when captured, so flush before fork(). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1   /* si_code of a SIGSYS raised by a filter */
#endif

static int seccomp_(unsigned op, unsigned flags, void *arg) {
    return (int)syscall(__NR_seccomp, op, flags, arg);
}

/* Standard prologue: refuse anything from another architecture, then jump to
 * the per-syscall decision. */
#define PROLOGUE \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))

static int install(struct sock_filter *f, unsigned short len) {
    struct sock_fprog prog = { len, f };
    return seccomp_(SECCOMP_SET_MODE_FILTER, 0, &prog);
}

static volatile int trap_sig, trap_code, trap_nr, trap_arch, trap_data;
static void on_sigsys(int sig, siginfo_t *si, void *u) {
    (void)u;
    trap_sig = sig;
    trap_code = si->si_code;
    trap_nr = si->si_syscall;
    trap_arch = (int)si->si_arch;
    trap_data = si->si_errno;   /* the filter's SECCOMP_RET_DATA */
}

/* The low 16 bits a trapping filter returns; the kernel hands them to the
 * handler in si_errno, which is how one filter tells its own traps apart. */
#define TRAP_DATA 0x0042

int main(void) {
    /* Without no_new_privs the kernel refuses to install a filter. */
    struct sock_filter deny_chdir[] = {
        PROLOGUE,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chdir, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    int r = install(deny_chdir, sizeof deny_chdir / sizeof deny_chdir[0]);
    printf("nonnp=%d %d\n", r, r < 0 && errno == EACCES);

    printf("nnp=%d\n", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

    /* Strict mode, before any filter exists (a mode cannot be switched once
     * set): read/write/exit/rt_sigreturn only, SIGKILL for anything else. */
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        if (seccomp_(SECCOMP_SET_MODE_STRICT, 0, NULL) != 0) _exit(9);
        getpid();   /* not on the list */
        _exit(8);   /* not reached */
    }
    int st = 0;
    waitpid(kid, &st, 0);
    printf("strict=%d sig=%d\n", WIFSIGNALED(st),
           WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);

    /* Rejected programs: empty, and one with an opcode seccomp does not allow
     * (a packet-relative load — there is no packet). */
    struct sock_fprog empty = { 0, deny_chdir };
    r = seccomp_(SECCOMP_SET_MODE_FILTER, 0, &empty);
    printf("empty=%d\n", r < 0 && errno == EINVAL);
    struct sock_filter bad[] = {
        BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    r = install(bad, 2);
    printf("badinsn=%d\n", r < 0 && errno == EINVAL);
    r = seccomp_(SECCOMP_SET_MODE_FILTER, 1 << 20, &empty);
    printf("badflag=%d\n", r < 0 && errno == EINVAL);

    /* ERRNO on one syscall; everything else still runs. */
    printf("install=%d\n", install(deny_chdir,
                                   sizeof deny_chdir / sizeof deny_chdir[0]));
    r = chdir("/");
    printf("chdir=%d %d\n", r, r < 0 && errno == EPERM);
    printf("getpid_ok=%d\n", getpid() > 0);
    printf("mode=%d\n", prctl(PR_GET_SECCOMP));

    /* Argument matching: only writes to fd 99 are refused. */
    struct sock_filter deny_fd99[] = {
        PROLOGUE,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 99, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EBADF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    printf("install2=%d\n", install(deny_fd99,
                                    sizeof deny_fd99 / sizeof deny_fd99[0]));
    r = (int)write(99, "x", 1);
    printf("write99=%d %d\n", r, r < 0 && errno == EBADF);
    printf("write1=%d\n", (int)write(1, "", 0));
    /* The older filter is still in force: both are consulted. */
    r = chdir("/");
    printf("chdir2=%d %d\n", r, r < 0 && errno == EPERM);

    /* Stacked filters answering the same call: the newest wins the tie. */
    struct sock_filter deny_chdir_acces[] = {
        PROLOGUE,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chdir, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    printf("install3=%d\n",
           install(deny_chdir_acces,
                   sizeof deny_chdir_acces / sizeof deny_chdir_acces[0]));
    r = chdir("/");
    printf("chdir3=%d %d\n", r, r < 0 && errno == EACCES);

    /* TRAP: SIGSYS carrying the blocked call, and the syscall does not run. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, NULL);
    struct sock_filter trap_prio[] = {
        PROLOGUE,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpriority, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | TRAP_DATA),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    printf("install4=%d\n", install(trap_prio,
                                    sizeof trap_prio / sizeof trap_prio[0]));
    errno = 0;
    r = (int)syscall(__NR_getpriority, 0, 0);
    printf("trap sig=%d code=%d nr=%d arch=%d ret=%d errno=%d data=%d\n",
           trap_sig == SIGSYS, trap_code == SYS_SECCOMP,
           trap_nr == __NR_getpriority, trap_arch == (int)AUDIT_ARCH_AARCH64,
           r, errno == ENOSYS, trap_data == TRAP_DATA);

    /* Inherited by a fork child, filters and all. */
    fflush(stdout);
    kid = fork();
    if (kid == 0) {
        int rc = chdir("/");
        _exit(rc < 0 && errno == EACCES ? 0 : 1);
    }
    st = 0;
    waitpid(kid, &st, 0);
    printf("forked=%d\n", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* KILL takes the process down with SIGSYS. */
    fflush(stdout);
    kid = fork();
    if (kid == 0) {
        struct sock_filter kill_chdir[] = {
            PROLOGUE,
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchdir, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        if (install(kill_chdir, sizeof kill_chdir / sizeof kill_chdir[0]) != 0)
            _exit(9);
        syscall(__NR_fchdir, 0);
        _exit(8);   /* not reached */
    }
    st = 0;
    waitpid(kid, &st, 0);
    printf("killed=%d sig=%d\n", WIFSIGNALED(st),
           WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);

    /* A mode cannot be switched once one is set. */
    r = seccomp_(SECCOMP_SET_MODE_STRICT, 0, NULL);
    printf("noswitch=%d\n", r < 0 && errno == EINVAL);
    printf("done\n");
    return 0;
}
