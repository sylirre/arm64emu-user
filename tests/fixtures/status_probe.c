/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* /proc/<pid>/status: the lines that must describe the GUEST process rather
 * than the emulator carrying it (src/sys_procfs.c put_status).
 *
 * Self-checking. qemu-user cannot be the oracle here -- it has no guest seccomp
 * and no emulated ptrace, so it would report the host task's own state for
 * every field this checks. The expected block is what a real kernel prints for
 * this program; x86lines is the only line where the oracle has to be an
 * *aarch64* kernel, which emits no x86_* arch-hook line at all.
 *
 * Everything is reported as a boolean or a small count rather than a raw mask,
 * so the answer does not depend on which signals the C library happens to have
 * touched on its own. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* Value of one "Key:" line of a status file, or "" if it has none. */
static void field(const char *path, const char *key, char *out, size_t n) {
    out[0] = 0;
    FILE *f = fopen(path, "r");
    if (!f) return;
    size_t kl = strlen(key);
    char line[4096];
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, key, kl) || line[kl] != ':') continue;
        const char *v = line + kl + 1;
        while (*v == ' ' || *v == '\t') v++;
        size_t vl = strlen(v);
        while (vl && (v[vl - 1] == '\n' || v[vl - 1] == ' ')) vl--;
        if (vl >= n) vl = n - 1;
        memcpy(out, v, vl);
        out[vl] = 0;
        break;
    }
    fclose(f);
}

static unsigned long long mask(const char *path, const char *key) {
    char v[64];
    field(path, key, v, sizeof v);
    return strtoull(v, NULL, 16);
}

static long num(const char *path, const char *key) {
    char v[64];
    field(path, key, v, sizeof v);
    return strtol(v, NULL, 10);
}

/* Signal N lives in bit N-1 of every mask the file prints. */
static int has(unsigned long long m, int sig) { return (m >> (sig - 1)) & 1; }

/* Lines the host kernel's own arch hook adds. An aarch64 kernel has none, so
 * seeing one means the guest is being told what the host CPU is. */
static int x86_lines(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[4096];
    int n = 0;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "x86_", 4)) n++;
    fclose(f);
    return n;
}

static void handler(int sig) { (void)sig; }

/* An allow-everything filter: installing it must change only what status
 * reports, never whether a later syscall runs. */
static int install_filter(void) {
    struct sock_filter insns[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { 1, insns };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

int main(void) {
    const char *self = "/proc/self/status";

    /* Dispositions: an ignored signal shows up in SigIgn and a handled one in
     * SigCgt. The host's own lines describe the capture layer, which installs
     * a handler for far more than the guest ever asked about. */
    signal(SIGHUP, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sigaction(SIGTERM, &sa, NULL);
    printf("ign_hup=%d cgt_hup=%d cgt_term=%d ign_term=%d\n",
           has(mask(self, "SigIgn"), SIGHUP), has(mask(self, "SigCgt"), SIGHUP),
           has(mask(self, "SigCgt"), SIGTERM), has(mask(self, "SigIgn"), SIGTERM));

    /* Blocked set, and a signal raised while blocked: it stays pending on this
     * thread, so SigPnd carries it and the process-wide ShdPnd does not. It is
     * handled rather than left at SIG_DFL only so that unblocking it below runs
     * the handler instead of killing the probe. */
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t bs;
    sigemptyset(&bs);
    sigaddset(&bs, SIGUSR1);
    sigprocmask(SIG_BLOCK, &bs, NULL);
    raise(SIGUSR1);
    printf("blk_usr1=%d blk_usr2=%d pnd_usr1=%d pnd_usr2=%d shd_usr1=%d\n",
           has(mask(self, "SigBlk"), SIGUSR1), has(mask(self, "SigBlk"), SIGUSR2),
           has(mask(self, "SigPnd"), SIGUSR1), has(mask(self, "SigPnd"), SIGUSR2),
           has(mask(self, "ShdPnd"), SIGUSR1));
    sigprocmask(SIG_UNBLOCK, &bs, NULL);
    printf("unblk_usr1=%d\n", has(mask(self, "SigBlk"), SIGUSR1));

    /* TracerPid, from a child that put itself under us. The emulated ptrace
     * never host-attaches, so the host file reports nobody. */
    printf("untraced=%ld\n", num(self, "TracerPid"));
    pid_t kid = fork();
    if (kid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) _exit(2);
        raise(SIGSTOP);
        _exit(0);
    }
    int st = 0;
    char kpath[64];
    snprintf(kpath, sizeof kpath, "/proc/%d/status", (int)kid);
    waitpid(kid, &st, WUNTRACED);
    printf("tracer_is_me=%d\n", num(kpath, "TracerPid") == (long)getpid());
    ptrace(PTRACE_DETACH, kid, 0, 0);
    waitpid(kid, &st, 0);

    /* no_new_privs is answered from the guest's own recorded intent, the same
     * as PR_GET_NO_NEW_PRIVS: an inherited host flag is not the guest's. */
    printf("nnp0=%ld\n", num(self, "NoNewPrivs"));
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    printf("nnp1=%ld\n", num(self, "NoNewPrivs"));

    /* Strict mode entered through seccomp(2), read from OUTSIDE. The process
     * that set it cannot look at itself -- strict mode allows read, write,
     * _exit and rt_sigreturn, and nothing else -- so the only place that
     * answer can come from is the shared registry, and it only gets there if
     * the seccomp(2) spelling publishes it the way the prctl one does. Forked
     * before this process installs any filter of its own: a mode cannot be
     * switched once set, so a child that inherited a filter could not enter
     * strict mode at all. */
    int up[2], down[2];
    if (pipe(up) != 0 || pipe(down) != 0) return 1;
    fflush(stdout);
    kid = fork();
    if (kid == 0) {
        close(up[0]);
        close(down[1]);
        if (syscall(__NR_seccomp, (unsigned)SECCOMP_SET_MODE_STRICT, 0u, NULL) != 0)
            _exit(9);
        char one = 1;
        if (write(up[1], &one, 1) != 1) _exit(9);
        char sink;
        read(down[0], &sink, 1);   /* park where strict mode permits */
        _exit(0);
    }
    close(up[1]);
    close(down[0]);
    char ready = 0;
    if (read(up[0], &ready, 1) != 1) return 1;
    snprintf(kpath, sizeof kpath, "/proc/%d/status", (int)kid);
    printf("strict_sec=%ld strict_f=%ld\n", num(kpath, "Seccomp"),
           num(kpath, "Seccomp_filters"));
    kill(kid, SIGKILL);
    waitpid(kid, &st, 0);
    close(up[0]);
    close(down[1]);

    /* Seccomp: a guest filter never reaches the host, so the host file cannot
     * count it -- and where the emulator itself carries one, it counts that. */
    printf("sec0=%ld f0=%ld\n", num(self, "Seccomp"), num(self, "Seccomp_filters"));
    printf("install1=%d\n", install_filter());
    printf("sec1=%ld f1=%ld\n", num(self, "Seccomp"), num(self, "Seccomp_filters"));
    printf("install2=%d\n", install_filter());
    printf("sec2=%ld f2=%ld\n", num(self, "Seccomp"), num(self, "Seccomp_filters"));

    /* And the same, read from the outside: a child inherits the chain, so its
     * status must show it to us. That answer cannot come from the child's own
     * memory, which is why it is published to the shared registry. */
    kid = fork();
    if (kid == 0) { pause(); _exit(0); }
    snprintf(kpath, sizeof kpath, "/proc/%d/status", (int)kid);
    printf("kid_sec=%ld kid_f=%ld\n", num(kpath, "Seccomp"),
           num(kpath, "Seccomp_filters"));
    kill(kid, SIGKILL);
    waitpid(kid, &st, 0);

    printf("x86lines=%d\n", x86_lines(self));
    printf("done\n");
    return 0;
}
