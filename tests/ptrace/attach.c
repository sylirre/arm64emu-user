/* Self-checking PTRACE_ATTACH / PTRACE_SEIZE+INTERRUPT test (emulator-only):
 * the tracer attaches to an ALREADY-RUNNING child (one it never TRACEME'd),
 * which the cooperative model stops via a reserved-signal kick that interrupts
 * the child's blocking syscall. Pipes carry the handshake (guest MAP_SHARED
 * anonymous memory is not shared across the emulator's fork, but inherited fds
 * are): the child announces readiness on `rp` (so it is registered before we
 * attach), and the tracer closes `sp` after detaching to let it exit cleanly. */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

/* Child: announce readiness on rp, then spin in a short interruptible sleep
 * until sp reports EOF/data, then exit(code). */
static void child_body(int rpw, int spr, int code) {
    char b = 'x';
    if (write(rpw, &b, 1) != 1) _exit(101);
    fcntl(spr, F_SETFL, O_NONBLOCK);
    for (;;) {
        struct timespec ts = { 0, 2 * 1000 * 1000 };   /* 2 ms */
        nanosleep(&ts, NULL);
        ssize_t n = read(spr, &b, 1);
        if (n == 0 || n == 1) break;                    /* stop signalled */
        if (n < 0 && errno != EAGAIN) break;
    }
    _exit(code);
}

/* Fork a ready-announcing child; return its pid and the tracer-side pipe ends. */
static pid_t spawn(int code, int *stop_w) {
    int rp[2], sp[2];
    if (pipe(rp) || pipe(sp)) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(rp[0]); close(sp[1]);
        child_body(rp[1], sp[0], code);
    }
    close(rp[1]); close(sp[0]);
    char b;
    if (read(rp[0], &b, 1) != 1) { close(rp[0]); close(sp[1]); return -1; }
    close(rp[0]);
    *stop_w = sp[1];
    return pid;
}

int main(void) {
    int st, stop_w;

    /* ---- case 1: PTRACE_ATTACH -> initial SIGSTOP stop ---- */
    pid_t a = spawn(7, &stop_w);
    if (a <= 0) return fail("spawn a");
    if (ptrace(PTRACE_ATTACH, a, 0, 0) != 0) return fail("PTRACE_ATTACH");
    if (waitpid(a, &st, 0) != a) return fail("waitpid(attach)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP)
        return fail("attach stop not SIGSTOP");

    struct user_regs_struct r;
    struct iovec io = { &r, sizeof r };
    if (ptrace(PTRACE_GETREGSET, a, (void *)NT_PRSTATUS, &io) != 0)
        return fail("GETREGSET after attach");
    errno = 0;
    ptrace(PTRACE_PEEKTEXT, a, (void *)(unsigned long)r.pc, 0);
    if (errno) return fail("PEEKTEXT after attach");

    if (ptrace(PTRACE_DETACH, a, 0, 0) != 0) return fail("PTRACE_DETACH");
    close(stop_w);                        /* let it exit after detach */
    if (waitpid(a, &st, 0) != a) return fail("waitpid(detach exit)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 7)
        return fail("child exit wrong after detach");

    /* ---- case 2: PTRACE_SEIZE + PTRACE_INTERRUPT -> EVENT_STOP ---- */
    pid_t b = spawn(9, &stop_w);
    if (b <= 0) return fail("spawn b");
    if (ptrace(PTRACE_SEIZE, b, 0, 0) != 0) return fail("PTRACE_SEIZE");
    if (ptrace(PTRACE_INTERRUPT, b, 0, 0) != 0) return fail("PTRACE_INTERRUPT");
    if (waitpid(b, &st, 0) != b) return fail("waitpid(interrupt)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP ||
        (st >> 8) != (SIGTRAP | (PTRACE_EVENT_STOP << 8)))
        return fail("interrupt stop not PTRACE_EVENT_STOP");

    if (ptrace(PTRACE_DETACH, b, 0, 0) != 0) return fail("DETACH(seize)");
    close(stop_w);
    if (waitpid(b, &st, 0) != b) return fail("waitpid(seize exit)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 9)
        return fail("seized child exit wrong");

    printf("OK\n");
    return 0;
}
