/* Self-checking test: which ptrace requests a tracee must be stopped for.
 *
 * Every request but KILL and INTERRUPT goes through ptrace_check_attach, which
 * wants the tracee in a stop of its own -- TASK_TRACED, and not listening
 * (LISTEN takes a stop out of TRACED for ptrace(2) and wait(2) alike): one
 * running, or listening, is ESRCH. INTERRUPT and LISTEN are a SEIZEd
 * tracee's alone (EIO for an ATTACHed one), and LISTEN wants the stop to be a
 * PTRACE_EVENT_STOP trap -- a signal-delivery-stop is EIO. The emulator
 * answered SETOPTIONS, GETEVENTMSG and GETSIGINFO from the registry whatever
 * the tracee was doing, let a resume request through to a listening tracee
 * (cancelling the listen), took INTERRUPT from an ATTACHed tracer, and had a
 * wait report a listening stop that had only been looked at (WNOWAIT).
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_LISTEN
#define PTRACE_LISTEN 0x4208
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

static pid_t kid(void) {
    pid_t k = fork();
    if (k == 0) { for (;;) nap(5); }
    nap(50);
    return k;
}

static int fail(const char *step) { printf("FAIL: %s (errno %d)\n", step, errno); return 1; }

/* Every request that needs a stopped tracee: ESRCH for `why`. */
static int all_esrch(pid_t k, const char *why) {
    unsigned long msg;
    siginfo_t si;
    unsigned long long regs[34];
    struct iovec iov = { regs, sizeof regs };
    struct { long r; int err; const char *name; } t[8];
    int n = 0;
#define TRY(call, nm) do { errno = 0; t[n].r = (call); t[n].err = errno; t[n++].name = nm; } while (0)
    TRY(ptrace(PTRACE_SETOPTIONS, k, 0, PTRACE_O_TRACESYSGOOD), "SETOPTIONS");
    TRY(ptrace(PTRACE_GETEVENTMSG, k, 0, &msg), "GETEVENTMSG");
    TRY(ptrace(PTRACE_GETSIGINFO, k, 0, &si), "GETSIGINFO");
    TRY(ptrace(PTRACE_GETREGSET, k, NT_PRSTATUS, &iov), "GETREGSET");
    TRY(ptrace(PTRACE_CONT, k, 0, 0), "CONT");
    TRY(ptrace(PTRACE_DETACH, k, 0, 0), "DETACH");
    TRY(ptrace(PTRACE_LISTEN, k, 0, 0), "LISTEN");
    TRY(ptrace(PTRACE_PEEKDATA, k, (void *)&msg, 0), "PEEKDATA");
#undef TRY
    for (int i = 0; i < n; i++)
        if (t[i].r != -1 || t[i].err != ESRCH) {
            printf("FAIL: %s %s: %ld, errno %d\n", t[i].name, why, t[i].r, t[i].err);
            return 1;
        }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int st;

    /* A SEIZEd tracee, running. */
    pid_t k = kid();
    if (ptrace(PTRACE_SEIZE, k, 0, 0)) return fail("SEIZE");
    if (all_esrch(k, "running")) return 1;

    /* ...at a signal-delivery-stop: stopped, but no EVENT_STOP to listen at. */
    kill(k, SIGUSR1);
    if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGUSR1)
        return fail("SIGUSR1 stop");
    errno = 0;
    if (ptrace(PTRACE_LISTEN, k, 0, 0) != -1 || errno != EIO) return fail("LISTEN at a signal stop");
    if (ptrace(PTRACE_SETOPTIONS, k, 0, PTRACE_O_TRACESYSGOOD)) return fail("SETOPTIONS stopped");
    if (ptrace(PTRACE_CONT, k, 0, 0)) return fail("CONT");

    /* ...at an INTERRUPT trap, only looked at (WNOWAIT), then listening: a
     * listening stop is not one a wait reports, collected or not. */
    if (ptrace(PTRACE_INTERRUPT, k, 0, 0)) return fail("INTERRUPT");
    siginfo_t wi;
    memset(&wi, 0, sizeof wi);
    if (waitid(P_PID, (id_t)k, &wi, WSTOPPED | WNOWAIT | __WALL) ||
        wi.si_code != CLD_TRAPPED || (wi.si_status >> 8) != PTRACE_EVENT_STOP)
        return fail("INTERRUPT stop");
    if (ptrace(PTRACE_LISTEN, k, 0, 0)) return fail("LISTEN at the trap");
    if (all_esrch(k, "listening")) return 1;
    if (waitpid(k, &st, __WALL | WNOHANG) != 0) return fail("a listening tracee reported");
    if (ptrace(PTRACE_KILL, k, 0, 0)) return fail("KILL listening");
    if (waitpid(k, &st, __WALL) != k || !WIFSIGNALED(st)) return fail("killed");

    /* An ATTACHed tracee: no INTERRUPT, running or stopped, and no LISTEN. */
    k = kid();
    if (ptrace(PTRACE_ATTACH, k, 0, 0)) return fail("ATTACH");
    if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st)) return fail("attach stop");
    errno = 0;
    if (ptrace(PTRACE_INTERRUPT, k, 0, 0) != -1 || errno != EIO) return fail("INTERRUPT attached, stopped");
    errno = 0;
    if (ptrace(PTRACE_LISTEN, k, 0, 0) != -1 || errno != EIO) return fail("LISTEN attached");
    if (ptrace(PTRACE_CONT, k, 0, 0)) return fail("CONT attached");
    errno = 0;
    if (ptrace(PTRACE_INTERRUPT, k, 0, 0) != -1 || errno != EIO) return fail("INTERRUPT attached, running");
    if (all_esrch(k, "attached, running")) return 1;
    if (ptrace(PTRACE_KILL, k, 0, 0)) return fail("KILL running");
    if (waitpid(k, &st, __WALL) != k || !WIFSIGNALED(st)) return fail("killed");
    printf("OK\n");
    return 0;
}
