/* SIGSEGV, SIGBUS, SIGILL, SIGFPE and SIGTRAP are faults when the CPU raises
 * them and ordinary signals when a process is SENT them -- kill(2), raise(3),
 * a pthread_kill -- and the sent kind takes the guest's disposition like any
 * other signal: a handler runs it, SIG_IGN drops it, SIG_DFL ends the process
 * by it, a blocked one waits in sigwait. The emulator delivered its own faults
 * to the guest but left a sent one to the HOST's default disposition, so a
 * guest with a SIGSEGV handler died of kill(SIGSEGV), and a sent SIGBUS was
 * swallowed by the bus-error net and the process lived on. Self-checking:
 * qemu-user hangs on the second row (a raise() of SIGSEGV into its own
 * handler); the expected block is what this program prints built for the
 * host and run on a real kernel. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int got_sig, got_code;
static void h(int sig, siginfo_t *si, void *u) { (void)u; got_sig = sig; got_code = si->si_code; }

static void child_status(const char *label, void (*body)(void)) {
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) { body(); _exit(7); }
    int st;
    waitpid(k, &st, 0);
    if (WIFSIGNALED(st)) printf("%s: signaled %d\n", label, WTERMSIG(st));
    else printf("%s: exited %d\n", label, WEXITSTATUS(st));
}
static void dfl_bus(void)  { signal(SIGBUS, SIG_DFL); kill(getpid(), SIGBUS); usleep(200000); }
static void dfl_segv(void) { signal(SIGSEGV, SIG_DFL); raise(SIGSEGV); usleep(200000); }
static void dfl_ill(void)  { signal(SIGILL, SIG_DFL); kill(getpid(), SIGILL); usleep(200000); }
static void dfl_fpe(void)  { signal(SIGFPE, SIG_DFL); kill(getpid(), SIGFPE); usleep(200000); }
static void dfl_trap(void) { signal(SIGTRAP, SIG_DFL); kill(getpid(), SIGTRAP); usleep(200000); }
static void ign_segv(void) { signal(SIGSEGV, SIG_IGN); kill(getpid(), SIGSEGV); signal(SIGBUS, SIG_IGN); kill(getpid(), SIGBUS); usleep(100000); _exit(5); }
static void dfl_abrt(void) { signal(SIGABRT, SIG_DFL); kill(getpid(), SIGABRT); usleep(200000); }
static void dfl_term(void) { kill(getpid(), SIGTERM); usleep(200000); }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO;
    int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP };
    const char *names[] = { "segv", "bus", "ill", "fpe", "trap" };
    for (int i = 0; i < 5; i++) {
        sigaction(sigs[i], &sa, NULL);
        got_sig = 0;
        kill(getpid(), sigs[i]);
        printf("kill_%s: handler=%d si_user=%d\n", names[i], got_sig == sigs[i], got_code == SI_USER);
        got_sig = 0;
        raise(sigs[i]);
        printf("raise_%s: handler=%d si_tkill=%d\n", names[i], got_sig == sigs[i], got_code == SI_TKILL);
        got_sig = 0;
        pthread_kill(pthread_self(), sigs[i]);
        printf("pthread_kill_%s: handler=%d\n", names[i], got_sig == sigs[i]);
    }
    /* Blocked and waited for. */
    sigset_t set, old;
    sigemptyset(&set); sigaddset(&set, SIGSEGV);
    sigprocmask(SIG_BLOCK, &set, &old);
    kill(getpid(), SIGSEGV);
    int w = -1;
    printf("sigwait_segv=%d\n", sigwait(&set, &w) == 0 && w == SIGSEGV);
    sigprocmask(SIG_SETMASK, &old, NULL);
    /* The default: death by that signal. */
    child_status("dfl_bus", dfl_bus);
    child_status("dfl_segv", dfl_segv);
    child_status("dfl_ill", dfl_ill);
    child_status("dfl_fpe", dfl_fpe);
    child_status("dfl_trap", dfl_trap);
    child_status("dfl_abrt", dfl_abrt);
    child_status("dfl_term", dfl_term);
    child_status("ign_segv_bus", ign_segv);
    printf("done\n");
    return 0;
}
