/* Self-checking ptrace signal-delivery-stop test (emulator-only). Verifies the
 * tracer sees a signal-delivery stop and can both suppress the signal (data=0)
 * and inject it (data=signo) on PTRACE_CONT. */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

static volatile sig_atomic_t got_usr1;
static void handler(int s) { (void)s; got_usr1 = 1; }

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

/* Fork a tracee that raises SIGUSR1 and exits 1 if its handler ran, 0 if not.
 * Resume the signal-delivery stop with `inject` (0 = suppress). Returns the
 * child's exit code, or -1 on protocol error. */
static int run_case(int inject) {
    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGUSR1, handler);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGUSR1);
        _exit(got_usr1 ? 1 : 0);
    }
    int status;
    if (waitpid(pid, &status, 0) != pid) return -1;
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGUSR1) return -1;
    ptrace(PTRACE_CONT, pid, 0, (void *)(long)inject);
    if (waitpid(pid, &status, 0) != pid) return -1;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

int main(void) {
    if (run_case(0) != 0) return fail("SIGUSR1 not suppressed");
    if (run_case(SIGUSR1) != 1) return fail("SIGUSR1 not injected");
    printf("OK\n");
    return 0;
}
