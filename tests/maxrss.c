/* Host-side helper: run a command and print its peak RSS in kB.
 *
 * Some things the emulator must not do are invisible from inside the guest,
 * because they are the *emulator's* memory rather than the guest's: a page
 * table that never gives its second level back grows the host process while
 * the guest's own /proc/self/status stays flat. Measuring that needs a view
 * from outside, and `/usr/bin/time -f %M` is not portable enough to rely on
 * (Termux ships no such binary), so this does the one wait4 that answers it.
 *
 * Built with the HOST compiler, like tests/seccomp_wrap.c and
 * tests/memfd_seal_probe.c -- nothing here is guest code. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: maxrss <cmd> [args...]\n"); return 2; }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) {
        /* The measurement is of the child alone, so its own output must not
         * land in ours: the caller reads this program's stdout for a number. */
        if (!freopen("/dev/null", "w", stdout)) _exit(127);
        execv(argv[1], &argv[1]);
        _exit(127);
    }
    int status = 0;
    struct rusage ru;
    if (wait4(pid, &status, 0, &ru) < 0) { perror("wait4"); return 2; }
    /* ru_maxrss is in kilobytes on Linux (bytes on some other systems; this
     * helper is Linux-only, like everything else here). */
    printf("%ld\n", (long)ru.ru_maxrss);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) return 1;
    if (WIFSIGNALED(status)) return 1;
    return 0;
}
