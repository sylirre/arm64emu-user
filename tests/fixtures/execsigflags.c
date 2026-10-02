/* What an execve leaves of the dispositions (flush_signal_handlers): a
 * handler goes back to the default, an ignored signal stays ignored -- and
 * every disposition, default and ignored ones too, loses its flags and its
 * mask. The emulator reset the handlers alone, so SA_NOCLDSTOP on a SIGCHLD
 * left at its default outlived the exec, sparing the new image the stop
 * notices it never asked to be spared, and the flags and mask of every other
 * default or ignored one were read back as the old image had set them.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void on_usr(int s) { (void)s; }

int main(int argc, char **argv) {
    struct sigaction sa;
    static const int sigs[] = { SIGCHLD, SIGUSR1, SIGUSR2, SIGTERM };
    if (argc > 1) {
        for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
            sigaction(sigs[i], NULL, &sa);
            /* SA_RESTORER is the libc's own, set on every install it makes */
            printf("sig %d: %s, flags 0x%lx, mask %s\n", sigs[i],
                   sa.sa_handler == SIG_IGN ? "ignored" :
                   sa.sa_handler == SIG_DFL ? "default" : "a handler",
                   (unsigned long)sa.sa_flags & ~0x04000000UL,
                   sigismember(&sa.sa_mask, SIGINT) ? "SIGINT" : "empty");
        }
        printf("done\n");
        return 0;
    }
    memset(&sa, 0, sizeof sa);
    sigaddset(&sa.sa_mask, SIGINT);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART | SA_ONSTACK;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    sa.sa_handler = on_usr;
    sa.sa_flags = SA_RESTART | SA_NODEFER;
    sigaction(SIGTERM, &sa, NULL);
    execl("/proc/self/exe", argv[0], "again", (char *)0);
    perror("execl");
    return 1;
}
