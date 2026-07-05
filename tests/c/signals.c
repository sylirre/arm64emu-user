#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <setjmp.h>

static volatile sig_atomic_t got;
static void h(int s) { got = s; printf("handler got %d\n", s); }

static sigjmp_buf jb;
static void segv(int s) { (void)s; printf("caught SIGSEGV\n"); siglongjmp(jb, 1); }

int main(void) {
    // basic handler + raise
    signal(SIGUSR1, h);
    raise(SIGUSR1);
    printf("after raise got=%d\n", got);

    // sigaction with SA_SIGINFO
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = h; sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &sa, NULL);
    kill(getpid(), SIGUSR2);
    printf("after kill got=%d\n", got);

    // block/unblock
    sigset_t set, old; sigemptyset(&set); sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, &old);
    got = 0;
    raise(SIGUSR1);
    printf("while blocked got=%d\n", got);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("after unblock got=%d\n", got);

    // SIGSEGV recovery
    signal(SIGSEGV, segv);
    if (sigsetjmp(jb, 1) == 0) {
        volatile int *p = (int*)0x0;
        *p = 42;
        printf("NOT REACHED\n");
    } else {
        printf("recovered from segv\n");
    }
    printf("done\n");
    return 0;
}
