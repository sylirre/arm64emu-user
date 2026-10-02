/* The emulator's own threads across their idle spells and a process's
 * forks (signal.c, "the emulator's own threads, and fork"). Each round has
 * a clone child die while SIGCHLD is blocked -- its own signal comes only
 * if the SIGCHLD watcher is awake to turn the host's SIGCHLD into it, which
 * from the second round on means woken again from its sleep since the last
 * one -- and then forks, one every 5 ms for a while, children that start a
 * thread of their own. The watcher used to end once the clone child was
 * reaped, and a new one was made for the next: under qemu-user, which takes
 * a lock of its own as a thread starts and as one exits and forks without
 * it, a fork that met that end handed its child the lock held, and the
 * child's pthread_create waited for it forever.
 *
 * Self-checking: the kernel's answer is every round done. */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 12
#define FORKS 20

static void *nothing(void *a) { return a; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    sigset_t b;
    sigemptyset(&b);
    sigaddset(&b, SIGCHLD);
    sigaddset(&b, SIGUSR2);
    sigprocmask(SIG_BLOCK, &b, NULL);
    sigset_t u2;
    sigemptyset(&u2);
    sigaddset(&u2, SIGUSR2);
    int notices = 0, forks = 0;
    for (int i = 0; i < ROUNDS; i++) {
        long k = syscall(SYS_clone, (long)SIGUSR2, 0L, 0L, 0L, 0L);
        if (k == 0) _exit(0);
        siginfo_t si;
        struct timespec to = { 3, 0 };
        if (sigtimedwait(&u2, &si, &to) == SIGUSR2 && si.si_pid == k) notices++;
        waitpid((pid_t)k, NULL, __WALL);
        for (int f = 0; f < FORKS; f++) {
            pid_t c = fork();
            if (c == 0) {
                pthread_t t;
                if (pthread_create(&t, NULL, nothing, NULL) != 0) _exit(2);
                pthread_join(t, NULL);
                _exit(0);
            }
            int st = 0;
            if (waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0) forks++;
            struct timespec ts = { 0, 5 * 1000000L };
            nanosleep(&ts, NULL);
        }
        /* The ordinary children's notices, which the blocked SIGCHLD holds. */
        sigset_t c;
        sigemptyset(&c);
        sigaddset(&c, SIGCHLD);
        struct timespec z = { 0, 0 };
        while (sigtimedwait(&c, NULL, &z) > 0) ;
    }
    printf("clone children's notices: %d of %d\n", notices, ROUNDS);
    printf("forks done: %d of %d\n", forks, ROUNDS * FORKS);
    return 0;
}
