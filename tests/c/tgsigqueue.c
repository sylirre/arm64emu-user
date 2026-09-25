/* rt_tgsigqueueinfo (nr 240): a sigqueue aimed at one thread
 * (pthread_sigqueue's call), which the emulator answered ENOSYS; plus the
 * rules rt_sigqueueinfo shares with it.
 *
 * Covered: the payload reaches the thread it was aimed at -- si_code, the
 * value, the sender's pid and uid; the kernel's order of refusals (EFAULT for
 * the siginfo, EINVAL for a non-positive id, EPERM for a code the caller may
 * not claim, ESRCH for a tid that is not in the group); and the forge rule's
 * subject being the calling THREAD, so a thread that is not main may not
 * claim SI_USER even to its own process with rt_sigqueueinfo. (si_errno,
 * which the kernel hands on as the sender gave it and qemu-user does not, is
 * tests/fixtures/sqiread.c's.) */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t worker_tid;
static int ready[2], go[2];
static siginfo_t worker_got;
static int worker_sig;
static long worker_user, worker_queue;
static int worker_user_errno;

static long tgsqi(pid_t tgid, pid_t tid, int sig, siginfo_t *si) {
    return syscall(SYS_rt_tgsigqueueinfo, tgid, tid, sig, si);
}

static void fill(siginfo_t *si, int sig, int code, int val) {
    memset(si, 0, sizeof *si);
    si->si_signo = sig;
    si->si_code = code;
    si->si_pid = getpid();
    si->si_uid = getuid();
    si->si_value.sival_int = val;
}

static const char *err_name(long r, int e) {
    return r == 0 ? "0" : e == EFAULT ? "EFAULT" : e == EINVAL ? "EINVAL" :
           e == EPERM ? "EPERM" : e == ESRCH ? "ESRCH" : "other";
}

static void report(const char *what, long r) {
    int e = errno;
    printf("%s: %s\n", what, err_name(r, e));
}

/* Takes SIGUSR1 with sigwaitinfo (blocked here, as in every thread), then
 * tries two sends of its own; main prints what happened, in order. */
static void *worker(void *a) {
    (void)a;
    worker_tid = (pid_t)syscall(SYS_gettid);
    char b = 'r';
    if (write(ready[1], &b, 1) != 1) return NULL;
    sigset_t w;
    sigemptyset(&w);
    sigaddset(&w, SIGUSR1);
    memset(&worker_got, 0, sizeof worker_got);
    worker_sig = sigwaitinfo(&w, &worker_got);
    /* The forge rule names the calling thread: SI_USER to its own process is
     * EPERM from a thread that is not main, SI_QUEUE is not. */
    siginfo_t q;
    fill(&q, SIGUSR2, SI_USER, 0);
    worker_user = syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR2, &q);
    worker_user_errno = errno;
    fill(&q, SIGUSR2, SI_QUEUE, 9);
    worker_queue = syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR2, &q);
    if (write(ready[1], &b, 1) != 1 || read(go[0], &b, 1) != 1) return NULL;
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigaddset(&m, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &m, NULL);
    if (pipe(ready) || pipe(go)) return 1;
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    char b;
    if (read(ready[0], &b, 1) != 1) return 1;
    /* Another thread group to name the worker's tid under. */
    pid_t other = fork();
    if (other == 0) { pause(); _exit(0); }

    siginfo_t si;
    /* The kernel reads the siginfo before it looks at anything else. */
    report("null siginfo, tgid 0", tgsqi(0, worker_tid, SIGUSR1, NULL));
    fill(&si, SIGUSR1, SI_QUEUE, 1);
    report("tgid 0", tgsqi(0, worker_tid, SIGUSR1, &si));
    report("tid -1", tgsqi(getpid(), -1, SIGUSR1, &si));
    fill(&si, SIGUSR1, SI_USER, 1);
    report("SI_USER to another thread", tgsqi(getpid(), worker_tid, SIGUSR1, &si));
    fill(&si, SIGUSR1, SI_TKILL, 1);
    report("SI_TKILL to another thread", tgsqi(getpid(), worker_tid, SIGUSR1, &si));
    fill(&si, SIGUSR1, SI_QUEUE, 1);
    report("tid of another group", tgsqi(other, worker_tid, SIGUSR1, &si));
    report("tid that is not a thread", tgsqi(getpid(), 0x3ffffff0, SIGUSR1, &si));
    report("signal 0 probe", tgsqi(getpid(), worker_tid, 0, &si));
    kill(other, SIGKILL);
    waitpid(other, NULL, 0);
    fill(&si, SIGUSR1, SI_USER, 5);
    report("SI_USER to the calling thread",
           tgsqi(getpid(), (pid_t)syscall(SYS_gettid), SIGUSR2, &si));
    sigset_t w;
    sigemptyset(&w);
    sigaddset(&w, SIGUSR2);
    siginfo_t got;
    struct timespec to = { 1, 0 };
    memset(&got, 0, sizeof got);
    got.si_code = -99;
    int s = sigtimedwait(&w, &got, &to);
    printf("main took %d: code=%s\n", s, got.si_code == SI_USER ? "SI_USER" : "other");

    /* The real thing: SI_QUEUE with a payload, to the worker. */
    fill(&si, SIGUSR1, SI_QUEUE, 42);
    report("SI_QUEUE to the worker", tgsqi(getpid(), worker_tid, SIGUSR1, &si));
    if (read(ready[0], &b, 1) != 1) return 1;
    printf("worker took %d: code=%s val=%d pid_ok=%d uid_ok=%d\n", worker_sig,
           worker_got.si_code == SI_QUEUE ? "SI_QUEUE" : "other",
           worker_got.si_value.sival_int, worker_got.si_pid == getpid(),
           worker_got.si_uid == getuid());
    printf("secondary thread, SI_USER to own process: %s\n",
           err_name(worker_user, worker_user_errno));
    printf("secondary thread, SI_QUEUE to own process: %s\n",
           err_name(worker_queue, 0));
    if (write(go[1], &b, 1) != 1) return 1;
    pthread_join(t, NULL);
    memset(&got, 0, sizeof got);
    s = sigtimedwait(&w, &got, &to);
    printf("main took %d: val=%d\n", s, got.si_value.sival_int);
    printf("done\n");
    return 0;
}
