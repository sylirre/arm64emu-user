/* Fork safety of the emulator's own process-local mutexes -- see
 * docs/signals-and-processes.md, "fork safety". Two invariants, neither of them
 * visible to the guest and neither covered deliberately anywhere else:
 *
 *   1. a fork must not hand the child a mutex a *sibling* thread held. fork(2)
 *      duplicates the calling thread alone, so such a lock arrives locked and
 *      owned by a thread that does not exist, and the child wedges on the next
 *      acquisition. That is exactly how an armv7 replay wedged for good
 *      (c2fe3ad), found by accident because tests/c/timers.c happens to fork
 *      while libc's SIGEV_THREAD helper is running.
 *
 *   2. the pthread_atfork prepare handlers must acquire in an order compatible
 *      with the nesting real code uses. as_lock is the innermost of the seven:
 *      a netlink critical section takes it whenever copying the guest's request
 *      misses that thread's D-TLB. Were prepare to take as_lock *before*
 *      nl_lock -- which is what reordering the *_atfork_init() calls in main.c
 *      would do, since prepare handlers run in reverse registration order --
 *      fork would deadlock against the netlink thread here.
 *
 * Shape: three threads keep those locks hot while the main thread forks and
 * reaps in a loop. The address-space churn is what makes (2) deterministic
 * rather than lucky: every mmap/munmap bumps the emulator's address-space
 * generation, which invalidates the netlink thread's D-TLB, so its next request
 * copy is a guaranteed miss and takes as_lock underneath nl_lock.
 *
 * Both violations are hangs, so an alarm converts them into a named failure
 * instead of a suite timeout. Run under A64_NETLINK_FORCE_BLOCK so the netlink
 * thread exercises the emulated path on any host. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define FORKS      200
#define DEADLINE    40      /* seconds; the suite's own timeout is longer */

static volatile sig_atomic_t stop;

/* Async-signal-safe: the point of the alarm is to report a deadlock, and a
 * deadlocked process cannot be trusted to make it through printf. */
static void on_alarm(int sig)
{
    static const char msg[] =
        "FAIL: timed out -- a fork or a child never completed, which is what a\n"
        "      lock inherited locked (or an atfork prepare order inverted against\n"
        "      the nl_lock -> as_lock nesting) looks like from out here.\n";
    (void)sig;
    ssize_t n = write(1, msg, sizeof msg - 1);
    (void)n;
    _exit(1);
}

/* nl_lock, plus as_lock underneath it: the emulator copies this request out of
 * guest memory while holding nl_lock, and the churn thread keeps that copy
 * missing the D-TLB. */
static void *nl_thread(void *arg)
{
    int fd = *(int *)arg;
    struct { struct nlmsghdr n; struct rtgenmsg g; } req;
    struct sockaddr_nl snl;
    char buf[4096];

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    while (!stop) {
        memset(&req, 0, sizeof req);
        req.n.nlmsg_len = sizeof req;
        req.n.nlmsg_type = RTM_GETADDR;
        req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.n.nlmsg_seq = 1;
        req.g.rtgen_family = AF_INET;
        if (sendto(fd, &req, sizeof req, 0,
                   (struct sockaddr *)&snl, sizeof snl) < 0)
            break;                       /* host took the socket away: stop */
        while (recv(fd, buf, sizeof buf, MSG_DONTWAIT) > 0)
            ;
    }
    return NULL;
}

/* as_lock, and the generation bumps that flush every thread's D-TLB. */
static void *churn_thread(void *arg)
{
    (void)arg;
    while (!stop) {
        void *p = mmap(NULL, 64 * 1024, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) continue;
        *(volatile char *)p = 1;
        munmap(p, 64 * 1024);
    }
    return NULL;
}

/* pf_lock: the synthesized per-pid /proc files. */
static void *procfs_thread(void *arg)
{
    (void)arg;
    char buf[2048];
    while (!stop) {
        int fd = open("/proc/self/status", O_RDONLY);
        if (fd < 0) continue;
        while (read(fd, buf, sizeof buf) > 0)
            ;
        close(fd);
    }
    return NULL;
}

int main(void)
{
    pthread_t t[3];
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (nl < 0) { printf("FAIL: no netlink socket (errno %d)\n", errno); return 1; }
    signal(SIGALRM, on_alarm);
    alarm(DEADLINE);

    if (pthread_create(&t[0], NULL, nl_thread, &nl) != 0 ||
        pthread_create(&t[1], NULL, churn_thread, NULL) != 0 ||
        pthread_create(&t[2], NULL, procfs_thread, NULL) != 0) {
        printf("FAIL: pthread_create\n");
        return 1;
    }

    for (int i = 0; i < FORKS; i++) {
        pid_t p = fork();
        if (p < 0) { printf("FAIL: fork %d: errno %d\n", i, errno); return 1; }
        if (p == 0) _exit(0);            /* the child only has to get here */
        int st = 0;
        if (waitpid(p, &st, 0) != p) { printf("FAIL: waitpid %d\n", i); return 1; }
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            printf("FAIL: child %d status 0x%x\n", i, st);
            return 1;
        }
    }

    stop = 1;
    for (int i = 0; i < 3; i++) pthread_join(t[i], NULL);
    close(nl);
    printf("OK\n");
    return 0;
}
