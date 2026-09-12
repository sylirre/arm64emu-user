/* Which interrupted syscalls a handler's SA_RESTART resumes, and which are
 * EINTR whatever the flag says. A kernel decides it by the errno the call
 * came back with: ERESTARTSYS (the blocking file and socket calls, the
 * waits, the locks, an untimed FUTEX_WAIT) is restarted under SA_RESTART;
 * ERESTARTNOINTR (the PI futex ops) is restarted whatever the flags;
 * ERESTART_RESTARTBLOCK and ERESTARTNOHAND (every sleep and poll, a timed
 * FUTEX_WAIT) are EINTR to a handler, always, and so is a socket with a
 * timeout of its own (sock_intr_errno). The emulator used to restart sixteen
 * numbers and nothing else: accept4, flock, F_SETLKW, splice and the open of
 * a FIFO came back EINTR under SA_RESTART where a kernel resumes them, and a
 * timed futex wait was restarted where a kernel reports it. Self-checking:
 * qemu-user has a restart list of its own that differs from the kernel's;
 * the expected block is what this program prints built for the host and run
 * on a real kernel.
 *
 * Every row arms a timer that lands while the call is blocked, and a helper
 * that unblocks the call a little later: a restarted call returns the
 * helper's outcome ("done"), a reported one returns EINTR (errno 4). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ALARM_US  120000   /* the handler lands here... */
#define HELPER_US 350000   /* ...and the helper unblocks the call here */

static volatile sig_atomic_t alarms;
static void on_alrm(int s) { (void)s; alarms++; }
static void nap(void) { usleep(HELPER_US); }

static int pipefd[2], spair[2], lsock, lockfd, lockfd2, fword, piword, sync_pipe[2];
static char dir[] = "/tmp/sarestXXXXXX", fifo[64], sockpath[80], lockpath[80];

/* ---- the helpers: one wake-up each, after the nap ---- */
static void *h_feed_pipe(void *a) { (void)a; nap(); if (write(pipefd[1], "x", 1) != 1) abort(); return NULL; }
static void *h_drain_pipe(void *a) {
    (void)a; nap();
    static char buf[1 << 20];
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    while (read(pipefd[0], buf, sizeof buf) > 0) ;
    return NULL;
}
static void *h_connect(void *a) {
    (void)a; nap();
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", sockpath);
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) abort();
    nap(); close(s);
    return NULL;
}
static void *h_accept(void *a) { (void)a; nap(); int c = accept(lsock, NULL, NULL); if (c >= 0) close(c); return NULL; }
static void *h_unflock(void *a) { (void)a; nap(); flock(lockfd2, LOCK_UN); return NULL; }
static void *h_unofd(void *a) {
    (void)a; nap();
    struct flock fl; memset(&fl, 0, sizeof fl); fl.l_type = F_UNLCK; fl.l_whence = SEEK_SET;
    fcntl(lockfd2, F_OFD_SETLK, &fl);
    return NULL;
}
static void *h_open_fifo(void *a) {   /* a reader, so the writer's open completes (non-blocking: a reported open leaves no writer) */
    (void)a; nap(); int f = open(fifo, O_RDONLY | O_NONBLOCK); nap(); if (f >= 0) close(f); return NULL;
}
static void *h_wake(void *a) { (void)a; nap(); syscall(SYS_futex, &fword, FUTEX_WAKE, 1, NULL, NULL, 0); return NULL; }
static void *h_unlock_pi(void *a) {
    /* This thread is the owner the word names; hold it through the nap. */
    piword = (int)syscall(SYS_gettid);
    if (write(sync_pipe[1], "o", 1) != 1) abort();
    nap();
    syscall(SYS_futex, &piword, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}
static void *h_feed_sock(void *a) { (void)a; nap(); if (send(spair[1], "x", 1, 0) != 1) abort(); return NULL; }
static void *h_nothing(void *a) { (void)a; nap(); return NULL; }

/* A reported receive leaves the helper's byte in the socket: take it. */
static void drain_sock(void) { char b; while (recv(spair[0], &b, 1, MSG_DONTWAIT) == 1) ; }

/* Take every connection still queued on the listener. */
static void drain_listen(void) {
    int fl = fcntl(lsock, F_GETFL);
    fcntl(lsock, F_SETFL, fl | O_NONBLOCK);
    int c;
    while ((c = accept(lsock, NULL, NULL)) >= 0) close(c);
    fcntl(lsock, F_SETFL, fl);
}

/* ---- the calls ---- */
static long c_read(void) { char b; return read(pipefd[0], &b, 1); }
static long c_write(void) {
    static char big[1 << 16];
    fcntl(pipefd[1], F_SETFL, O_NONBLOCK);
    while (write(pipefd[1], big, sizeof big) > 0) ;   /* fill it */
    fcntl(pipefd[1], F_SETFL, 0);
    return write(pipefd[1], big, 1);
}
static long c_accept4(void) { int c = accept4(lsock, NULL, NULL, SOCK_CLOEXEC); if (c >= 0) close(c); return c; }
static long c_connect(void) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", sockpath);
    long r = connect(s, (struct sockaddr *)&sa, sizeof sa);
    int e = errno; close(s); errno = e;
    return r;
}
static long c_flock(void) { return flock(lockfd, LOCK_EX); }
static long c_setlkw(void) {
    struct flock fl; memset(&fl, 0, sizeof fl); fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET;
    return fcntl(lockfd, F_SETLKW, &fl);
}
static long c_ofd_setlkw(void) {
    struct flock fl; memset(&fl, 0, sizeof fl); fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET;
    return fcntl(lockfd, F_OFD_SETLKW, &fl);
}
static long c_open_fifo(void) { int f = open(fifo, O_WRONLY); if (f >= 0) close(f); return f; }
static long c_futex(void) { return syscall(SYS_futex, &fword, FUTEX_WAIT, 0, NULL, NULL, 0); }
static long c_futex_timed(void) { struct timespec ts = { 3, 0 }; return syscall(SYS_futex, &fword, FUTEX_WAIT, 0, &ts, NULL, 0); }
static long c_futex_abs(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 3;
    return syscall(SYS_futex, &fword, FUTEX_WAIT_BITSET, 0, &ts, NULL, FUTEX_BITSET_MATCH_ANY);
}
static long c_lock_pi(void) {
    char b; if (read(sync_pipe[0], &b, 1) != 1) abort();   /* the owner is set */
    long r = syscall(SYS_futex, &piword, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (r == 0) syscall(SYS_futex, &piword, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return r;
}
static long c_recv(void) { char b; return recv(spair[0], &b, 1, 0); }
static long c_read_sock(void) { char b; return read(spair[0], &b, 1); }
static long c_nanosleep(void) { struct timespec ts = { 2, 0 }; return nanosleep(&ts, NULL); }
static long c_poll(void) { struct pollfd p = { pipefd[0], POLLIN, 0 }; return poll(&p, 1, 2000); }
static long c_wait(void) { int st; return waitpid(-1, &st, 0); }
static long c_splice(void) {
    int out[2]; if (pipe(out) < 0) abort();
    long r = splice(pipefd[0], NULL, out[1], NULL, 1, 0);
    int e = errno; close(out[0]); close(out[1]); errno = e;
    return r;
}

static void run(const char *what, int restart, void *(*helper)(void *), long (*call)(void)) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigaction(SIGALRM, &sa, NULL);
    alarms = 0;
    pthread_t t;
    if (pthread_create(&t, NULL, helper, NULL) != 0) abort();
    struct itimerval it = { { 0, 0 }, { 0, ALARM_US } };
    setitimer(ITIMER_REAL, &it, NULL);
    long r = call();
    int e = errno;
    struct itimerval off = { { 0, 0 }, { 0, 0 } };
    setitimer(ITIMER_REAL, &off, NULL);
    pthread_join(t, NULL);
    if (r >= 0) printf("%s/%s: done alarm=%d\n", what, restart ? "restart" : "plain", alarms ? 1 : 0);
    else printf("%s/%s: errno=%d alarm=%d\n", what, restart ? "restart" : "plain", e, alarms ? 1 : 0);
}

int main(void) {
    if (!mkdtemp(dir)) { printf("SKIP: no /tmp\n"); return 0; }
    snprintf(fifo, sizeof fifo, "%s/fifo", dir);
    snprintf(sockpath, sizeof sockpath, "%s/sock", dir);
    snprintf(lockpath, sizeof lockpath, "%s/lock", dir);
    if (mkfifo(fifo, 0600) < 0) return 1;
    lsock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", sockpath);
    if (bind(lsock, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(lsock, 0) < 0) return 1;
    lockfd = open(lockpath, O_RDWR | O_CREAT, 0600);
    lockfd2 = open(lockpath, O_RDWR);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, spair) < 0 || pipe(sync_pipe) < 0) return 1;

    for (int restart = 0; restart < 2; restart++) {
        if (pipe(pipefd) < 0) return 1;
        run("read", restart, h_feed_pipe, c_read);
        run("write", restart, h_drain_pipe, c_write);
        close(pipefd[0]); close(pipefd[1]);
        if (pipe(pipefd) < 0) return 1;
        run("splice", restart, h_feed_pipe, c_splice);
        close(pipefd[0]); close(pipefd[1]);
        run("accept4", restart, h_connect, c_accept4);
        drain_listen();   /* a reported accept left the connection queued */
        /* connect blocks once the backlog (0: one pending connection) is
         * full; the helper accepts one and makes room. */
        {
            int s = socket(AF_UNIX, SOCK_STREAM, 0);
            if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) return 1;   /* the pending one */
            run("connect", restart, h_accept, c_connect);
            close(s);
            drain_listen();
        }
        /* The locks are held through the second descriptor (flock and OFD
         * locks belong to the open file description) and released by the
         * helper; a POSIX record lock belongs to the process, so its holder
         * is a child. */
        if (flock(lockfd2, LOCK_EX) < 0) return 1;
        run("flock", restart, h_unflock, c_flock);
        flock(lockfd, LOCK_UN);
        {
            struct flock fl; memset(&fl, 0, sizeof fl); fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET;
            if (fcntl(lockfd2, F_OFD_SETLK, &fl) < 0) return 1;
            run("ofd_setlkw", restart, h_unofd, c_ofd_setlkw);
            fl.l_type = F_UNLCK; fcntl(lockfd, F_OFD_SETLK, &fl);
        }
        {
            int ready[2]; if (pipe(ready) < 0) return 1;
            pid_t k = fork();
            if (k == 0) {
                struct flock fl; memset(&fl, 0, sizeof fl); fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET;
                int f = open(lockpath, O_RDWR);
                if (fcntl(f, F_SETLK, &fl) < 0) _exit(1);
                if (write(ready[1], "l", 1) != 1) _exit(1);
                nap(); _exit(0);   /* death releases the lock */
            }
            char b; if (read(ready[0], &b, 1) != 1) return 1;
            close(ready[0]); close(ready[1]);
            run("setlkw", restart, h_nothing, c_setlkw);
            { struct flock fl; memset(&fl, 0, sizeof fl); fl.l_type = F_UNLCK; fl.l_whence = SEEK_SET; fcntl(lockfd, F_SETLK, &fl); }
            int st; waitpid(k, &st, 0);
        }
        run("open_fifo", restart, h_open_fifo, c_open_fifo);
        run("futex", restart, h_wake, c_futex);
        run("futex_timed", restart, h_wake, c_futex_timed);
        run("futex_abs", restart, h_wake, c_futex_abs);
        run("lock_pi", restart, h_unlock_pi, c_lock_pi);
        run("recv", restart, h_feed_sock, c_recv);
        drain_sock();
        run("read_sock", restart, h_feed_sock, c_read_sock);
        drain_sock();
        {
            struct timeval tv = { 5, 0 };
            setsockopt(spair[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            run("recv_timeo", restart, h_feed_sock, c_recv);
            drain_sock();
            tv.tv_sec = 0;
            setsockopt(spair[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        }
        run("nanosleep", restart, h_nothing, c_nanosleep);
        if (pipe(pipefd) < 0) return 1;
        run("poll", restart, h_feed_pipe, c_poll);
        close(pipefd[0]); close(pipefd[1]);
        {
            pid_t k = fork();
            if (k == 0) { nap(); _exit(0); }
            run("waitpid", restart, h_nothing, c_wait);
            if (restart == 0) { int st; waitpid(k, &st, 0); }   /* reported: still to reap */
        }
    }
    unlink(fifo); unlink(sockpath); unlink(lockpath); rmdir(dir);
    printf("done\n");
    return 0;
}
