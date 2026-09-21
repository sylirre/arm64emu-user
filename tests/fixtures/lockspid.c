/* Record-lock owners as the guest may see them: F_GETLK / F_OFD_GETLK's
 * l_pid and /proc/locks.
 *
 * Guest pids are host pids, and both faces used to hand the guest the host's
 * raw answer -- so a lock a HOST process held on a shared file named that
 * process, which kill(2), /proc and every other face keep hidden. A kernel
 * answers a caller in a pid namespace of its own with 0 for a holder it
 * cannot see (locks_translate_pid), leaves such a lock out of /proc/locks
 * together with the requests queued behind it (locks_show), and shows a
 * queued request whose owner is invisible with pid 0 (lock_get_status). An
 * OFD lock's owner is -1 either way.
 *
 * Rows: a guest child's POSIX lock (its pid, both query forms), a guest
 * child's OFD lock (-1), a guest request queued behind a guest lock (shown,
 * with its pid), and -- with a file a host process holds locked named on the
 * command line, plus that process's pid -- the host's lock (l_pid 0, absent
 * from /proc/locks, its guest waiter absent with it). Self-checking: qemu-user
 * forwards the raw answer, and the host block is what the kernel prints for a
 * caller in a child pid namespace. Run as
 *   arm64chroot / tests/fixtures/lockspid.bin [<host-locked file> <host pid>] */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef F_OFD_GETLK
#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#endif

/* /proc/locks, fully. */
static char locks[1 << 16];
static size_t locks_read(void) {
    int fd = open("/proc/locks", O_RDONLY);
    size_t n = 0;
    if (fd < 0) return 0;
    for (;;) {
        ssize_t r = read(fd, locks + n, sizeof locks - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    locks[n] = 0;
    return n;
}
/* Lines whose pid field is `pid`; `arrow` selects the queued ("-> ") lines,
 * else the lock lines. The pid is the fourth field after the number and the
 * optional arrow. */
static int locks_count(int pid, int arrow) {
    int hits = 0;
    for (char *ln = locks; *ln; ) {
        char *e = strchr(ln, '\n');
        size_t len = e ? (size_t)(e - ln) : strlen(ln);
        char line[512];
        if (len >= sizeof line) len = sizeof line - 1;
        memcpy(line, ln, len); line[len] = 0;
        char *save, *tok = strtok_r(line, " ", &save);   /* "N:" */
        tok = strtok_r(NULL, " ", &save);
        int is_arrow = tok && !strcmp(tok, "->");
        if (is_arrow) tok = strtok_r(NULL, " ", &save);
        for (int i = 0; i < 3 && tok; i++) tok = strtok_r(NULL, " ", &save);
        if (tok && is_arrow == arrow && atoi(tok) == pid) hits++;
        if (!e) break;
        ln = e + 1;
    }
    return hits;
}
static int poll_locks(int pid, int arrow, int want) {   /* up to 5 s */
    for (int i = 0; i < 500; i++) {
        locks_read();
        if ((locks_count(pid, arrow) > 0) == want) return 1;
        usleep(10000);
    }
    return 0;
}
static const char *type(short t) {
    return t == F_WRLCK ? "WRLCK" : t == F_RDLCK ? "RDLCK" : t == F_UNLCK ? "UNLCK" : "?";
}
static void query(const char *label, int fd, int cmd) {
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0, .l_pid = 0 };
    int r = fcntl(fd, cmd, &fl);
    printf("%s=%s pid=%s\n", label, r < 0 ? strerror(errno) : type(fl.l_type),
           r < 0 ? "?" : fl.l_pid == -1 ? "-1" : fl.l_pid == 0 ? "0" : "guest");
}
/* A child that takes `cmd` on a whole-file write lock and holds it until
 * told; `ready` is written when the lock call returns (or, for a request that
 * blocks, just before it is made). The release ends of the earlier children's
 * pipes are closed in each new child, or a later child blocked behind an
 * earlier one would keep that one's pipe open and neither could ever go. */
static int releases[8], nreleases;
static pid_t holder(int fd, int cmd, int *ready) {
    int p[2], q[2];
    if (pipe(p) || pipe(q)) exit(1);
    pid_t k = fork();
    if (k < 0) exit(1);
    if (k == 0) {
        close(p[0]); close(q[1]);
        for (int i = 0; i < nreleases; i++) close(releases[i]);
        struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0 };
        if (cmd == F_SETLKW) { if (write(p[1], "b", 1) != 1) _exit(1); }
        int r = fcntl(fd, cmd, &fl);
        if (cmd != F_SETLKW) { if (write(p[1], r < 0 ? "e" : "l", 1) != 1) _exit(1); }
        char c;
        if (read(q[0], &c, 1) < 0) _exit(1);
        _exit(r < 0 ? 1 : 0);
    }
    close(p[1]); close(q[0]);
    char c = 0;
    if (read(p[0], &c, 1) != 1) exit(1);
    close(p[0]);
    *ready = q[1];
    if (nreleases < 8) releases[nreleases++] = q[1];
    return k;
}
static void release(pid_t k, int ready) {
    close(ready);
    for (int i = 0; i < nreleases; i++)
        if (releases[i] == ready) releases[i] = releases[--nreleases];
    int st;
    waitpid(k, &st, 0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);            /* the children fork mid-run */
    char ta[] = "./.lockspid.a.XXXXXX", tb[] = "./.lockspid.b.XXXXXX";
    int a = mkstemp(ta), b = mkstemp(tb);
    if (a < 0 || b < 0) { printf("SKIP: no writable directory\n"); return 0; }
    int a2 = open(ta, O_RDWR);                  /* a second open file description */
    unlink(ta); unlink(tb);
    if (a2 < 0) return 1;

    /* A guest child's POSIX lock: seen, and its owner named, by both forms. */
    int rdy;
    pid_t k1 = holder(a, F_SETLK, &rdy);
    query("posix_getlk", a, F_GETLK);
    query("posix_ofd_getlk", a2, F_OFD_GETLK);
    locks_read();
    printf("posix_in_locks=%d\n", locks_count((int)k1, 0) > 0);
    /* A guest request queued behind it: shown, and named. */
    int rdy2;
    pid_t k2 = holder(a2, F_SETLKW, &rdy2);
    printf("waiter_in_locks=%d\n", poll_locks((int)k2, 1, 1));
    release(k1, rdy);                           /* k2 now holds it */
    printf("waiter_became_holder=%d\n", poll_locks((int)k2, 0, 1) && poll_locks((int)k2, 1, 0));
    release(k2, rdy2);
    /* A guest child's OFD lock: -1 for an owner, both forms. */
    pid_t k3 = holder(b, F_OFD_SETLK, &rdy);
    query("ofd_getlk", b, F_GETLK);
    char lb[64];                                /* a second description of b */
    snprintf(lb, sizeof lb, "/proc/self/fd/%d", b);
    int b2 = open(lb, O_RDWR);
    query("ofd_ofd_getlk", b2 >= 0 ? b2 : b, F_OFD_GETLK);
    locks_read();
    printf("ofd_in_locks=%d\n", locks_count(-1, 0) > 0);
    release(k3, rdy);

    if (argc >= 3) {
        /* A file a HOST process holds locked. */
        int h = open(argv[1], O_RDWR);
        int hpid = atoi(argv[2]);
        if (h < 0) { printf("host_open=%s\n", strerror(errno)); return 1; }
        query("host_getlk", h, F_GETLK);
        query("host_ofd_getlk", h, F_OFD_GETLK);
        locks_read();
        printf("host_in_locks=%d\n", locks_count(hpid, 0) > 0);
        /* A guest request queued behind the host's lock goes unseen with it. */
        pid_t k4 = holder(h, F_SETLKW, &rdy);
        usleep(300000);
        locks_read();
        printf("host_waiter_in_locks=%d\n", locks_count((int)k4, 1) > 0 || locks_count((int)k4, 0) > 0);
        kill(k4, SIGKILL);
        release(k4, rdy);
    }
    printf("done\n");
    return 0;
}
