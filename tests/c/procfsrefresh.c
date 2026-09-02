/* SAME-HOST-ONLY: the descriptor number the limit is set at is whatever this
 * process had free, and /proc/uptime is this host's.
 *
 * A synthesized /proc view is a memfd the emulator fills at open time and
 * refills when the guest rewinds and reads again -- that is what makes
 * /proc/uptime, /proc/loadavg and /proc/stat time-varying rather than frozen at
 * their open. The refill needs the descriptor to be in a small per-process
 * table (PF_MAX_FDS entries), and an open that is refused AFTER the view was
 * built -- the guest's RLIMIT_NOFILE says the number it landed on is one it may
 * not have -- used to close the descriptor and leave its table entry behind.
 * Enough refused opens and the table is full of dead rows, at which point the
 * next real open is not tracked at all and its file never refreshes again.
 *
 * A kernel has no such table and no such failure mode, so both sides answer the
 * same two things: the refused opens are EMFILE, and a rewound re-read of
 * /proc/uptime a moment later reports a later uptime than the first read did. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#define ROUNDS 16      /* comfortably more than PF_MAX_FDS */

static double uptime_of(int fd) {
    char buf[128];
    if (lseek(fd, 0, SEEK_SET) != 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n <= 0) return -1;
    buf[n] = 0;
    return strtod(buf, NULL);
}

int main(void) {
    struct rlimit rl, saved;
    if (getrlimit(RLIMIT_NOFILE, &saved) != 0) { printf("getrlimit failed\n"); return 1; }

    /* The lowest number an open would land on right now. Setting the soft limit
     * to exactly that makes every open below refusable and nothing else. */
    int probe = dup(0);
    if (probe < 0) { printf("dup failed\n"); return 1; }
    close(probe);

    rl = saved;
    rl.rlim_cur = (rlim_t)probe;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) { printf("setrlimit failed\n"); return 1; }
    int emfile = 0;
    for (int i = 0; i < ROUNDS; i++) {
        int fd = open("/proc/uptime", O_RDONLY);
        if (fd >= 0) { close(fd); continue; }
        if (errno == EMFILE) emfile++;
    }
    if (setrlimit(RLIMIT_NOFILE, &saved) != 0) { printf("restore failed\n"); return 1; }
    printf("emfile=%d\n", emfile);

    int fd = open("/proc/uptime", O_RDONLY);
    if (fd < 0) { printf("open failed\n"); return 1; }
    double first = uptime_of(fd);
    nanosleep(&(struct timespec){ 0, 500000000L }, NULL);
    double second = uptime_of(fd);
    close(fd);
    printf("read=%d refreshed=%d\n", first > 0 && second > 0,
           first > 0 && second > first);
    return 0;
}
