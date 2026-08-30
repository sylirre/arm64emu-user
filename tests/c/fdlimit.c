/* SAME-HOST-ONLY: the descriptor numbers depend on what the process running
 * the test had open, and the fixture lives in the host /tmp; a replay host
 * (Android: no /tmp) answers differently for reasons that are not the
 * emulator's.
 *
 * RLIMIT_NOFILE is the one limit the guest and this emulator have to share a
 * table for, because guest fd IS host fd. Containment names a path target by a
 * descriptor rather than by a name (path.c), so a path syscall holds one of its
 * own while it runs -- two for the calls that pin the final component as well --
 * and handing the limit straight to the host charged those to the guest: it
 * could open one fewer file than a kernel allows, and statfs/chmod answered
 * EMFILE with a slot still free, where a kernel needs no descriptor at all.
 *
 * So the rows here are what a kernel does with a descriptor table at its
 * ceiling, and the oracle answers every one of them: how many files fit and
 * what the highest number is, that the path syscalls needing no descriptor
 * still work at full saturation, that everything which does need one is
 * refused, that freeing one hands the same number back, and the two calls where
 * the guest NAMES the descriptor and the limit is a straight argument check. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE               /* dup3 */
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#define LIM 64

static char path[] = "/tmp/ci_fdlim.XXXXXX";

/* -1 for failure, so a row reads the same on both sides without printing an
 * errno that only one of them can have a reason for. */
static int ok(long r) { return r < 0 ? -1 : 0; }

int main(void)
{
    unlink("/tmp/ci_fdlim_new");     /* a crashed earlier run leaves one */
    int tfd = mkstemp(path);
    if (tfd < 0) { printf("mkstemp errno=%d\n", errno); return 0; }

    struct rlimit rl = { LIM, LIM };
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) { printf("setrlimit errno=%d\n", errno); return 0; }

    /* Naming a descriptor at or above the limit is refused by the argument
     * check, not by exhaustion -- and each call has its own errno for it. */
    errno = 0;
    printf("dup3_over=%d errno=%d\n", ok(dup3(tfd, LIM, 0)), errno);
    errno = 0;
    printf("dupfd_over=%d errno=%d\n", ok(fcntl(tfd, F_DUPFD, LIM)), errno);
    errno = 0;
    printf("dupfd_ok=%d\n", ok(fcntl(tfd, F_DUPFD, LIM - 1)));

    /* Fill the table. */
    int n = 0, last = -1;
    for (;;) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) break;
        last = fd;
        n++;
        if (n > 4 * LIM) break;          /* a limit that is not being enforced */
    }
    printf("filled n=%d highest=%d errno=%d\n", n, last, errno);

    /* A kernel needs no descriptor for any of these, so a full table changes
     * nothing about them. statfs and chmod are the two that pin the final
     * component as well as its parent, so they needed two. */
    struct stat st;
    struct statfs sf;
    printf("stat=%d lstat=%d access=%d\n",
           ok(stat(path, &st)), ok(lstat(path, &st)), ok(access(path, R_OK)));
    printf("statfs=%d chmod=%d truncate=%d\n",
           ok(statfs(path, &sf)), ok(chmod(path, 0600)), ok(truncate(path, 0)));
    printf("chdir=%d rename=%d\n",
           ok(chdir("/tmp")), ok(rename(path, path)));

    /* Everything that does need one is refused, and by exhaustion. */
    errno = 0; printf("open_full=%d errno=%d\n", ok(open(path, O_RDONLY)), errno);
    /* And it must not leave the file behind: the kernel takes the descriptor
     * before it does the lookup, so an open with none to return creates
     * nothing. Asked with O_EXCL so the answer is visible after a slot frees. */
    errno = 0;
    printf("creat_full=%d errno=%d\n",
           ok(open("/tmp/ci_fdlim_new", O_RDONLY | O_CREAT | O_EXCL, 0600)), errno);
    errno = 0; printf("dup_full=%d errno=%d\n", ok(dup(tfd)), errno);
    errno = 0; printf("socket_full=%d errno=%d\n",
                      ok(socket(AF_UNIX, SOCK_STREAM, 0)), errno);
    int p[2];
    errno = 0; printf("pipe_full=%d errno=%d\n", ok(pipe(p)), errno);
    int sv[2];
    errno = 0; printf("spair_full=%d errno=%d\n",
                      ok(socketpair(AF_UNIX, SOCK_STREAM, 0, sv)), errno);

    /* One back, and open(2) promises the lowest free number -- which is the one
     * just released, and must not have been taken by anything of the
     * emulator's. */
    close(last);
    int again = open(path, O_RDONLY);
    printf("reopen_same=%d\n", again == last ? 1 : 0);
    /* Nothing was created above, so this is the first one to succeed. */
    close(again);
    errno = 0;
    printf("creat_after=%d errno=%d\n",
           ok(open("/tmp/ci_fdlim_new", O_WRONLY | O_CREAT | O_EXCL, 0600)), errno);
    unlink("/tmp/ci_fdlim_new");

    unlink(path);
    printf("done\n");
    return 0;
}
