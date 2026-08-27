/* Bind-table readers against slot reuse.
 *
 * umount frees a table slot and the next mount is handed the same one,
 * rewriting its guest mount point and its host directory in place.  A reader
 * that only gated on "this slot is live" could match a canonical guest path
 * against the guest string of the mount that WAS there and then join it onto
 * the host directory of the one that replaced it, resolving a path into a
 * subtree it was never mounted at.
 *
 * The two mounts here are chosen so that outcome is visible.  /race/mnt is
 * bound to a directory whose only file says A and /race/mnt2 to one whose only
 * file says B; a reader that opens "/race/mnt/f" must read A, or fail because
 * nothing is mounted at that instant -- never B.  The mount thread alternates
 * the two through mount+umount, and since a new mount takes the lowest free
 * slot, both land on the same one, over and over.
 *
 * PAD extra binds are established first and never removed, so the racing slot
 * is index 0 and every reader keeps scanning for a while after matching it --
 * which is exactly the window between reading a slot's guest path and reading
 * its host path, the one the old reader left open.
 *
 * Self-checking, and a timing race: qemu-aarch64 performs real mounts and
 * cannot be the oracle, and there would be nothing to diff anyway -- the
 * answer is that B never appears.  Needs --fake-id (mount wants CAP_SYS_ADMIN).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

/* A long shared prefix: every slot the scan walks past compares that many
 * bytes against the path being resolved, which is what makes the reader's
 * guest-string-to-host-string window wide enough to hit in a test run. */
#define P64     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define ROOT    "/tmp/a64bindrace/" P64 P64 P64
#define ROUNDS  20000
#define READERS 4
#define PAD     60

static volatile int stop;
static volatile long wrong;      /* reads served out of the other mount */
static volatile long garbage;    /* reads of something that is neither */
static volatile long hits;       /* reads that resolved at all */

static void *reader(void *arg) {
    (void)arg;
    while (!stop) {
        int fd = open(ROOT "/mnt/f", O_RDONLY);
        if (fd < 0) continue;             /* nothing mounted right now: fine */
        char b[8] = {0};
        ssize_t n = read(fd, b, sizeof b - 1);
        close(fd);
        if (n <= 0) continue;
        hits++;
        if (b[0] == 'B') wrong++;
        else if (b[0] != 'A') garbage++;
    }
    return NULL;
}

static int put(const char *path, const char *s) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    int ok = write(fd, s, strlen(s)) == (ssize_t)strlen(s);
    close(fd);
    return ok ? 0 : -1;
}

int main(void) {
    char p[1024];
    mkdir("/tmp/a64bindrace", 0755);
    mkdir(ROOT, 0755);
    mkdir(ROOT "/A", 0755); mkdir(ROOT "/B", 0755);
    mkdir(ROOT "/mnt", 0755); mkdir(ROOT "/mnt2", 0755);
    if (put(ROOT "/A/f", "A") || put(ROOT "/B/f", "B")) {
        printf("setup failed\n"); return 1;
    }
    /* Slot 0 goes to the racing mount; the padding fills 1..PAD behind it. */
    if (mount(ROOT "/A", ROOT "/mnt", NULL, MS_BIND, NULL) != 0) {
        printf("mount unavailable (%d)\n", errno);
        return 1;
    }
    for (int i = 0; i < PAD; i++) {
        snprintf(p, sizeof p, ROOT "/d%d", i);
        mkdir(p, 0755);
        mount(ROOT "/B", p, NULL, MS_BIND, NULL);
    }
    umount(ROOT "/mnt");

    pthread_t r[READERS];
    for (int i = 0; i < READERS; i++) pthread_create(&r[i], NULL, reader, NULL);
    for (int i = 0; i < ROUNDS; i++) {
        mount(ROOT "/A", ROOT "/mnt", NULL, MS_BIND, NULL);
        umount(ROOT "/mnt");
        mount(ROOT "/B", ROOT "/mnt2", NULL, MS_BIND, NULL);
        umount(ROOT "/mnt2");
    }
    stop = 1;
    for (int i = 0; i < READERS; i++) pthread_join(r[i], NULL);

    printf("resolved=%d wrong=%ld garbage=%ld\n", hits > 0, wrong, garbage);

    for (int i = 0; i < PAD; i++) {
        snprintf(p, sizeof p, ROOT "/d%d", i);
        umount(p); rmdir(p);
    }
    unlink(ROOT "/A/f"); unlink(ROOT "/B/f");
    rmdir(ROOT "/A"); rmdir(ROOT "/B");
    rmdir(ROOT "/mnt"); rmdir(ROOT "/mnt2"); rmdir(ROOT);
    rmdir("/tmp/a64bindrace");
    return 0;
}
