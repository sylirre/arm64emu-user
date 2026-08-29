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
#define ROUNDS  20000
#define READERS 4
#define PAD     60

/* The tree is built under a scratch directory named on the command line (the
 * harness passes one the host actually has: Android has no /tmp, and this
 * fixture is self-checking, so no other environment has to spell its paths the
 * same way). Every path below is that base plus the long prefix, composed once
 * at startup -- the reader loop wants a ready string, not a snprintf. */
static char base[512];          /* <scratch>/a64bindrace */
static char root[768];          /* base + the long prefix (192 bytes) */
static char p_mntf[1024], p_A[1024], p_B[1024], p_Af[1024], p_Bf[1024];
static char p_mnt[1024], p_mnt2[1024];   /* root + a short tail: never cut */

static void mkpaths(const char *scratch) {
    snprintf(base, sizeof base, "%s/a64bindrace", scratch);
    snprintf(root, sizeof root, "%s/" P64 P64 P64, base);
    snprintf(p_mntf, sizeof p_mntf, "%s/mnt/f", root);
    snprintf(p_A,    sizeof p_A,    "%s/A",     root);
    snprintf(p_B,    sizeof p_B,    "%s/B",     root);
    snprintf(p_Af,   sizeof p_Af,   "%s/A/f",   root);
    snprintf(p_Bf,   sizeof p_Bf,   "%s/B/f",   root);
    snprintf(p_mnt,  sizeof p_mnt,  "%s/mnt",   root);
    snprintf(p_mnt2, sizeof p_mnt2, "%s/mnt2",  root);
}

static volatile int stop;
static volatile long wrong;      /* reads served out of the other mount */
static volatile long garbage;    /* reads of something that is neither */
static volatile long hits;       /* reads that resolved at all */

static void *reader(void *arg) {
    (void)arg;
    while (!stop) {
        int fd = open(p_mntf, O_RDONLY);
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

int main(int argc, char **argv) {
    char p[1200];
    mkpaths(argc > 1 ? argv[1] : "/tmp");
    mkdir(base, 0755);
    mkdir(root, 0755);
    mkdir(p_A, 0755); mkdir(p_B, 0755);
    mkdir(p_mnt, 0755); mkdir(p_mnt2, 0755);
    if (put(p_Af, "A") || put(p_Bf, "B")) {
        printf("setup failed\n"); return 1;
    }
    /* Slot 0 goes to the racing mount; the padding fills 1..PAD behind it. */
    if (mount(p_A, p_mnt, NULL, MS_BIND, NULL) != 0) {
        printf("mount unavailable (%d)\n", errno);
        return 1;
    }
    for (int i = 0; i < PAD; i++) {
        snprintf(p, sizeof p, "%s/d%d", root, i);
        mkdir(p, 0755);
        mount(p_B, p, NULL, MS_BIND, NULL);
    }
    umount(p_mnt);

    pthread_t r[READERS];
    for (int i = 0; i < READERS; i++) pthread_create(&r[i], NULL, reader, NULL);
    for (int i = 0; i < ROUNDS; i++) {
        mount(p_A, p_mnt, NULL, MS_BIND, NULL);
        umount(p_mnt);
        mount(p_B, p_mnt2, NULL, MS_BIND, NULL);
        umount(p_mnt2);
    }
    stop = 1;
    for (int i = 0; i < READERS; i++) pthread_join(r[i], NULL);

    printf("resolved=%d wrong=%ld garbage=%ld\n", hits > 0, wrong, garbage);

    for (int i = 0; i < PAD; i++) {
        snprintf(p, sizeof p, "%s/d%d", root, i);
        umount(p); rmdir(p);
    }
    unlink(p_Af); unlink(p_Bf);
    rmdir(p_A); rmdir(p_B);
    rmdir(p_mnt); rmdir(p_mnt2); rmdir(root);
    rmdir(base);
    return 0;
}
