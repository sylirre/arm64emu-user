/* Rootfs containment against a path race (self-checking; no oracle can answer
 * this -- qemu-user has no rootfs at all, and a native run has nothing to
 * escape from).
 *
 * The emulator resolves a guest path itself and then asks the host to resolve
 * the result all over again. Between the two, another guest thread can rename a
 * symlink into any directory of that path -- and a symlink is resolved by the
 * HOST against the host's root, not the guest's, so "/" reaches the whole
 * filesystem with the emulator's uid. This is the flipper thread below: one
 * name alternates, by rename(2), between a real directory and a symlink to "/".
 *
 * The prober thread asks for that name plus the path of a file that exists on
 * the HOST and not in the rootfs. Resolved by the emulator's own walk the
 * answer is always ENOENT: through the real directory nothing is there, and
 * through the symlink "/" means the GUEST's root. Only the host following a
 * symlink the emulator did not can produce that file -- so a single successful
 * open, or a stat of the host file's distinctive size, is an escape.
 *
 * Every path syscall gets the same treatment, since each one names the target
 * to the kernel on its own. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define DIR   "/a64race"
#define REAL  DIR "/realdir"
#define LNK   DIR "/lnk"
#define FLIP  DIR "/d"
#define VICTIM "/tmp/a64_toctou_victim"   /* a HOST path: not in the rootfs */
#define VSIZE  4242
#define PROBE  FLIP VICTIM
#define PROBE_DIR FLIP "/tmp/"    /* the host's /tmp, if the race is ever won */

static volatile int stop;

/* One counter per probe, so a failure names the syscall that escaped (printed
 * to stderr; stdout carries only the verdict). */
enum { P_OPEN, P_STAT, P_LSTAT, P_ACCESS, P_STATFS, P_CHMOD, P_TRUNCATE,
       P_UTIMES, P_READLINK, P_LISTXATTR, P_LINK, P_N };
static const char *pname[P_N] = {
    "open", "stat", "lstat", "access", "statfs", "chmod", "truncate",
    "utimensat", "readlink", "listxattr", "link",
};
static long hit[P_N];

static void *flipper(void *a) {
    (void)a;
    while (!stop) {
        rename(REAL, FLIP); rename(FLIP, REAL);
        rename(LNK, FLIP);  rename(FLIP, LNK);
    }
    return NULL;
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    double secs = argc > 1 ? atof(argv[1]) : 3.0;
    /* A previous run's tree (its own /a64race, in whatever state the flipper
     * left it, plus everything the creation probes made inside the rootfs)
     * must not decide this one: clear it out first. */
    static const char *made[] = {
        "a64_race_mkdir", "a64_race_creat", "a64_race_sym", "a64_race_fifo",
        "a64_race_moved", "a64_race_sock", "a64_toctou_unlinkme",
    };
    mkdir(DIR, 0755);
    for (unsigned i = 0; i < sizeof made / sizeof made[0]; i++) {
        char p2[256];
        snprintf(p2, sizeof p2, "%s/tmp/%s", REAL, made[i]);
        unlink(p2);
        rmdir(p2);
    }
    unlink(LNK); unlink(FLIP); rmdir(FLIP);
    unlink(DIR "/movable"); unlink(DIR "/hard");
    rmdir(REAL "/tmp"); rmdir(REAL);
    if (mkdir(REAL, 0755) < 0 || symlink("/", LNK) < 0) { perror("setup"); return 1; }
    /* The real directory carries a "tmp" of its own, so the probe path below
     * resolves through EITHER state of the flipped name. Without it the walk
     * simply fails while the name is a directory, and the race would only ever
     * be tried against half of the window. */
    mkdir(REAL "/tmp", 0755);
    int mv = open(DIR "/movable", O_CREAT | O_WRONLY, 0644);   /* rename's source */
    if (mv >= 0) close(mv);

    /* The victim must be invisible to an honest guest lookup, or the test would
     * be measuring the wrong thing. */
    struct stat st;
    if (stat(VICTIM, &st) == 0) { printf("victim visible in rootfs\n"); return 1; }

    pthread_t th;
    if (pthread_create(&th, NULL, flipper, NULL) != 0) { perror("thread"); return 1; }

    long tries = 0, escapes = 0;
    double t0 = now();
    while (now() - t0 < secs) {
        for (int i = 0; i < 64; i++) {
            char buf[64];
            struct statfs sfs;
            struct timespec times[2] = { { 0, UTIME_NOW }, { 0, UTIME_NOW } };
            tries++;
            /* Every one of these is a positive sighting of the host file:
             * through the guest's own view the name does not exist. */
            int fd = open(PROBE, O_RDONLY);
            if (fd >= 0) { hit[P_OPEN]++; close(fd); }
            if (stat(PROBE, &st) == 0 && st.st_size == VSIZE) hit[P_STAT]++;
            if (lstat(PROBE, &st) == 0 && st.st_size == VSIZE) hit[P_LSTAT]++;
            if (access(PROBE, R_OK) == 0) hit[P_ACCESS]++;
            if (statfs(PROBE, &sfs) == 0) hit[P_STATFS]++;
            if (chmod(PROBE, 0644) == 0) hit[P_CHMOD]++;
            if (truncate(PROBE, VSIZE) == 0) hit[P_TRUNCATE]++;   /* its own size */
            if (utimensat(AT_FDCWD, PROBE, times, 0) == 0) hit[P_UTIMES]++;
            if (readlink(PROBE, buf, sizeof buf) >= 0) hit[P_READLINK]++;
            if (listxattr(PROBE, buf, sizeof buf) >= 0) hit[P_LISTXATTR]++;
            if (link(PROBE, DIR "/hard") == 0) { hit[P_LINK]++; unlink(DIR "/hard"); }

            /* The mutating half. These cannot be judged from in here: an
             * honest resolution puts every one of them inside the rootfs
             * (through the symlink, "/" is the GUEST's root), and the guest
             * cannot see the host paths they would escape to. The harness
             * checks afterwards that no such host file appeared and that the
             * host file below still exists. */
            mkdir(PROBE_DIR "a64_race_mkdir", 0755);
            int cfd = open(PROBE_DIR "a64_race_creat", O_CREAT | O_WRONLY, 0644);
            if (cfd >= 0) close(cfd);
            if (symlink("x", PROBE_DIR "a64_race_sym") == 0) { /* rootfs-side */ }
            mknod(PROBE_DIR "a64_race_fifo", S_IFIFO | 0644, 0);
            rename(DIR "/movable", PROBE_DIR "a64_race_moved");
            unlink(PROBE_DIR "a64_toctou_unlinkme");
            rmdir(PROBE_DIR "a64_race_rmdir");
            struct sockaddr_un un;
            memset(&un, 0, sizeof un);
            un.sun_family = AF_UNIX;
            strncpy(un.sun_path, PROBE_DIR "a64_race_sock", sizeof un.sun_path - 1);
            int sk = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sk >= 0) {
                if (bind(sk, (struct sockaddr *)&un, sizeof un) == 0)
                    unlink(PROBE_DIR "a64_race_sock");   /* ours, in the rootfs */
                close(sk);
            }
        }
    }
    stop = 1;
    pthread_join(th, NULL);
    for (int i = 0; i < P_N; i++) {
        escapes += hit[i];
        if (hit[i]) fprintf(stderr, "  %-10s escaped %ld times\n", pname[i], hit[i]);
    }
    printf("escaped=%ld\n", escapes);
    printf("tries=%s\n", tries > 1000 ? "enough" : "too-few");
    printf("done\n");
    return 0;
}
