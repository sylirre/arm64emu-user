/* A fork child's descriptor table is its parent's -- and nothing more. Guest
 * fd == host fd here, so every descriptor the emulator opens for itself on a
 * guest thread (a path pin's O_PATH parent, the socket a blocking semop holds
 * to the IPC broker, the image an execve is loading) sits in the guest's
 * table while it is open, and a fork by ANOTHER thread used to duplicate it
 * into the child for good: 222 of 300 children of a four-thread opener loop
 * carried a directory fd they never opened, where a kernel's carry none (its
 * path walk holds dentries, not descriptors). The child's next open()
 * returned a higher number than a kernel gives and /proc/self/fd listed the
 * stray. Self-checking: qemu-user has no pins and nothing to leak; the
 * numbers are what a kernel guarantees, zero. Each row forks under a
 * different kind of sibling activity and counts, in the child, the
 * descriptors that are not the ones this program opened itself. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int stop;
static char fifo[64];
static void statfs_probe(void);

/* What a child may hold: stdio and the descriptors listed here. */
static int allowed[16];
static int nallowed;
static void allow(int fd) { if (fd >= 0 && nallowed < 16) allowed[nallowed++] = fd; }
static int is_allowed(int fd) {
    if (fd < 3) return 1;
    for (int i = 0; i < nallowed; i++) if (allowed[i] == fd) return 1;
    return 0;
}

/* Fork `n` times; count children that found a descriptor they cannot account
 * for. Run in the main thread while the helpers do their thing. */
static int fork_round(int n) {
    int bad = 0;
    for (int it = 0; it < n; it++) {
        pid_t c = fork();
        if (c == 0) {
            DIR *d = opendir("/proc/self/fd");
            if (!d) _exit(99);
            int extra = 0;
            struct dirent *de;
            while ((de = readdir(d))) {
                int fd = atoi(de->d_name);
                if (de->d_name[0] == '.' || fd == dirfd(d)) continue;
                if (!is_allowed(fd)) extra++;
            }
            _exit(extra > 100 ? 100 : extra);
        }
        int st;
        waitpid(c, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) bad++;
    }
    return bad;
}

static void *opener(void *a) {   /* path syscalls that leave no descriptor
                                   * of the guest's own behind: only pins */
    (void)a;
    char buf[64];
    while (!stop) {
        struct stat st;
        stat("/usr/bin/env", &st);
        access("/etc/passwd", R_OK);
        if (readlink("/proc/self/exe", buf, sizeof buf) < 0) {}
        chmod("/nonexistent/x", 0644);
        statfs_probe();
    }
    return NULL;
}
static void statfs_probe(void) { struct statfs f; statfs("/etc", &f); if (truncate("/nonexistent/y", 0) < 0) {} }
static void *fifo_writer(void *a) {   /* blocks in open() with the pin held */
    (void)a;
    int fd = open(fifo, O_WRONLY);
    if (fd >= 0) close(fd);
    return NULL;
}
static int semid = -1;
static void *sem_waiter(void *a) {    /* parked in the IPC broker, socket held */
    (void)a;
    struct sembuf op = { 0, -1, 0 };
    semop(semid, &op, 1);
    return NULL;
}

int main(void) {
    char dir[] = "/tmp/forkfdsXXXXXX";
    if (!mkdtemp(dir)) { printf("SKIP: no /tmp\n"); return 0; }
    snprintf(fifo, sizeof fifo, "%s/fifo", dir);
    mkfifo(fifo, 0600);
    /* A descriptor of our own, to show the count is of strangers only. */
    int keep = open("/etc/hostname", O_RDONLY);
    allow(keep);

    /* Four threads pinning paths as fast as they can (stat, access, readlink,
     * chmod, statfs, truncate -- the last three pin the final component too). */
    pthread_t t[4];
    for (int i = 0; i < 4; i++) pthread_create(&t[i], NULL, opener, NULL);
    printf("openers: bad=%d/200\n", fork_round(200));
    stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);

    /* One thread blocked in open() of a FIFO, its parent pinned throughout. */
    pthread_t w;
    pthread_create(&w, NULL, fifo_writer, NULL);
    usleep(200000);
    printf("fifo_open: bad=%d/50\n", fork_round(50));
    int rd = open(fifo, O_RDONLY);   /* release the writer */
    pthread_join(w, NULL);
    if (rd >= 0) close(rd);

    /* One thread parked in semop, its broker connection open all the while. */
    semid = semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT);
    if (semid >= 0) {
        pthread_t s;
        pthread_create(&s, NULL, sem_waiter, NULL);
        usleep(200000);
        printf("semop: bad=%d/50\n", fork_round(50));
        struct sembuf op = { 0, 1, 0 };
        semop(semid, &op, 1);   /* release the waiter */
        pthread_join(s, NULL);
        semctl(semid, 0, IPC_RMID);
    } else {
        printf("semop: bad=0/50\n");   /* no System V IPC here: nothing to leak */
    }
    close(keep);
    unlink(fifo); rmdir(dir);
    printf("done\n");
    return 0;
}
