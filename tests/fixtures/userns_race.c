/* Registration order around a faked user namespace.
 *
 * The maps of a faked CLONE_NEWUSER live in the shared PID registry, not in the
 * process's own Machine, because the usual way to populate them is for the
 * PARENT to write /proc/<child>/uid_map. That puts three actors on one record --
 * the child unsharing, the parent publishing the child's registry slot, and the
 * parent writing the maps -- and parent and child run concurrently from the
 * fork on, so their order is not fixed. Every interleaving must still produce
 * what a real kernel produces:
 *
 *   R1  the child unshares and maps its own ids with no handshake at all,
 *       racing its parent's publication of its slot.
 *   R2  the same one level down: the parent already holds a namespace, so a
 *       late inherit would otherwise overwrite the fresh one the child made.
 *   R3  the parent maps the child, which signals only that it has unshared --
 *       the real-world shape, and the one that fails outright if the child's
 *       namespace was never recorded where the parent could see it.
 *   R4  a grandchild of that arrangement reads the inherited maps the instant
 *       it starts. Those maps were written from outside the namespace, so they
 *       are in no Machine state a fork hands down; only the registry has them,
 *       and the grandchild's own slot is published by a process running
 *       concurrently with it.
 *
 * Self-checking: every assertion is the answer a real kernel gives (verified
 * against one for the same sequence), but qemu cannot be the oracle, because it
 * hands unshare to the host, where an unprivileged process gets either a
 * refusal or -- under an AppArmor userns restriction -- a namespace it holds no
 * capability in. Only which code path reaches the answer varies here; a run
 * that prints ok=1 three times is a pass.
 *
 * These are timing races, so the loops are sized to catch them: with the
 * ordering guards removed, R2 and R3 both trip well inside one round. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define ROUNDS 1000
#define MAP "         0       1000          1"

static int write_str(const char *p, const char *s) {
    int fd = open(p, O_RDWR);
    if (fd < 0) return -errno;
    ssize_t r = write(fd, s, strlen(s));
    int e = r < 0 ? -errno : (int)r;
    close(fd);
    return e;
}

static const char *slurp(const char *p, char *b, size_t n) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return "-";
    ssize_t r = read(fd, b, n - 1);
    close(fd);
    if (r < 0) r = 0;
    b[r] = 0;
    while (r > 0 && b[r - 1] == '\n') b[--r] = 0;
    return b;
}

/* Unshare, then map our own ids and read them back. A fresh namespace starts
 * empty, takes exactly one write, and reports it in the kernel's column form. */
static int self_map_child(void) {
    char b[256];
    if (unshare(CLONE_NEWUSER) != 0) return 10;
    if (strcmp(slurp("/proc/self/uid_map", b, sizeof b), "")) return 11;
    if (write_str("/proc/self/uid_map", "0 1000 1") != 8) return 12;
    if (strcmp(slurp("/proc/self/uid_map", b, sizeof b), MAP)) return 13;
    if (write_str("/proc/self/uid_map", "0 1000 1") != -EPERM) return 14;
    return 0;
}

static int unsynchronized_children(const char *tag) {
    for (int i = 0; i < ROUNDS; i++) {
        fflush(stdout);
        pid_t k = fork();
        if (k == 0) _exit(self_map_child());
        int st = 0;
        waitpid(k, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) {
            printf("%s iter %d -> %d\n", tag, i, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            return 0;
        }
    }
    return 1;
}

/* The child unshares and waits; the parent writes its maps from outside. With
 * `grandchild`, the child then forks one that reads the inherited maps at once
 * and reports through its exit status. */
static int parent_maps_child(const char *tag, int grandchild) {
    for (int i = 0; i < ROUNDS; i++) {
        int up[2], down[2];
        char path[64], b[256], c;
        if (pipe(up) || pipe(down)) return 0;
        fflush(stdout);
        pid_t k = fork();
        if (k == 0) {
            close(up[0]); close(down[1]);
            if (unshare(CLONE_NEWUSER) != 0) _exit(20);
            c = 'x';
            if (write(up[1], &c, 1) != 1) _exit(21);
            if (read(down[0], &c, 1) != 1) _exit(22);
            if (!grandchild)
                _exit(strcmp(slurp("/proc/self/uid_map", b, sizeof b), MAP) ? 23 : 0);
            pid_t g = fork();
            if (g == 0)
                _exit(strcmp(slurp("/proc/self/uid_map", b, sizeof b), MAP) ? 24 : 0);
            int gs = 0;
            waitpid(g, &gs, 0);
            _exit(WIFEXITED(gs) ? WEXITSTATUS(gs) : 25);
        }
        close(up[1]); close(down[0]);
        if (read(up[0], &c, 1) != 1) return 0;
        snprintf(path, sizeof path, "/proc/%d/uid_map", (int)k);
        int w = write_str(path, "0 1000 1");
        c = 'g';
        if (write(down[1], &c, 1) != 1) return 0;
        int st = 0;
        waitpid(k, &st, 0);
        close(up[0]); close(down[1]);
        if (w != 8 || !WIFEXITED(st) || WEXITSTATUS(st)) {
            printf("%s iter %d -> write=%d child=%d\n", tag, i, w,
                   WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            return 0;
        }
    }
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* keep verdicts if a probe kills us */
    printf("R1 ok=%d\n", unsynchronized_children("R1"));
    /* Take a namespace of our own, so every child below nests inside it. */
    if (unshare(CLONE_NEWUSER) != 0 ||
        write_str("/proc/self/uid_map", "0 1000 1") != 8) {
        printf("R2 setup failed\n");
        return 1;
    }
    printf("R2 ok=%d\n", unsynchronized_children("R2"));
    printf("R3 ok=%d\n", parent_maps_child("R3", 0));
    printf("R4 ok=%d\n", parent_maps_child("R4", 1));
    return 0;
}
