/* /proc/<tid> of a thread that is not its process's main thread. The kernel
 * resolves any task id under /proc (proc_pid_lookup), not only a process's,
 * and serves it the process directory's entries for that task -- while
 * /proc itself lists processes alone. So for a thread of this process and a
 * thread of another one:
 *   - /proc/<tid> exists, and is not in the /proc listing;
 *   - status names the thread (Pid) and its process (Tgid), comm the thread;
 *   - cmdline, environ, exe, maps and fd/ are the process's: the same as
 *     /proc/<pid>'s;
 *   - task/ lists the whole thread group.
 * The emulator answered ENOENT for every /proc/<tid> of a thread that was not
 * a main one.
 *
 * Self-checking: under qemu-user these files are the host's, which describe
 * qemu. The expectations are a kernel's, and hold on any architecture: this
 * program gives the same answers built natively for the host. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int ready[2], hold[2];

static long slurp(const char *path, char *buf, long cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long n = 0, r;
    while (n < cap && (r = read(fd, buf + n, (size_t)(cap - n))) > 0) n += r;
    close(fd);
    return n;
}

static int same_file(const char *a, const char *b) {
    static char x[1 << 16], y[1 << 16];
    long n = slurp(a, x, sizeof x), m = slurp(b, y, sizeof y);
    return n >= 0 && n == m && !memcmp(x, y, (size_t)n);
}

static int same_link(const char *a, const char *b) {
    char x[4096], y[4096];
    ssize_t n = readlink(a, x, sizeof x), m = readlink(b, y, sizeof y);
    return n > 0 && n == m && !memcmp(x, y, (size_t)n);
}

static int status_field(const char *path, const char *key) {
    char buf[8192];
    long n = slurp(path, buf, sizeof buf - 1);
    if (n < 0) return -1;
    buf[n] = 0;
    size_t kl = strlen(key);
    for (char *l = buf; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL)
        if (!strncmp(l, key, kl) && l[kl] == ':') return atoi(l + kl + 1);
    return -1;
}

static int dir_has(const char *dir, long id) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)))
        if (atol(e->d_name) == id) found = 1;
    closedir(d);
    return found;
}

/* The maps line covering `addr`, as a yes. */
static int maps_covers(const char *path, unsigned long addr) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    unsigned long lo, hi;
    int found = 0;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && addr >= lo && addr < hi) found = 1;
    fclose(f);
    return found;
}

static void *worker(void *a) {
    (void)a;
    pthread_setname_np(pthread_self(), "worker");
    long tid = syscall(SYS_gettid);
    if (write(ready[1], &tid, sizeof tid) != sizeof tid) _exit(5);
    char b;
    if (read(hold[0], &b, 1) < 0) _exit(5);   /* until told to go */
    return NULL;
}

/* One thread's rows: `pid` its process, `tid` the thread. */
static void rows(const char *who, long pid, long tid) {
    char tp[64], pp[64], a[96], b[96];
    snprintf(tp, sizeof tp, "/proc/%ld", tid);
    snprintf(pp, sizeof pp, "/proc/%ld", pid);
    struct stat st;
    printf("%s_exists=%d\n", who, stat(tp, &st) == 0 && S_ISDIR(st.st_mode));
    printf("%s_listed=%d\n", who, dir_has("/proc", tid));
    snprintf(a, sizeof a, "%s/status", tp);
    printf("%s_status_pid=%d tgid=%d\n", who, status_field(a, "Pid") == tid,
           status_field(a, "Tgid") == pid);
    snprintf(a, sizeof a, "%s/comm", tp);
    char comm[32] = "";
    long n = slurp(a, comm, sizeof comm - 1);
    comm[n > 0 ? n : 0] = 0;
    printf("%s_comm=%s", who, n > 0 ? comm : "?\n");
    static const char *files[] = { "cmdline", "environ" };
    for (unsigned i = 0; i < 2; i++) {
        snprintf(a, sizeof a, "%s/%s", tp, files[i]);
        snprintf(b, sizeof b, "%s/%s", pp, files[i]);
        printf("%s_%s_same=%d\n", who, files[i], same_file(a, b));
    }
    snprintf(a, sizeof a, "%s/exe", tp);
    snprintf(b, sizeof b, "%s/exe", pp);
    printf("%s_exe_same=%d\n", who, same_link(a, b));
    snprintf(a, sizeof a, "%s/task", tp);
    printf("%s_task_lists=%d %d\n", who, dir_has(a, pid), dir_has(a, tid));
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (pipe(ready) || pipe(hold)) return 1;
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    long tid;
    if (read(ready[0], &tid, sizeof tid) != sizeof tid) return 1;
    rows("own", getpid(), tid);
    char a[64];
    snprintf(a, sizeof a, "/proc/%ld/maps", tid);
    printf("own_maps_covers_main=%d\n", maps_covers(a, (unsigned long)&main));
    snprintf(a, sizeof a, "/proc/%ld/fd/1", tid);
    printf("own_fd_same=%d\n", same_link(a, "/proc/self/fd/1"));
    if (write(hold[1], "g", 1) != 1) return 1;
    pthread_join(t, NULL);
    close(hold[0]); close(hold[1]);

    /* Another process's thread. */
    if (pipe(hold)) return 1;
    pid_t kid = fork();
    if (kid == 0) {
        pthread_create(&t, NULL, worker, NULL);
        pthread_join(t, NULL);
        _exit(0);
    }
    if (read(ready[0], &tid, sizeof tid) != sizeof tid) return 1;
    rows("other", kid, tid);
    if (write(hold[1], "g", 1) != 1) return 1;
    waitpid(kid, NULL, 0);

    struct stat st;
    printf("gone=%d\n", stat("/proc/2147483646", &st) != 0);
    printf("done\n");
    return 0;
}
