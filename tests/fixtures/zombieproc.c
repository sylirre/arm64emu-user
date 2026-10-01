/* A guest process that has exited and not been reaped is a zombie, and a
 * kernel's zombie is still there: kill(pid, 0) finds it, getpgid(2) and
 * getsid(2) answer for it, ptrace(2) refuses it with EPERM, and /proc/<pid>
 * lists it -- with what a task without an mm, a filesystem context or a
 * mount namespace has: an empty cmdline, maps, smaps and numa_maps, zero
 * sizes in stat and statm and no Vm lines in status, EACCES for environ,
 * auxv, mem and pagemap (root's files once the mm is gone), ESRCH for
 * smaps_rollup, EINVAL for mounts, ENOENT for its exe, cwd and root.
 *
 * The emulator dropped a guest process from its registry the moment it
 * exited, so its zombie was a host process to the guest: ESRCH, and
 * ENOENT under /proc. One killed outright (SIGKILL) ran nothing to drop
 * itself, and was shown alive instead -- the cmdline, environ and exe it
 * had, its address space's sizes. Both endings are run.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

static void show(pid_t k, const char *f) {
    char p[128], b[8192];
    snprintf(p, sizeof p, "/proc/%d/%s", (int)k, f);
    int fd = open(p, O_RDONLY);
    if (fd < 0) { printf("  %s: open %s\n", f, strerror(errno)); return; }
    ssize_t n = read(fd, b, sizeof b - 1);
    int e = errno;
    close(fd);
    if (n < 0) { printf("  %s: read %s\n", f, strerror(e)); return; }
    b[n] = 0;
    if (!strcmp(f, "status")) {
        char *s = strstr(b, "State:"), *nl = s ? strchr(s, '\n') : NULL;
        if (nl) *nl = 0;
        printf("  status: %s, Vm lines %d\n", s ? s : "?", strstr(nl ? nl + 1 : b, "\nVm") != NULL);
    } else if (!strcmp(f, "stat")) {
        char *r = strrchr(b, ')');
        unsigned long vsize = 0, rss = 0;
        int f3 = 0;
        if (r) sscanf(r + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %*u %lu %lu%n", &vsize, &rss, &f3);
        printf("  stat: state %c, vsize %lu, rss %lu\n", r ? r[2] : '?', vsize, rss);
    } else if (!strcmp(f, "statm")) {
        printf("  statm: %s", b);
    } else {
        printf("  %s: %zd bytes\n", f, n);
    }
}

static void lnk(pid_t k, const char *f) {
    char p[128], b[256];
    snprintf(p, sizeof p, "/proc/%d/%s", (int)k, f);
    ssize_t n = readlink(p, b, sizeof b - 1);
    printf("  %s: readlink %s\n", f, n < 0 ? strerror(errno) : "ok");
}

static void zombie(int sigkill) {
    pid_t k = fork();
    if (k == 0) {
        if (sigkill) kill(getpid(), SIGKILL);
        _exit(3);
    }
    /* a zombie once its state says so */
    for (int i = 0; i < 400; i++) {
        siginfo_t si;
        memset(&si, 0, sizeof si);
        if (waitid(P_PID, k, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == k) break;
        nap(5);
    }
    printf("%s:\n", sigkill ? "killed by SIGKILL" : "exited");
    char p[64];
    snprintf(p, sizeof p, "/proc/%d", (int)k);
    DIR *d = opendir(p);
    printf("  /proc/<pid>: %s\n", d ? "listed" : strerror(errno));
    if (d) closedir(d);
    const char *fs[] = { "cmdline", "environ", "auxv", "status", "stat", "statm", "maps",
                         "smaps", "smaps_rollup", "numa_maps", "mem", "pagemap", "mounts",
                         "mountinfo", NULL };
    for (int i = 0; fs[i]; i++) show(k, fs[i]);
    lnk(k, "exe");
    lnk(k, "cwd");
    lnk(k, "root");
    errno = 0;
    int r = kill(k, 0);
    printf("  kill(pid, 0): %s\n", r ? strerror(errno) : "0");
    printf("  getpgid: %s\n", getpgid(k) == getpgid(0) ? "ours" : strerror(errno));
    printf("  getsid: %s\n", getsid(k) == getsid(0) ? "ours" : strerror(errno));
    errno = 0;
    long a = ptrace(PTRACE_ATTACH, k, 0, 0);
    printf("  ptrace attach: %s\n", a ? strerror(errno) : "0");
    int st;
    pid_t w = waitpid(k, &st, 0);
    printf("  reaped: %d, then kill: %s\n", w == k, kill(k, 0) ? strerror(errno) : "0");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    zombie(0);
    zombie(1);
    printf("done\n");
    return 0;
}
