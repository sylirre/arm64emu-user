/* Nothing under another guest process's /proc may hand back the emulator's own
 * state. Self-checking, because qemu has no notion of a guest PID registry and
 * so cannot be the oracle: what each file must contain is what this process
 * sees for *itself*, which is always the guest view.
 *
 * The leak this pins down was reachable from a shell with no race at all:
 * /proc/<pid>/task/<tid>/ names the same per-process files as /proc/<pid>/, but
 * only the second spelling was recognized, so the first resolved to the host
 * file -- handing the guest the emulator's command line, its binary path, and
 * its entire environment (host secrets included). The plain spelling leaks the
 * same way whenever the registry lookup comes up empty, which a process
 * re-registering itself (execve) makes happen for real.
 *
 * The child re-execs itself in a loop so the registry entry is being rewritten
 * throughout, which is what exercises the lookup-miss path; ROUNDS is sized to
 * hit it. Every read is compared against this process's own /proc/self view. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#define ROUNDS 20000

enum { K_CMD, K_ENV, K_AUXV, K_EXE, K_CWD, NKIND };
static const char *names[NKIND] = { "cmdline", "environ", "auxv", "exe", "cwd" };
static int bad[NKIND];
static char shown[NKIND];

static char self_env[16384], self_auxv[16384], self_exe[4096], self_cwd[4096];
static size_t self_env_n, self_auxv_n;
static char argv0[4096];

static size_t slurp(const char *path, char *out, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, out, cap);
    close(fd);
    return n > 0 ? (size_t)n : 0;
}

static void note(int k, const char *what) {
    if (!shown[k]) { printf("LEAK %s: \"%.60s\"\n", names[k], what); shown[k] = 1; }
    bad[k]++;
}

/* One pass over both spellings of every registry-backed file of `w`. */
static void probe(pid_t w, const char *dir) {
    char path[128], buf[16384];

    snprintf(path, sizeof path, "%s/cmdline", dir);
    size_t n = slurp(path, buf, sizeof buf);
    if (n) {   /* empty is allowed (a lookup that came up dry); the host's is not */
        size_t l = strnlen(buf, n);
        if (l != strlen(argv0) || memcmp(buf, argv0, l)) note(K_CMD, buf);
    }

    snprintf(path, sizeof path, "%s/environ", dir);
    n = slurp(path, buf, sizeof buf);
    if (n && (n != self_env_n || memcmp(buf, self_env, n))) note(K_ENV, buf);

    snprintf(path, sizeof path, "%s/auxv", dir);
    n = slurp(path, buf, sizeof buf);
    if (n && n != self_auxv_n) {
        char d[80];
        snprintf(d, sizeof d, "%zu bytes, guest auxv is %zu", n, self_auxv_n);
        note(K_AUXV, d);
    }

    snprintf(path, sizeof path, "%s/exe", dir);
    ssize_t r = readlink(path, buf, sizeof buf - 1);
    if (r > 0) {   /* ENOENT is allowed (dry lookup); the emulator's path is not */
        buf[r] = 0;
        if (strcmp(buf, self_exe)) note(K_EXE, buf);
    }

    snprintf(path, sizeof path, "%s/cwd", dir);
    r = readlink(path, buf, sizeof buf - 1);
    if (r > 0) {
        buf[r] = 0;
        if (strcmp(buf, self_cwd)) note(K_CWD, buf);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "spin"))
        for (;;) execl("/proc/self/exe", argv[0], "spin", (char *)NULL);

    snprintf(argv0, sizeof argv0, "%s", argv[0]);
    self_env_n  = slurp("/proc/self/environ", self_env, sizeof self_env);
    self_auxv_n = slurp("/proc/self/auxv", self_auxv, sizeof self_auxv);
    ssize_t n = readlink("/proc/self/exe", self_exe, sizeof self_exe - 1);
    self_exe[n > 0 ? n : 0] = 0;
    if (!getcwd(self_cwd, sizeof self_cwd)) strcpy(self_cwd, "/");

    pid_t w = fork();
    if (w == 0) { execl("/proc/self/exe", argv[0], "spin", (char *)NULL); _exit(127); }

    char plain[64], task[80];
    snprintf(plain, sizeof plain, "/proc/%d", (int)w);
    snprintf(task, sizeof task, "/proc/%d/task/%d", (int)w, (int)w);
    for (int i = 0; i < ROUNDS; i++) { probe(w, plain); probe(w, task); }

    /* The address-space files have no guest answer at all, so they must be
     * refused rather than passed through -- the host's describe the emulator's
     * own mappings. EACCES, as a host with yama ptrace_scope=1 already gives
     * between siblings. Our own stay readable. */
    static const char *as[] = { "maps", "smaps", "numa_maps", "pagemap",
                                "stack", "mem", "syscall" };
    int denied = 1;
    for (size_t i = 0; i < sizeof as / sizeof as[0]; i++) {
        char p[128];
        for (int spelling = 0; spelling < 2; spelling++) {
            if (spelling) snprintf(p, sizeof p, "/proc/%d/task/%d/%s",
                                   (int)w, (int)w, as[i]);
            else          snprintf(p, sizeof p, "/proc/%d/%s", (int)w, as[i]);
            errno = 0;
            int fd = open(p, O_RDONLY);
            if (fd >= 0) {
                close(fd);
                printf("READABLE %s\n", p);
                denied = 0;
            } else if (errno != EACCES && errno != ENOENT) {
                printf("UNEXPECTED errno %d for %s\n", errno, p);
                denied = 0;
            }
        }
    }
    int self_maps = open("/proc/self/maps", O_RDONLY);
    if (self_maps < 0) { printf("own maps unreadable\n"); denied = 0; }
    else close(self_maps);

    kill(w, SIGKILL);
    waitpid(w, NULL, 0);

    int total = 0;
    for (int k = 0; k < NKIND; k++) total += bad[k];
    if (total) {
        printf("FAIL: %d host-view reads\n", total);
        return 1;
    }
    if (!denied) return 1;
    printf("no_host_view=1\n");
    printf("addrspace_denied=1\n");
    printf("done\n");
    return 0;
}
