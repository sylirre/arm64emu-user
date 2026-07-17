/* Guest-view /proc fidelity, run against a throwaway mini-rootfs built by
 * run_tests.sh (qemu-user has no rootfs concept, so this cannot be
 * differential): the magic self-links resolve and read back in guest terms —
 * /proc/self/root must NOT escape to the host fs — and maps/cmdline/comm/
 * mounts/mountinfo/auxv are synthesized from guest state. Expected output is
 * hard-coded in run_tests.sh. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void rl(const char *p) {
    char b[PATH_MAX];
    ssize_t n = readlink(p, b, sizeof b - 1);
    if (n < 0) { printf("readlink %s: fail\n", p); return; }
    b[n] = 0;
    printf("readlink=%s\n", b);
}

int main(void) {
    char b[4096];

    /* Containment: /proc/self/root is the GUEST root, not the host's. */
    int fd = open("/proc/self/root/etc/hostname", O_RDONLY);
    ssize_t n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (n > 0) {
        b[n] = 0;
        b[strcspn(b, "\n")] = 0;
        printf("root_etc_hostname=%s\n", b);
    } else {
        puts("root_etc_hostname=FAIL");
    }
    if (fd >= 0) close(fd);

    if (chdir("/etc") != 0) puts("chdir fail");
    rl("/proc/self/cwd");                        /* /etc */
    rl("/proc/self/root");                       /* / */
    rl("/proc/self/exe");                        /* /procfs_fidelity.bin */
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/exe", (int)getpid());
    rl(p);                                       /* numeric-pid spelling */

    fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0) {
        snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
        rl(p);                                   /* guest path, no host prefix */
        close(fd);
    } else {
        puts("open /etc/hostname: fail");
    }

    struct stat st;
    printf("lstat_cwd_link=%d\n",
           lstat("/proc/self/cwd", &st) == 0 && S_ISLNK(st.st_mode));

    fd = open("/proc/self/cmdline", O_RDONLY);
    n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (n > 0) printf("cmdline=%s trailing_nul=%d\n", b, b[n - 1] == 0);
    else puts("cmdline=FAIL");
    if (fd >= 0) close(fd);

    fd = open("/proc/self/comm", O_RDONLY);
    n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (n > 0) {
        b[n] = 0;
        b[strcspn(b, "\n")] = 0;
        printf("comm=%s\n", b);
    } else {
        puts("comm=FAIL");
    }
    if (fd >= 0) close(fd);

    FILE *f = fopen("/proc/self/mounts", "r");
    int lines = 0, have_proc = 0, have_pts = 0, have_shm = 0;
    char dev0[32] = "";
    while (f && fgets(b, sizeof b, f)) {
        if (++lines == 1) sscanf(b, "%31s", dev0);
        if (strstr(b, " /proc proc ")) have_proc = 1;
        if (strstr(b, " /dev/pts devpts ")) have_pts = 1;
        if (strstr(b, " /dev/shm tmpfs ")) have_shm = 1;
    }
    if (f) fclose(f);
    printf("mounts dev0=%s lines=%d proc=%d pts=%d shm=%d\n",
           dev0, lines, have_proc, have_pts, have_shm);

    f = fopen("/proc/self/mountinfo", "r");
    int milines = 0, sep_ok = 1;
    while (f && fgets(b, sizeof b, f)) {
        milines++;
        if (!strstr(b, " - ")) sep_ok = 0;
    }
    if (f) fclose(f);
    printf("mountinfo lines=%d sep=%d\n", milines, sep_ok);

    /* /etc/mtab is the usual symlink to /proc/mounts. */
    f = fopen("/etc/mtab", "r");
    dev0[0] = 0;
    if (f && fgets(b, sizeof b, f)) sscanf(b, "%31s", dev0);
    if (f) fclose(f);
    printf("mtab0=%s\n", dev0);

    errno = 0;
    printf("mounts_wr=%d\n",
           open("/proc/self/mounts", O_WRONLY) < 0 && errno == EACCES);

    f = fopen("/proc/self/maps", "r");
    int stack = 0, exe_named = 0, rx = 0;
    while (f && fgets(b, sizeof b, f)) {
        if (strstr(b, "[stack]")) stack = 1;
        if (strstr(b, "/procfs_fidelity.bin")) exe_named = 1;
        if (strstr(b, " r-xp ")) rx = 1;
    }
    if (f) fclose(f);
    printf("maps stack=%d exe=%d rx=%d\n", stack, exe_named, rx);

    /* Global files: shape here, guest kernel id exactly (the differential
     * test can't — qemu shows the host kernel). */
    f = fopen("/proc/loadavg", "r");
    double l0, l1, l2;
    int running = 0, total = 0, lastpid = 0, nf = 0;
    if (f) nf = fscanf(f, "%lf %lf %lf %d/%d %d",
                       &l0, &l1, &l2, &running, &total, &lastpid);
    if (f) fclose(f);
    printf("loadavg fields=%d\n", nf);

    f = fopen("/proc/uptime", "r");
    double up = -1, idle = -1;
    nf = f ? fscanf(f, "%lf %lf", &up, &idle) : 0;
    if (f) fclose(f);
    printf("uptime fields=%d up_pos=%d\n", nf, up > 0);

    f = fopen("/proc/version", "r");
    b[0] = 0;
    if (f && !fgets(b, sizeof b, f)) b[0] = 0;
    if (f) fclose(f);
    printf("version_guest=%d\n",
           strncmp(b, "Linux version 6.1.0-arm64chroot ", 32) == 0);

    /* /proc/stat — run_tests.sh sets A64_PROCSTAT_FORCE_SYNTH, so this is
     * the synthesized fallback exactly: one cpuN line per online CPU, the
     * loadavg-consistent procs_running 1, an exact btime, an idle figure
     * agreeing with /proc/uptime's, and counters that advance when reread
     * through one fd (the procps open-once/lseek/reread pattern). */
    struct sysinfo si;
    sysinfo(&si);
    long long sum1 = -1, sum2 = -1, btime = -1, prunning = -1;
    double sidle = -1;
    int ncpu = 0;
    fd = open("/proc/stat", O_RDONLY);
    for (int pass = 0; pass < 2 && fd >= 0; pass++) {
        static char sb[1 << 16];
        ssize_t r, tot = 0;
        lseek(fd, 0, SEEK_SET);
        while ((r = read(fd, sb + tot, sizeof sb - 1 - (size_t)tot)) > 0)
            tot += r;
        sb[tot] = 0;
        unsigned long long v[4] = { 0 };
        long long *sum = pass ? &sum2 : &sum1;
        if (sscanf(sb, "cpu %llu %llu %llu %llu",
                   &v[0], &v[1], &v[2], &v[3]) == 4) {
            *sum = (long long)(v[0] + v[1] + v[2] + v[3]);
            sidle = (double)v[3] / 100.0;
        }
        for (char *q = sb; !pass && q; q = strchr(q + 1, '\n')) {
            if (*q == '\n') q++;
            /* "cpuN" only: %d after "cpu" would eat the aggregate line */
            if (!strncmp(q, "cpu", 3) && q[3] >= '0' && q[3] <= '9') ncpu++;
            sscanf(q, "btime %lld", &btime);
            sscanf(q, "procs_running %lld", &prunning);
        }
        if (!pass) {
            struct timespec ts = { 0, 120000000 };
            nanosleep(&ts, NULL);
        }
    }
    long long boot = (long long)time(NULL) - (long long)si.uptime;
    printf("stat ncpu=%d running1=%d btime_ok=%d idle_agree=%d\n",
           ncpu == (int)sysconf(_SC_NPROCESSORS_ONLN), prunning == 1,
           btime >= boot - 3 && btime <= boot + 3,
           sidle >= 0 && idle >= 0 && sidle - idle < 2.0 && idle - sidle < 2.0);
    printf("stat_rewind=%d\n", sum1 > 0 && sum2 > sum1);

    /* uptime through one fd must advance on reread too. */
    fd = fd >= 0 ? (close(fd), open("/proc/uptime", O_RDONLY)) : -1;
    double u1 = -1, u2 = -1;
    if (fd >= 0) {
        n = read(fd, b, sizeof b - 1);
        if (n > 0) { b[n] = 0; sscanf(b, "%lf", &u1); }
        struct timespec ts = { 0, 120000000 };
        nanosleep(&ts, NULL);
        lseek(fd, 0, SEEK_SET);
        n = read(fd, b, sizeof b - 1);
        if (n > 0) { b[n] = 0; sscanf(b, "%lf", &u2); }
        close(fd);
    }
    printf("uptime_rewind=%d\n", u1 > 0 && u2 > u1);

    /* /proc/<pid>/auxv of ANOTHER guest process — the gdb-attach shape (gdb
     * reads the inferior's auxv for AT_HWCAP) — must be the guest auxv from
     * the shared registry, not the emulator's own host auxv (whose wrong-ISA
     * AT_HWCAP sends gdb chasing pauth/SVE regsets the ptrace shim doesn't
     * have). The child's registry entry is published inside its fork return
     * path, so any guest code running in the child implies it is visible;
     * the pipe byte orders the parent's read after that. */
    int ready[2], hold[2];
    char one = 1;
    if (pipe(ready) == 0 && pipe(hold) == 0) {
        pid_t ch = fork();
        if (ch == 0) {
            ssize_t w = write(ready[1], &one, 1);
            ssize_t r = read(hold[0], &one, 1);
            (void)w; (void)r;
            _exit(0);
        }
        if (read(ready[0], &one, 1) != 1) puts("auxv_foreign sync=FAIL");
        snprintf(p, sizeof p, "/proc/%d/auxv", (int)ch);
        unsigned long long pair[2], hw = 0, pg = 0;
        int ents = 0;
        fd = open(p, O_RDONLY);
        while (fd >= 0 && read(fd, pair, 16) == 16 && pair[0] != 0) {
            if (pair[0] == 16) hw = pair[1];   /* AT_HWCAP */
            if (pair[0] == 6)  pg = pair[1];   /* AT_PAGESZ */
            ents++;
        }
        if (fd >= 0) close(fd);
        printf("auxv_foreign entries>10=%d hwcap=%d pagesz=%d\n", ents > 10,
               hw == getauxval(AT_HWCAP) && hw != 0, pg == getauxval(AT_PAGESZ));
        ssize_t w = write(hold[1], &one, 1); (void)w;
        waitpid(ch, NULL, 0);
    } else {
        puts("auxv_foreign pipe=FAIL");
    }
    return 0;
}
