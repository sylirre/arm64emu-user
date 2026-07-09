/* Guest-view /proc fidelity, run against a throwaway mini-rootfs built by
 * run_tests.sh (qemu-user has no rootfs concept, so this cannot be
 * differential): the magic self-links resolve and read back in guest terms —
 * /proc/self/root must NOT escape to the host fs — and maps/cmdline/comm/
 * mounts/mountinfo are synthesized from guest state. Expected output is
 * hard-coded in run_tests.sh. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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
    return 0;
}
