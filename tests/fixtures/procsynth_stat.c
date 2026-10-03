/* A synthesized /proc file is as stat-able as it is readable (self-checking;
 * qemu-user has no synthesized /proc, so it cannot be the oracle).
 *
 * The emulator serves the open of version, stat, loadavg, uptime, cpuinfo,
 * overflow{u,g}id and the per-process maps/environ/... from a view of its own,
 * but stat(2), statx(2), access(2) and statfs(2) of the same name went to the
 * host. Android's SELinux policy denies an app getattr and access on exactly
 * the files whose open it denies, so a guest could `cat /proc/version` and not
 * `stat` it -- `ls -l /proc` printed an error per entry, `test -r` was false,
 * and every tool that stats before it opens gave up. The host's refusal is now
 * answered from the view, with the attributes a kernel's procfs gives the file:
 * a regular file of size 0 with one link, root's if it belongs to the system
 * and its owner's if it belongs to a process, on the proc filesystem.
 *
 * What is checked is the relation, not a host's answer: for every name the
 * guest CAN open, the stat family must succeed and describe a procfs file --
 * so the same expectations hold on a host that answers the stat itself, on one
 * that refuses it (A64_PROCSYNTH_FORCE_STAT_DENY makes any host that), and on
 * one that denies the open too (the name is then not served, and not checked).
 * A name that is not there, or not synthesized, must not be invented or
 * disturbed by the fallback. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NR_STATX 291               /* AArch64 */
#define PROC_SUPER_MAGIC 0x9fa0

static int fails;

static void bad(const char *path, const char *what, long a, long b) {
    printf("FAIL %s: %s (%ld vs %ld)\n", path, what, a, b);
    fails++;
}

/* The fields of a statx buffer the checks use (the layout is the kernel's). */
struct sx { unsigned nlink, uid; unsigned mode; unsigned long long size; };

static int do_statx(const char *path, int flags, struct sx *o) {
    unsigned char b[256];
    if (syscall(NR_STATX, AT_FDCWD, path, flags, 0x7ffu, b) < 0) return -1;
    unsigned short m;
    memcpy(&o->nlink, b + 16, 4);
    memcpy(&o->uid, b + 20, 4);
    memcpy(&m, b + 28, 2);
    memcpy(&o->size, b + 40, 8);
    o->mode = m;
    return 0;
}

/* `global`: belongs to the system (root's); else to a process (its owner's, or
 * root's where the process is not dumpable -- a host's call, not checked). */
static void check(const char *path, int global, unsigned mode) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;                /* not served here: nothing to hold to */
    close(fd);

    struct stat st, ls;
    if (stat(path, &st) < 0) { bad(path, "stat", errno, 0); return; }
    if (lstat(path, &ls) < 0) { bad(path, "lstat", errno, 0); return; }
    if (!S_ISREG(st.st_mode)) bad(path, "not a regular file", st.st_mode, 0);
    if ((st.st_mode & 07777) != mode) bad(path, "mode", st.st_mode & 07777, mode);
    if (st.st_size != 0) bad(path, "size", (long)st.st_size, 0);
    if (st.st_nlink != 1) bad(path, "nlink", (long)st.st_nlink, 1);
    if (global ? (st.st_uid != 0 || st.st_gid != 0)
               : (st.st_uid != 0 && st.st_uid != geteuid()))
        bad(path, "owner", st.st_uid, global ? 0 : (long)geteuid());
    if (ls.st_mode != st.st_mode || ls.st_size != st.st_size ||
        ls.st_uid != st.st_uid)
        bad(path, "lstat differs from stat", ls.st_mode, st.st_mode);

    struct sx sx;
    if (do_statx(path, 0, &sx) < 0) bad(path, "statx", errno, 0);
    else if (sx.mode != st.st_mode || sx.size != (unsigned long long)st.st_size ||
             sx.nlink != st.st_nlink || sx.uid != st.st_uid)
        bad(path, "statx differs from stat", sx.mode, st.st_mode);

    /* access: readable where the mode says everyone may; never executable
     * (no execute bit, root included); writable only to root where the file is
     * the system's (a process's own files depend on who the owner turned out
     * to be). */
    if ((mode & 0004) && access(path, R_OK) < 0) bad(path, "access R_OK", errno, 0);
    if ((mode & 0004) && faccessat(AT_FDCWD, path, R_OK, AT_EACCESS) < 0)
        bad(path, "faccessat R_OK|AT_EACCESS", errno, 0);
    if (!access(path, X_OK)) bad(path, "access X_OK succeeded", 0, EACCES);
    else if (errno != EACCES) bad(path, "access X_OK errno", errno, EACCES);
    if (global) {
        int w = access(path, W_OK);
        if (geteuid() == 0 ? w != 0 : (w == 0 || errno != EACCES))
            bad(path, "access W_OK", w == 0 ? 0 : errno, geteuid() == 0 ? 0 : EACCES);
    }
    if (access(path, F_OK) < 0) bad(path, "access F_OK", errno, 0);

    struct statfs sf;
    if (statfs(path, &sf) < 0) bad(path, "statfs", errno, 0);
    else if ((unsigned long)sf.f_type != PROC_SUPER_MAGIC)
        bad(path, "statfs f_type", (long)sf.f_type, PROC_SUPER_MAGIC);
}

int main(void) {
    static const struct { const char *path; int global; unsigned mode; } tab[] = {
        { "/proc/version",  1, 0444 }, { "/proc/uptime",  1, 0444 },
        { "/proc/loadavg",  1, 0444 }, { "/proc/cpuinfo", 1, 0444 },
        { "/proc/stat",     1, 0444 }, { "/proc/locks",   1, 0444 },
        { "/proc/sys/kernel/overflowuid", 1, 0644 },
        { "/proc/sys/kernel/overflowgid", 1, 0644 },
        { "/proc/self/status",     0, 0444 }, { "/proc/self/stat",    0, 0444 },
        { "/proc/self/statm",      0, 0444 }, { "/proc/self/cmdline", 0, 0444 },
        { "/proc/self/environ",    0, 0400 }, { "/proc/self/auxv",    0, 0400 },
        { "/proc/self/maps",       0, 0444 }, { "/proc/self/limits",  0, 0444 },
        { "/proc/self/mounts",     0, 0444 }, { "/proc/self/mountinfo", 0, 0444 },
        { "/proc/self/mountstats", 0, 0400 },
        { "/proc/thread-self/status", 0, 0444 },
    };
    for (unsigned i = 0; i < sizeof tab / sizeof tab[0]; i++)
        check(tab[i].path, tab[i].global, tab[i].mode);

    char own[64];                       /* the process's own pid spelling */
    snprintf(own, sizeof own, "/proc/%d/status", (int)getpid());
    check(own, 0, 0444);

    /* /proc/mounts is a symlink to self/mounts: stat follows it, lstat must
     * say what it is. */
    int mfd = open("/proc/mounts", O_RDONLY);
    if (mfd >= 0) {
        struct stat ms, ml;
        close(mfd);
        if (stat("/proc/mounts", &ms) < 0) bad("/proc/mounts", "stat", errno, 0);
        else if (!S_ISREG(ms.st_mode) || (ms.st_mode & 07777) != 0444)
            bad("/proc/mounts", "stat (followed) mode", ms.st_mode, S_IFREG | 0444);
        if (lstat("/proc/mounts", &ml) < 0) bad("/proc/mounts", "lstat", errno, 0);
        else if (!S_ISLNK(ml.st_mode)) bad("/proc/mounts", "lstat not a link", ml.st_mode, 0);
        else if (ml.st_size != 11) bad("/proc/mounts", "link size", (long)ml.st_size, 11);
    }

    /* What the fallback must leave alone: a name that is not there stays not
     * there, and a file nothing synthesizes keeps the host's own answer. */
    struct stat st;
    if (!stat("/proc/no_such_synth_file", &st)) bad("/proc/no_such_synth_file", "stat invented it", 0, ENOENT);
    else if (errno != ENOENT) bad("/proc/no_such_synth_file", "errno", errno, ENOENT);
    if (!access("/proc/no_such_synth_file", F_OK)) bad("/proc/no_such_synth_file", "access invented it", 0, ENOENT);
    else if (errno != ENOENT) bad("/proc/no_such_synth_file", "access errno", errno, ENOENT);
    if (stat("/proc/self/comm", &st) < 0) bad("/proc/self/comm", "stat", errno, 0);
    else if (!S_ISREG(st.st_mode)) bad("/proc/self/comm", "not a regular file", st.st_mode, 0);

    printf("fails=%d\n", fails);
    printf("done\n");
    return 0;
}
