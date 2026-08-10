/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Synthesized /proc files. Host /proc passes through, but a few files there
 * describe the EMULATOR process, not the guest: maps (host mappings, the
 * wrong ISA's addresses), cmdline (the emulator invocation), and mounts /
 * mountinfo (the host — on Android, the app-sandbox — mount namespace, which
 * confuses df/apt-style tools). Three global files are synthesized too:
 * loadavg and uptime because Android SELinux denies apps the real ones
 * (Termux patches packages to call sysinfo() instead; here unpatched guest
 * tools just work), and version because it must agree with the fixed kernel
 * identity sys_uname presents, not the host's. /proc/stat is different:
 * the readable host file is strictly richer than anything we can rebuild
 * (real per-CPU jiffies, intr, ctxt), so it passes through and synthesis
 * kicks in only where the host denies it (Android again) -- and
 * /proc/sys/kernel/overflow{u,g}id work the same try-host-first way, since
 * Android denies an app all of /proc/sys and a guest that cannot read them
 * (bubblewrap reads them before anything else) simply dies. openat() diverts
 * a read-only open of those names to an anonymous in-memory file holding
 * the guest view. The time-varying files (loadavg/uptime/stat) are also
 * regenerated when a read starts at offset 0 (procfs_pre_read): procps
 * opens them once and lseek(0)+rereads every refresh cycle, so an open-time
 * snapshot would freeze top/vmstat. environ, auxv and mountstats are
 * synthesized like cmdline and mounts: environ is the guest's own environment
 * (the host file shows the emulator's), auxv is the guest's exec-time auxv
 * block (the host file shows the emulator's — the wrong ISA's AT_HWCAP would
 * send gdb chasing pauth/SVE regsets the ptrace shim doesn't have), and
 * mountstats is the guest mount device list (the host file exposes the real
 * mount namespace). For any guest PID (not just self), the
 * exe/cwd/root symlinks resolve to the guest view too, spliced in path.c from
 * this Machine (self) or the shared PID registry (another guest process).
 * /proc/<pid>/status is synthesized line by line: most of it is a true
 * property of the process being asked about, but TracerPid, Seccomp, the
 * signal masks, NoNewPrivs and (under --fake-id) Uid/Gid/Groups and the
 * capability sets all describe the emulator instead, and the host kernel's
 * x86_* arch-hook lines describe the host CPU (see put_status). Another guest
 * process's address-space files (maps, smaps, pagemap, mem, ...) have no guest
 * answer to synthesize and the host's describes the emulator, so those are
 * refused with EACCES rather than passed through. Everything else under /proc
 * stays host-passthrough — including stat() of these paths (readers open+read). */
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>

#include "sys.h"
#include "ptrace.h"

enum {
    PF_CMDLINE, PF_MAPS, PF_MOUNTS, PF_MOUNTINFO,
    PF_LOADAVG, PF_UPTIME, PF_VERSION, PF_STAT,
    PF_ENVIRON, PF_MOUNTSTATS, PF_AUXV,
    PF_UIDMAP, PF_GIDMAP, PF_SETGROUPS,
    PF_OVERFLOWID, PF_STATUS, PF_LIMITS,
};

/* put_mounts format selector. */
enum { MNT_MOUNTS = 0, MNT_MOUNTINFO = 1, MNT_MOUNTSTATS = 2 };

/* Guards the pf_fds refresh registry (one struct Machine per process;
 * these files are opened rarely, so a single lock is fine). */
static pthread_mutex_t pf_lock = PTHREAD_MUTEX_INITIALIZER;

/* Defined below with the rest of the /proc/<pid>/status handling; the refresh
 * path (procfs_pre_read) comes first in this file. */
static int put_status(int fd, struct Machine *m, const char *canon, int self,
                      s32 *tid_out);
/* Leaf lock for the /proc/stat busy estimate — the writers run both with
 * and without pf_lock held (open vs refresh path). */
static pthread_mutex_t est_lock = PTHREAD_MUTEX_INITIALIZER;

/* Fork safety, as in mem.c. Both of this file's locks go in one triple and in
 * this order because they nest -- an estimate writer on the refresh path
 * already holds pf_lock -- so `prepare` has to take the outer one first or it
 * can deadlock against a thread coming the other way. */
/* Raw pthread calls on purpose: main()'s atfork handlers call these from
 * inside fork(), where the held-lock mask must not move (machine.h,
 * "fork safety"). */
void procfs_locks_take(void) {
    pthread_mutex_lock(&pf_lock);
    pthread_mutex_lock(&est_lock);
}
void procfs_locks_drop(void) {
    pthread_mutex_unlock(&est_lock);
    pthread_mutex_unlock(&pf_lock);
}
void procfs_locks_reinit(void) {
    pthread_mutex_init(&est_lock, NULL);
    pthread_mutex_init(&pf_lock, NULL);
}

/* Tail after any "this process" spelling -- self, own pid, thread-self, or one
 * of our threads' task/<tid> -- else NULL. See proc_self_tail (path.c). */
static const char *self_tail(const char *canon) {
    return proc_self_tail(canon);
}

/* Guest fstype of the rootfs: host statfs magic -> name, "ext4" fallback. */
static const char *rootfs_fstype(const struct Machine *m) {
    static const struct { long magic; const char *name; } tab[] = {
        { 0xEF53,       "ext4"    },
        { 0x9123683E,   "btrfs"   },
        { 0x58465342,   "xfs"     },
        { 0xF2F52010,   "f2fs"    },
        { 0x01021994,   "tmpfs"   },
        { 0x794C7630,   "overlay" },
        { 0x65735546,   "fuse"    },
        { 0x4D44,       "vfat"    },
    };
    struct statfs sf;
    if (statfs(m->rootfs[0] ? m->rootfs : "/", &sf) == 0)
        for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++)
            if ((long)sf.f_type == tab[i].magic) return tab[i].name;
    return "ext4";
}

/* A mount point in the guest's current view, or 0 when it is not reachable
 * from the current root (chroot / pivot_root) and so has no name there. */
static int mnt_view(struct Machine *m, const char *guest, char *out) {
    const char *croot = m->chroot_base[0] ? m->chroot_base : "/";
    if (!strcmp(croot, "/")) { strcpy(out, guest); return 1; }
    size_t cl = strlen(croot);
    if (strncmp(guest, croot, cl) || (guest[cl] != 0 && guest[cl] != '/')) return 0;
    strcpy(out, guest[cl] ? guest + cl : "/");
    return 1;
}

/* The guest mount table: the rootfs plus the passthrough zones path.c binds
 * (/proc, /dev/pts, /dev/shm). The devpts and shm rows are omitted under
 * --no-dev, when that passthrough is disabled. Fixed mount IDs; the root's
 * major:minor is real so tools cross-referencing stat().st_dev find it. `fmt`
 * selects the /proc/<pid>/{mounts,mountinfo,mountstats} rendering (MNT_* above). */
static void put_mounts(int fd, struct Machine *m, int fmt) {
    const char *fstype = rootfs_fstype(m);
    unsigned maj = 0, min = 0;
    struct stat st;
    if (stat(m->rootfs[0] ? m->rootfs : "/", &st) == 0) {
        maj = major(st.st_dev);
        min = minor(st.st_dev);
    }
    static const struct {
        const char *src, *dir, *type, *opts, *sopts;
    } pseudo[] = {
        { "proc",   "/proc",    "proc",
          "rw,nosuid,nodev,noexec,relatime", "rw" },
        { "devpts", "/dev/pts", "devpts",
          "rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666",
          "rw,gid=5,mode=620,ptmxmode=666" },
        { "tmpfs",  "/dev/shm", "tmpfs",  "rw,nosuid,nodev", "rw" },
    };
    /* -bind mounts follow the pseudo rows. Source is the host directory (as the
     * user supplied it); the kernel doesn't tag /proc/mounts entries as "bind",
     * so they read as ordinary mounts, ro or rw per the mount.
     *
     * Every mount point is reported in the guest's own view: after a chroot or
     * a pivot_root the table is otherwise unreadable to its own reader --
     * bubblewrap looks its sandbox mounts up here by the path it just got from
     * readlink(/proc/self/fd/N) -- and mounts outside the current root are
     * dropped, as the kernel drops what is unreachable in the namespace. */
    size_t np = sizeof pseudo / sizeof pseudo[0];
    int chrooted = m->chroot_base[0] && strcmp(m->chroot_base, "/");
    if (fmt == MNT_MOUNTINFO) {
        dprintf(fd, "1 1 %u:%u / / rw,relatime - %s /dev/root rw\n",
                maj, min, fstype);
        for (size_t i = 0; i < np; i++) {
            if (m->no_dev && !strncmp(pseudo[i].dir, "/dev", 4)) continue;
            if (chrooted) continue;   /* not reachable from the current root */
            dprintf(fd, "%zu 1 0:%zu / %s %s - %s %s %s\n",
                    i + 2, i + 5, pseudo[i].dir, pseudo[i].opts,
                    pseudo[i].type, pseudo[i].src, pseudo[i].sopts);
        }
        for (int i = 0, nb = bind_count(); i < nb; i++) {
            char bg[PATH_MAX], bh[PATH_MAX], bv[PATH_MAX]; int bro;
            if (!bind_get(i, bg, bh, &bro)) continue;   /* skip freed/mid-claim */
            if (!mnt_view(m, bg, bv)) continue;
            strcpy(bg, bv);
            struct stat bst;
            unsigned bmaj = maj, bmin = min;
            if (stat(bh, &bst) == 0) {
                bmaj = major(bst.st_dev);
                bmin = minor(bst.st_dev);
            }
            const char *o = bro ? "ro,relatime" : "rw,relatime";
            dprintf(fd, "%zu 1 %u:%u / %s %s - %s %s %s\n",
                    np + 2 + (size_t)i, bmaj, bmin, bg, o,
                    fstype, bh, bro ? "ro" : "rw");
        }
    } else if (fmt == MNT_MOUNTSTATS) {
        /* mountstats: a device line per mount (no NFS per-op stats, since these
         * are all local filesystems). */
        dprintf(fd, "device /dev/root mounted on / with fstype %s\n", fstype);
        for (size_t i = 0; i < np; i++) {
            if (m->no_dev && !strncmp(pseudo[i].dir, "/dev", 4)) continue;
            if (chrooted) continue;
            dprintf(fd, "device %s mounted on %s with fstype %s\n",
                    pseudo[i].src, pseudo[i].dir, pseudo[i].type);
        }
        for (int i = 0, nb = bind_count(); i < nb; i++) {
            char bg[PATH_MAX], bh[PATH_MAX], bv[PATH_MAX];
            if (!bind_get(i, bg, bh, NULL)) continue;
            if (!mnt_view(m, bg, bv)) continue;
            dprintf(fd, "device %s mounted on %s with fstype %s\n", bh, bv, fstype);
        }
    } else {
        dprintf(fd, "/dev/root / %s rw,relatime 0 0\n", fstype);
        for (size_t i = 0; i < np; i++) {
            if (m->no_dev && !strncmp(pseudo[i].dir, "/dev", 4)) continue;
            if (chrooted) continue;
            dprintf(fd, "%s %s %s %s 0 0\n", pseudo[i].src, pseudo[i].dir,
                    pseudo[i].type, pseudo[i].opts);
        }
        for (int i = 0, nb = bind_count(); i < nb; i++) {
            char bg[PATH_MAX], bh[PATH_MAX], bv[PATH_MAX]; int bro;
            if (!bind_get(i, bg, bh, &bro)) continue;
            if (!mnt_view(m, bg, bv)) continue;
            dprintf(fd, "%s %s %s %s 0 0\n", bh, bv,
                    fstype, bro ? "ro,relatime" : "rw,relatime");
        }
    }
}

/* Guest /proc/self/maps from the region list (which stores the guest path of
 * every file mapping for exactly this purpose). Region records keep their
 * creation prot; after mprotect the PTEs are the truth — the loader sets ELF
 * segment protections that way — so emit runs of equal page protection,
 * kernel-style. */
static void put_maps(int fd, struct Machine *m) {
    as_lock();
    AddrSpace *as = &m->as;
    for (int i = 0; i < as->nregions; i++) {
        const Region *r = &as->regions[i];
        /* Region paths are namespace-absolute guest paths; report them as the
         * guest sees them now (a sandbox that pivot_root'd would not recognize
         * its own mapped files otherwise). */
        char nameview[PATH_MAX];
        const char *name = r->path;
        if (name && name[0] == '/') {
            path_chroot_view(m, name, nameview);
            name = nameview;
        }
        if (!name) {
            if (r->start >= as->brk_start && r->start < as->brk)
                name = "[heap]";
            else if (r->start < as->stack_top && as->stack_top <= r->end)
                name = "[stack]";
        }
        u64 run = r->start;
        u32 prot = as_page_prot(as, run);
        for (u64 pg = r->start + GUEST_PAGE_SIZE; ; pg += GUEST_PAGE_SIZE) {
            u32 p = pg < r->end ? as_page_prot(as, pg) : ~0u;
            if (p != prot) {
                dprintf(fd, "%08llx-%08llx %c%c%c%c %08llx 00:00 0%s%s\n",
                        (unsigned long long)run, (unsigned long long)pg,
                        (prot & PTE_R) ? 'r' : '-',
                        (prot & PTE_W) ? 'w' : '-',
                        (prot & PTE_X) ? 'x' : '-',
                        r->shared ? 's' : 'p',
                        (unsigned long long)
                            (r->path ? r->file_off + (run - r->start) : 0),
                        name ? "                   " : "", name ? name : "");
                run = pg;
                prot = p;
            }
            if (pg >= r->end) break;
        }
    }
    as_unlock();
}

/* Load averages and thread count from sysinfo() — the same source the guest's
 * own sysinfo() is marshalled from, so the two views always agree. nr_running
 * and the last-allocated pid are unknowable without /proc/stat (which Android
 * also denies): claim 1 running (the reader is) and our own pid — put_stat's
 * procs_running/processes fabrications must agree with these. */
static void put_loadavg(int fd) {
    struct sysinfo si;
    unsigned long l[3] = { 0, 0, 0 };
    unsigned nproc = 1;
    if (sysinfo(&si) == 0) {
        for (int i = 0; i < 3; i++) l[i] = si.loads[i];
        nproc = si.procs ? si.procs : 1;
    }
    /* loads are fixed-point, scaled by 1 << SI_LOAD_SHIFT (65536) */
    dprintf(fd, "%lu.%02lu %lu.%02lu %lu.%02lu 1/%u %d\n",
            l[0] >> 16, (l[0] & 0xFFFF) * 100 / 65536,
            l[1] >> 16, (l[1] & 0xFFFF) * 100 / 65536,
            l[2] >> 16, (l[2] & 0xFFFF) * 100 / 65536,
            nproc, getpid());
}

/* Try-host-first gate for /proc/stat: 1 when the host denies the file
 * (Android SELinux) or A64_PROCSTAT_FORCE_SYNTH forces the fallback in
 * tests; probed once per process, netlink-style. */
static int stat_blocked(void) {
    static int blocked = -1;
    if (blocked < 0) {
        if (getenv("A64_PROCSTAT_FORCE_SYNTH")) {
            blocked = 1;
        } else {
            int fd = open("/proc/stat", O_RDONLY | O_CLOEXEC);
            blocked = fd < 0;
            if (fd >= 0) close(fd);
        }
    }
    return blocked;
}

/* Same try-host-first gate for /proc/sys/kernel/overflow{u,g}id, which Android
 * SELinux denies an app along with the rest of /proc/sys. A guest that cannot
 * read them is not a hypothetical: it is the first thing bubblewrap does, and
 * it dies outright ("Can't read /proc/sys/kernel/overflowuid"). Probed once per
 * file per process; A64_OVERFLOWID_FORCE_SYNTH forces the fallback in tests. */
static int overflowid_blocked(int is_gid) {
    static int blocked[2] = { -1, -1 };
    if (blocked[is_gid] < 0) {
        if (getenv("A64_OVERFLOWID_FORCE_SYNTH")) {
            blocked[is_gid] = 1;
        } else {
            int fd = open(is_gid ? "/proc/sys/kernel/overflowgid"
                                 : "/proc/sys/kernel/overflowuid",
                          O_RDONLY | O_CLOEXEC);
            blocked[is_gid] = fd < 0;
            if (fd >= 0) close(fd);
        }
    }
    return blocked[is_gid];
}

/* The id a file's owner is reported as when it does not fit the caller's view
 * of it (a 16-bit stat, an unmapped id in a user namespace). 65534 is the
 * kernel's compiled-in default for both sysctls, which is also what every
 * distro ships -- so it is the right answer when the real file is out of
 * reach, and the readable one passes through when it is not. */
static void put_overflowid(int fd) {
    dprintf(fd, "65534\n");
}

/* /proc/<pid>/limits from the guest's own table rather than the host's.
 *
 * The host file describes the emulator, and for the three limits that bound an
 * address space the emulator's are deliberately not the guest's (see struct
 * Machine rlim[]) -- so passing it through would have shown a guest a "Max
 * address space" nothing was enforcing and hidden the one that was. Column
 * layout and wording are the kernel's (fs/proc/base.c), because this is a file
 * people grep. */
static void put_limits(int fd, struct Machine *m) {
    static const struct { const char *name, *unit; } ln[G_RLIM_NLIMITS] = {
        [G_RLIMIT_CPU]        = { "Max cpu time",           "seconds"   },
        [G_RLIMIT_FSIZE]      = { "Max file size",          "bytes"     },
        [G_RLIMIT_DATA]       = { "Max data size",          "bytes"     },
        [G_RLIMIT_STACK]      = { "Max stack size",         "bytes"     },
        [G_RLIMIT_CORE]       = { "Max core file size",     "bytes"     },
        [G_RLIMIT_RSS]        = { "Max resident set",       "bytes"     },
        [G_RLIMIT_NPROC]      = { "Max processes",          "processes" },
        [G_RLIMIT_NOFILE]     = { "Max open files",         "files"     },
        [G_RLIMIT_MEMLOCK]    = { "Max locked memory",      "bytes"     },
        [G_RLIMIT_AS]         = { "Max address space",      "bytes"     },
        [G_RLIMIT_LOCKS]      = { "Max file locks",         "locks"     },
        [G_RLIMIT_SIGPENDING] = { "Max pending signals",    "signals"   },
        [G_RLIMIT_MSGQUEUE]   = { "Max msgqueue size",      "bytes"     },
        [G_RLIMIT_NICE]       = { "Max nice priority",      NULL        },
        [G_RLIMIT_RTPRIO]     = { "Max realtime priority",  NULL        },
        [G_RLIMIT_RTTIME]     = { "Max realtime timeout",   "us"        },
    };
    dprintf(fd, "%-25s %-20s %-20s %-10s\n",
            "Limit", "Soft Limit", "Hard Limit", "Units");
    for (int i = 0; i < G_RLIM_NLIMITS; i++) {
        char cur[24], max[24];
        if (m->rlim[i].rlim_cur == G_RLIM_INFINITY) strcpy(cur, "unlimited");
        else snprintf(cur, sizeof cur, "%llu",
                      (unsigned long long)m->rlim[i].rlim_cur);
        if (m->rlim[i].rlim_max == G_RLIM_INFINITY) strcpy(max, "unlimited");
        else snprintf(max, sizeof max, "%llu",
                      (unsigned long long)m->rlim[i].rlim_max);
        dprintf(fd, "%-25s %-20s %-20s ", ln[i].name, cur, max);
        if (ln[i].unit) dprintf(fd, "%-10s\n", ln[i].unit);
        else            dprintf(fd, "\n");
    }
}

static u64 stat_ncpu(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (u64)n : 1;
}

/* CPU-time estimate for the synthesized /proc/stat, in USER_HZ = 100
 * jiffies (matching the G_AT_CLKTCK auxv): the real split is unknowable
 * without the host file, so busy time is the integral of the sysinfo()
 * load average over wall time (seeded from the 15-minute average, advanced
 * by the 1-minute average, capped at ncpu) and idle is the remainder.
 * Increments are >= 0, so the counters are monotonic — what delta-computing
 * readers (top, vmstat) require. */
static void stat_estimate(struct Machine *m, u64 ncpu, u64 *busy_j, u64 *idle_j) {
    struct timespec ts = { 0, 0 };
    clock_gettime(CLOCK_BOOTTIME, &ts);
    u64 now = (u64)ts.tv_sec * 1000000000u + (u64)ts.tv_nsec;
    u64 up_j = (u64)ts.tv_sec * 100 + (u64)ts.tv_nsec / 10000000;
    u64 l1 = 0, l15 = 0;    /* <<16 fixed-point (SI_LOAD_SHIFT) */
    struct sysinfo si;
    if (sysinfo(&si) == 0) { l1 = si.loads[0]; l15 = si.loads[2]; }
    u64 cap = ncpu << 16;
    if (l1 > cap) l1 = cap;
    if (l15 > cap) l15 = cap;
    EMU_LOCK(&est_lock, EMU_LK_EST);
    if (!m->stat_last_ns)
        m->stat_busy = up_j * l15 >> 16;
    else if (now > m->stat_last_ns)
        m->stat_busy += (now - m->stat_last_ns) / 10000000 * l1 >> 16;
    m->stat_last_ns = now;
    u64 busy = m->stat_busy;
    EMU_UNLOCK(&est_lock, EMU_LK_EST);
    u64 total = up_j * ncpu;
    if (busy > total) busy = total;
    *busy_j = busy;
    *idle_j = total - busy;
}

/* Idle jiffies summed across CPUs (field 4 of the host /proc/stat aggregate
 * line); 0 when the file is unreadable or synthesis is forced — then the
 * caller falls back to stat_estimate, so uptime and the synthesized stat
 * report the same idle time. */
static int host_stat_idle(u64 *idle_j) {
    if (stat_blocked()) return 0;
    int fd = open("/proc/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    unsigned long long u, ni, sy, id;
    if (sscanf(buf, "cpu %llu %llu %llu %llu", &u, &ni, &sy, &id) != 4)
        return 0;
    *idle_j = id;
    return 1;
}

/* Uptime with sub-second precision from CLOCK_BOOTTIME (counts suspend, like
 * the real file). The idle field is the sum across CPUs from /proc/stat:
 * the host's when readable, else the same estimate the synthesized
 * /proc/stat reports (so the two files agree). */
static void put_uptime(int fd, struct Machine *m) {
    struct timespec ts = { 0, 0 };
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
        struct sysinfo si;
        if (sysinfo(&si) == 0) ts.tv_sec = si.uptime;
    }
    u64 busy_j, idle_j;
    if (!host_stat_idle(&idle_j))
        stat_estimate(m, stat_ncpu(), &busy_j, &idle_j);
    dprintf(fd, "%lld.%02ld %llu.%02llu\n",
            (long long)ts.tv_sec, ts.tv_nsec / 10000000,
            (unsigned long long)(idle_j / 100),
            (unsigned long long)(idle_j % 100));
}

static void put_version(int fd) {
    dprintf(fd, "Linux version %s (arm64chroot) (arm64chroot) %s\n",
            GUEST_KREL, GUEST_KVER);
}

/* The guest /proc/stat where the host's is unreadable (see stat_blocked).
 * CPU time comes from stat_estimate, all attributed to user; intr and ctxt
 * are honest zeros; btime is exact (wall clock now minus CLOCK_BOOTTIME);
 * processes/procs_running match put_loadavg's own-pid/1 fabrications. */
static void put_stat(int fd, struct Machine *m) {
    u64 ncpu = stat_ncpu(), busy_j, idle_j;
    stat_estimate(m, ncpu, &busy_j, &idle_j);
    dprintf(fd, "cpu  %llu 0 0 %llu 0 0 0 0 0 0\n",
            (unsigned long long)busy_j, (unsigned long long)idle_j);
    for (u64 i = 0; i < ncpu; i++)
        dprintf(fd, "cpu%llu %llu 0 0 %llu 0 0 0 0 0 0\n",
                (unsigned long long)i,
                (unsigned long long)(busy_j / ncpu),
                (unsigned long long)(idle_j / ncpu));
    struct timespec ts = { 0, 0 };
    clock_gettime(CLOCK_BOOTTIME, &ts);
    dprintf(fd, "intr 0\nctxt 0\nbtime %lld\nprocesses %d\n"
                "procs_running 1\nprocs_blocked 0\n"
                "softirq 0 0 0 0 0 0 0 0 0 0 0\n",
            (long long)(time(NULL) - ts.tv_sec), getpid());
}

/* ---- id maps of a faked user namespace ----
 *
 * A guest that thinks it unshared CLONE_NEWUSER writes uid_map, gid_map and
 * setgroups exactly once and expects the values back; the host files describe
 * the *initial* namespace, whose map is fixed, so a real write is refused
 * (bubblewrap dies with "setting up uid map"). These three are therefore
 * synthesized whenever the namespace was faked, and pass through untouched
 * otherwise -- outside the fiction the host file is the truthful answer. The
 * recorded maps are reported, not applied: they change no id the guest sees
 * (that is what --fake-id does).
 *
 * Both spellings are served, because both are used: /proc/self/... by a guest
 * that maps its own ids, and /proc/<child>/... by a parent doing it on the
 * child's behalf -- the usual arrangement, since a process that just unshared
 * generally has no privilege to map anything itself. Cross-process means the
 * maps cannot live in the writer's Machine, so they live in the shared PID
 * registry (proctab.c) and Machine only backs the case where the registry has
 * no answer: no slot for the pid, or a table that degraded off entirely. */

/* Registry-side name for a PF_* id-map kind. */
static int pt_idmap_kind(int kind) {
    return kind == PF_UIDMAP ? PT_IDMAP_UID :
           kind == PF_GIDMAP ? PT_IDMAP_GID : PT_IDMAP_SG;
}

/* `pid` is the process whose namespace this is: 0 means our own.
 *
 * Whichever side holds a value wins, rather than the registry unconditionally.
 * The two only ever disagree by one being empty -- a namespace the registry
 * never got a slot for lives in Machine alone, and maps written for us by
 * somebody else reach the registry alone -- so preferring the side that has an
 * answer is what makes a degraded registry cost nothing. */
static void put_idmap(int fd, struct Machine *m, int kind, s32 pid) {
    if (!pid) pid = (s32)getpid();
    int self = pid == (s32)getpid();
    char buf[IDMAP_MAX];
    u32 len = 0;
    int reg = proctab_idmap_read(pid, pt_idmap_kind(kind), buf, sizeof buf, &len);
    if (!reg && !self) return;          /* only we can answer from Machine */
    if (kind == PF_SETGROUPS) {
        /* "deny" is a one-way latch, so either side holding it decides. */
        int deny = (reg && len >= 4 && !memcmp(buf, "deny", 4)) ||
                   (self && m->setgroups_deny);
        const char *s = deny ? "deny\n" : "allow\n";
        ssize_t w = write(fd, s, strlen(s));
        (void)w;
        return;
    }
    if (reg && len) { ssize_t w = write(fd, buf, len); (void)w; return; }
    const char *s = kind == PF_UIDMAP ? m->uid_map : m->gid_map;
    if (*s) { ssize_t w = write(fd, s, strlen(s)); (void)w; }
}

/* A fork child taking over its parent's user namespace. Maps written *for* the
 * parent reached its registry record and nothing else -- a Machine is private,
 * so whoever wrote them had nowhere else to put them -- which leaves the copy
 * this child inherits empty. Pull them across at fork, so the Machine side is
 * complete: it is the whole answer for a child the registry could find no slot
 * for, and the registry's own copy of them is seeded separately (into the slot
 * reserved for this child before the fork, see proctab.c). */
void procfs_idmap_inherit(struct Machine *m, s32 from) {
    char buf[IDMAP_MAX];
    u32 len = 0;
    if (!m->uid_map_set && proctab_idmap_read(from, PT_IDMAP_UID, buf, sizeof buf, &len) && len) {
        if (len >= IDMAP_MAX) len = IDMAP_MAX - 1;
        memcpy(m->uid_map, buf, len);
        m->uid_map[len] = 0;
        m->uid_map_set = 1;
    }
    if (!m->gid_map_set && proctab_idmap_read(from, PT_IDMAP_GID, buf, sizeof buf, &len) && len) {
        if (len >= IDMAP_MAX) len = IDMAP_MAX - 1;
        memcpy(m->gid_map, buf, len);
        m->gid_map[len] = 0;
        m->gid_map_set = 1;
    }
    if (proctab_idmap_read(from, PT_IDMAP_SG, buf, sizeof buf, &len) &&
        len >= 4 && !memcmp(buf, "deny", 4)) {
        m->setgroups_deny = 1;   /* a one-way latch: only ever pulled forward */
        m->setgroups_set = 1;
    }
}

/* Parse one written map into the kernel's read-back form ("%10u %10u %10u\n"
 * per extent). Returns 0, or -errno for what the kernel would reject. */
static int idmap_format(const char *in, size_t len, char *out, size_t outsz) {
    size_t o = 0;
    int lines = 0;
    for (size_t i = 0; i < len; ) {
        while (i < len && (in[i] == ' ' || in[i] == '\t' || in[i] == '\n')) i++;
        if (i >= len) break;
        unsigned long v[3];
        for (int f = 0; f < 3; f++) {
            if (i >= len || in[i] < '0' || in[i] > '9') return -EINVAL;
            unsigned long n = 0;
            while (i < len && in[i] >= '0' && in[i] <= '9') {
                n = n * 10 + (unsigned long)(in[i++] - '0');
                if (n > 0xffffffffUL) return -EINVAL;
            }
            v[f] = n;
            while (i < len && (in[i] == ' ' || in[i] == '\t')) i++;
        }
        if (i < len && in[i] != '\n') return -EINVAL;
        if (v[2] == 0) return -EINVAL;       /* zero-length extent */
        if (o + 34 > outsz) return -EINVAL;  /* more extents than we hold */
        o += (size_t)snprintf(out + o, outsz - o, "%10lu %10lu %10lu\n",
                              v[0], v[1], v[2]);
        lines++;
    }
    return lines ? 0 : -EINVAL;   /* an empty map is EINVAL, as in the kernel */
}

/* write(2) landing on one of the three files. Enforces the kernel's one-shot
 * rules; returns 1 with *ret set (byte count or -errno) when it consumed the
 * write, 0 to let an ordinary fd take it. `off` is the explicit pwrite-family
 * offset or -1 for the fd's own position: the kernel only accepts a map write
 * at offset 0, and a write that landed in the backing memfd instead would be a
 * silent lie (unformatted on read-back, and the one-shot rule unapplied). */
int procfs_pre_write(CPU *c, int fd, const u8 *buf, size_t len, s64 off, s64 *ret) {
    struct Machine *m = c->m;
    if (!m->pf_fds_count) return 0;   /* unlocked fast path; benign race */
    EMU_LOCK(&pf_lock, EMU_LK_PF);
    int i;
    for (i = 0; i < m->pf_fds_count; i++)
        if (m->pf_fds[i].fd == fd) break;
    if (i == m->pf_fds_count) { EMU_UNLOCK(&pf_lock, EMU_LK_PF); return 0; }
    struct stat st;
    if (fstat(fd, &st) != 0 || (u64)st.st_ino != m->pf_fds[i].ino) {
        m->pf_fds[i] = m->pf_fds[--m->pf_fds_count];   /* stale: fd reused */
        EMU_UNLOCK(&pf_lock, EMU_LK_PF);
        return 0;
    }
    int kind = m->pf_fds[i].kind;
    s32 tpid = m->pf_fds[i].pid ? m->pf_fds[i].pid : (s32)getpid();
    EMU_UNLOCK(&pf_lock, EMU_LK_PF);
    if (kind != PF_UIDMAP && kind != PF_GIDMAP && kind != PF_SETGROUPS) return 0;
    if (off < 0) off = lseek(fd, 0, SEEK_CUR);
    if (off != 0) { *ret = -EINVAL; return 1; }
    /* Whose namespace this is decides where the state lives: the registry holds
     * a faked one (that is what lets a parent write its child's maps), Machine
     * only ever answers for us. The two are consulted together, for the reason
     * put_idmap explains. A target the registry has forgotten, and that is not
     * us, is a process that is gone. */
    int self = tpid == (s32)getpid(), err = 0;
    int reg = proctab_userns(tpid);
    if (!reg && !self) { *ret = -ESRCH; return 1; }

    if (kind == PF_SETGROUPS) {
        /* "allow" or "deny", and only until gid_map is set -- afterwards the
         * kernel refuses, since the decision has already been used. Nor may
         * "deny" be taken back. */
        int deny;
        if (len >= 4 && !memcmp(buf, "deny", 4))       deny = 1;
        else if (len >= 5 && !memcmp(buf, "allow", 5)) deny = 0;
        else { *ret = -EINVAL; return 1; }
        if (self && (m->gid_map_set || (m->setgroups_deny && !deny))) {
            *ret = -EPERM;
            return 1;
        }
        if (reg && proctab_idmap_write(tpid, PT_IDMAP_SG, deny ? "deny\n" : "allow\n",
                                       deny ? 5 : 6, &err)) {
            /* Mirror our own writes into Machine so the fallback never
             * contradicts the registry if the slot later goes away. */
            if (!err && self) { m->setgroups_deny = (u8)deny; m->setgroups_set = 1; }
            *ret = err ? err : (s64)len;
            return 1;
        }
        if (!self) { *ret = -ESRCH; return 1; }
        m->setgroups_deny = (u8)deny;
        m->setgroups_set = 1;
        *ret = (s64)len;
        return 1;
    }
    /* One shot per map, tested before anything is parsed -- the kernel's order,
     * so a second write is EPERM whatever it holds rather than EINVAL. The
     * registry's own claim is what actually enforces it; this only gets the
     * errno right for the ordinary sequential case. */
    int written = self && (kind == PF_UIDMAP ? m->uid_map_set : m->gid_map_set);
    if (reg && !written) {
        char cur[IDMAP_MAX];
        u32 curlen = 0;
        proctab_idmap_read(tpid, pt_idmap_kind(kind), cur, sizeof cur, &curlen);
        written = curlen != 0;
    }
    if (written) { *ret = -EPERM; return 1; }
    char fmt[IDMAP_MAX];
    fmt[0] = 0;
    int r = idmap_format((const char *)buf, len, fmt, sizeof fmt);
    if (r < 0) { *ret = r; return 1; }
    if (reg && proctab_idmap_write(tpid, pt_idmap_kind(kind), fmt,
                                   (u32)strlen(fmt), &err)) {
        if (!err && self) {
            if (kind == PF_UIDMAP) { memcpy(m->uid_map, fmt, sizeof fmt); m->uid_map_set = 1; }
            else                   { memcpy(m->gid_map, fmt, sizeof fmt); m->gid_map_set = 1; }
        }
        *ret = err ? err : (s64)len;
        return 1;
    }
    if (!self) { *ret = -ESRCH; return 1; }
    if (kind == PF_UIDMAP) { memcpy(m->uid_map, fmt, sizeof fmt); m->uid_map_set = 1; }
    else                   { memcpy(m->gid_map, fmt, sizeof fmt); m->gid_map_set = 1; }
    *ret = (s64)len;
    return 1;
}

/* Track an open fd of a time-varying file for refresh-on-rewind. The memfd
 * inode is recorded so a stale entry (fd number reused after a close this
 * table missed: dup2-onto, execve's CLOEXEC sweep) is detected and dropped
 * instead of clobbering an innocent file. Table full: the fd just keeps its
 * open-time snapshot. */
static void pf_track(struct Machine *m, int fd, int kind, s32 pid, int self) {
    struct stat st;
    if (fstat(fd, &st) != 0) return;
    u64 ino = (u64)st.st_ino;
    EMU_LOCK(&pf_lock, EMU_LK_PF);
    if (m->pf_fds_count < PF_MAX_FDS) {
        m->pf_fds[m->pf_fds_count].fd = fd;
        m->pf_fds[m->pf_fds_count].kind = (u8)kind;
        m->pf_fds[m->pf_fds_count].self = (u8)self;
        m->pf_fds[m->pf_fds_count].pid = pid;
        m->pf_fds[m->pf_fds_count].ino = ino;
        m->pf_fds_count++;
    }
    EMU_UNLOCK(&pf_lock, EMU_LK_PF);
}

void procfs_unmark_fd(struct Machine *m, int fd) {
    if (!m->pf_fds_count) return;
    EMU_LOCK(&pf_lock, EMU_LK_PF);
    for (int i = 0; i < m->pf_fds_count; i++)
        if (m->pf_fds[i].fd == fd) {
            m->pf_fds[i] = m->pf_fds[--m->pf_fds_count];
            break;
        }
    EMU_UNLOCK(&pf_lock, EMU_LK_PF);
}

void procfs_pre_read(CPU *c, int fd, s64 off) {
    struct Machine *m = c->m;
    if (!m->pf_fds_count) return;   /* unlocked fast path; benign race */
    EMU_LOCK(&pf_lock, EMU_LK_PF);
    int i;
    for (i = 0; i < m->pf_fds_count; i++)
        if (m->pf_fds[i].fd == fd) break;
    if (i == m->pf_fds_count) goto out;
    struct stat st;
    if (fstat(fd, &st) != 0 || (u64)st.st_ino != m->pf_fds[i].ino) {
        m->pf_fds[i] = m->pf_fds[--m->pf_fds_count];   /* stale: fd reused */
        goto out;
    }
    if (off < 0) off = lseek(fd, 0, SEEK_CUR);
    if (off != 0) goto out;   /* mid-file: keep the current snapshot */
    if (ftruncate(fd, 0) != 0) goto out;   /* memfd: cannot fail in practice */
    lseek(fd, 0, SEEK_SET);
    switch (m->pf_fds[i].kind) {
    case PF_LOADAVG: put_loadavg(fd);   break;
    case PF_UPTIME:  put_uptime(fd, m); break;
    case PF_STAT:    put_stat(fd, m);   break;
    case PF_LIMITS:  put_limits(fd, m); break;   /* setrlimit since the open */
    /* Re-read after a write must show what was written -- by us or, for a
     * child's namespace, by whoever set it up. */
    case PF_UIDMAP: case PF_GIDMAP: case PF_SETGROUPS:
        put_idmap(fd, m, m->pf_fds[i].kind, m->pf_fds[i].pid);
        break;
    /* The rewritten lines (TracerPid, Seccomp, the signal masks) change over a
     * process's life, so a re-read must go back to the host file. The tid the
     * open resolved names it directly -- /proc/<tid> works for a non-leader
     * thread too -- so no spelling of the original path has to be kept. */
    case PF_STATUS: {
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/status", (int)m->pf_fds[i].pid);
        if (put_status(fd, m, path, m->pf_fds[i].self, NULL) < 0)
            m->pf_fds[i] = m->pf_fds[--m->pf_fds_count];   /* process is gone */
        break;
    }
    }
    lseek(fd, 0, SEEK_SET);
out:
    EMU_UNLOCK(&pf_lock, EMU_LK_PF);
}

/* Anonymous backing for a synthesized /proc view. a64_anonfd falls back to an
 * unlinked temp file on hosts whose kernel predates memfd_create (< 3.17 —
 * Android 7): without that, every synthesized open here silently fell through
 * to the HOST file, and a guest read the emulator's own Uid lines, mount
 * table and environment. */
static int synth_memfd(void) { return a64_anonfd("proc-synth"); }

/* Which spelling of "status" canon names, if any: PS_SELF for this process
 * (self / own-pid / thread-self / one of our own threads' task dirs), PS_OTHER
 * for another guest process. A hidden (non-guest) pid returns PS_NONE so the
 * path layer's ENOENT stands and no foreign process's status can leak -- the
 * same visibility rule the other-pid handlers rely on. */
enum { PS_NONE = 0, PS_SELF, PS_OTHER };
static int status_target(const char *canon) {
    const char *t = self_tail(canon);
    if (t) return !strcmp(t, "status") ? PS_SELF : PS_NONE;
    s32 pid;
    t = proc_other_tail(canon, &pid);
    return (t && !strcmp(t, "status") && proctab_has(pid)) ? PS_OTHER : PS_NONE;
}

/* Does this status line carry exactly this key? ("Seccomp" must not match
 * "Seccomp_filters:", so the colon is part of the test.) */
static int is_key(const char *line, const char *key) {
    size_t n = strlen(key);
    return !strncmp(line, key, n) && line[n] == ':';
}

#define STATUS_MAX 16384   /* a status file is ~2 KB; Groups: is the long line */

/* Guest view of /proc/<pid>/status: pass the host file through, rewriting the
 * lines that describe the EMULATOR rather than the guest and dropping the ones
 * that describe the host's architecture. Everything else -- State, PPid,
 * FDSize, the Vm* sizes, Threads, the context-switch counters -- is a real
 * property of the process being asked about and stands as it is.
 *
 * What has to be rewritten, and why the host file cannot answer it:
 *   TracerPid  the emulated ptrace never host-attaches (ptracetab.c), so the
 *              host task has no tracer to report even while a guest gdb has it
 *              stopped -- and a real one would name a host pid regardless.
 *   Seccomp    a guest filter is evaluated here and never installed on the
 *              host (sys_seccomp.c), so a filtered guest reads 0; and where the
 *              emulator itself runs under a filter the guest never asked for
 *              (Android, `make test-seccomp`), an unfiltered guest reads 2.
 *   Sig*       the capture layer's dispositions and mask, not the guest's: it
 *              installs host handlers by its own rules and blocks/unblocks
 *              around delivery.
 *   NoNewPrivs the recorded guest intent, for the same reason PR_GET_NO_NEW_
 *              PRIVS is answered from it: an inherited host flag (the Android
 *              zygote sets one) is not something the guest asked for.
 *   Uid/Gid    the real invoking ids, which --fake-id exists to hide; ps and
 *              top read these lines to name the owner.
 *   Cap*       under fake-root, capget(2) already answers with a full set
 *              (sys_misc.c), so leaving zeros here contradicts the emulator's
 *              own syscall. CapBnd is the host kernel's full set and is what
 *              the rewritten CapPrm/CapEff report; CapInh/CapAmb stay empty,
 *              matching capget's inheritable set.
 *   x86_*      an arch hook of the host kernel. An aarch64 kernel prints no
 *              such line, so its presence is a bare host-arch fingerprint in
 *              a file the guest reads about itself.
 *
 * `self` says the file describes this Machine, the only place the guest's exact
 * signal state and credentials exist. For another guest process we rewrite what
 * the shared tables can answer -- TracerPid from the ptrace link registry,
 * Seccomp from the PID registry -- and leave the host's approximation of the
 * rest standing, the same split every other cross-process /proc file here
 * makes: its blocked set would have to be republished on every sigprocmask and
 * every delivery to be worth reading, and being per-thread it does not belong
 * in a per-process record anyway.
 *
 * That per-thread part also decides which mask the self case reports: the
 * *calling* thread's, since that is the one this emulator process can see. It
 * is exact for /proc/self/status in a single-threaded guest, for thread-self,
 * and for a thread's own task/<tid>; a thread reading a sibling's task dir gets
 * its own instead of the sibling's -- still the guest's mask rather than the
 * capture layer's, which is the choice being made everywhere here.
 *
 * `canon` is the passthrough host path. *tid_out gets the thread this file
 * describes, so a refresh can name it directly whichever spelling was opened.
 * Returns 0, or -1 if the host file can't be read (the caller then falls back
 * to plain passthrough). */
static int put_status(int fd, struct Machine *m, const char *canon, int self,
                      s32 *tid_out) {
    int hfd = open(canon, O_RDONLY | O_CLOEXEC);
    if (hfd < 0) return -1;
    char *buf = malloc(STATUS_MAX);
    if (!buf) { close(hfd); return -1; }
    size_t n = 0;
    for (;;) {
        ssize_t r = read(hfd, buf + n, STATUS_MAX - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (n >= STATUS_MAX - 1) break;
    }
    close(hfd);
    /* Empty, or bigger than the buffer -- a rewrite of half a file would be
     * worse than the host's own answer, so hand the caller back to it. (Only
     * Groups: can grow without bound, and only towards NGROUPS_MAX.) */
    if (!n || n >= STATUS_MAX - 1) { free(buf); return -1; }
    buf[n] = 0;

    /* Pass 1 for the two values a rewrite needs but does not carry: the tid
     * (Pid: names the thread the file describes, so it is right for every
     * spelling of the path) and the host kernel's own full capability set. */
    s32 tid = 0, tgid = 0;
    char capfull[48] = "";
    for (char *p = buf; *p; ) {
        char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (is_key(p, "Pid")) tid = (s32)strtol(p + 4, NULL, 10);
        else if (is_key(p, "Tgid")) tgid = (s32)strtol(p + 5, NULL, 10);
        else if (is_key(p, "CapBnd")) {
            const char *v = p + 7;
            while (*v == ' ' || *v == '\t') v++;
            size_t vl = len - (size_t)(v - p);
            if (vl && vl < sizeof capfull) { memcpy(capfull, v, vl); capfull[vl] = 0; }
        }
        if (!nl) break;
        p = nl + 1;
    }
    if (tid_out) *tid_out = tid;

    /* Guest signal state. The kernel's mask spelling puts signal N in bit N-1,
     * which is the guest sigset layout too, so these transfer as they are. */
    u64 blk = 0, ign = 0, cgt = 0, pnd = 0;
    if (self) {
        blk = g_tls.sigmask;
        /* Our capture ring is per-thread, so everything queued is private to
         * this thread and the process-wide (shared) pending set is empty. */
        pnd = sig_pending_set();
        for (int s = 1; s <= 64; s++) {
            u64 h = m->sigact[s].handler;
            if (h == 1) ign |= 1ull << (s - 1);          /* SIG_IGN */
            else if (h) cgt |= 1ull << (s - 1);          /* a guest handler */
        }
    }
    u8 scmode = 0;
    u32 scfilters = 0;
    int scknown;
    if (self) { scmode = (u8)seccomp_status(m, &scfilters); scknown = 1; }
    else scknown = proctab_seccomp_get(tid, &scmode, &scfilters);
    int fakeroot = self && m->fake_id && m->cred.euid == 0 && capfull[0];
    /* Threads: counts host tasks, and a host task in this process's thread
     * group need not be a guest thread -- an interposer between us and the
     * kernel can hold one (proc_foreign_sample). The guest is told what it has,
     * which is the same number its /proc/<pid>/task listing is filtered down to
     * (sys_file.c). Zero on every host we ship on, where the line stands. */
    s32 ftmp[PROCTAB_FOREIGN];
    int nforeign = tgid > 0 ? proc_foreign_tasks(tgid, ftmp, PROCTAB_FOREIGN) : 0;

    /* A host kernel older than a key is a host file without its line:
     * NoNewPrivs is 4.10, Seccomp 3.8, Seccomp_filters 5.9. The guest ABI
     * (uname says a modern kernel) promises all three, and a fixture that
     * greps for one reads its absence as 0 -- so lines the loop below never
     * saw are appended after it. Appended rather than spliced into the
     * kernel's exact position: every reader keys on the line name. */
    int saw_nnp = 0, saw_sec = 0, saw_scflt = 0;

    for (char *p = buf; *p; ) {
        char *nl = strchr(p, '\n');
        char *next = nl ? nl + 1 : NULL;
        if (nl) *nl = 0;               /* one NUL-terminated line at a time */

        if (is_key(p, "NoNewPrivs")) saw_nnp = 1;
        else if (is_key(p, "Seccomp_filters")) saw_scflt = 1;
        else if (is_key(p, "Seccomp")) saw_sec = 1;

        if (!strncmp(p, "x86_", 4)) goto next_line;

        if (is_key(p, "TracerPid")) {
            dprintf(fd, "TracerPid:\t%d\n", (int)ptrace_tracer_of(tid));
            goto next_line;
        }
        if (nforeign && is_key(p, "Threads")) {
            int t = (int)strtol(p + 8, NULL, 10) - nforeign;
            dprintf(fd, "Threads:\t%d\n", t > 0 ? t : 1);
            goto next_line;
        }
        if (scknown && is_key(p, "Seccomp")) {
            dprintf(fd, "Seccomp:\t%u\n", scmode);
            goto next_line;
        }
        if (scknown && is_key(p, "Seccomp_filters")) {
            dprintf(fd, "Seccomp_filters:\t%u\n", scfilters);
            goto next_line;
        }
        if (self) {
            if (is_key(p, "SigPnd")) { dprintf(fd, "SigPnd:\t%016llx\n", (unsigned long long)pnd); goto next_line; }
            if (is_key(p, "ShdPnd")) { dprintf(fd, "ShdPnd:\t%016llx\n", 0ULL); goto next_line; }
            if (is_key(p, "SigBlk")) { dprintf(fd, "SigBlk:\t%016llx\n", (unsigned long long)blk); goto next_line; }
            if (is_key(p, "SigIgn")) { dprintf(fd, "SigIgn:\t%016llx\n", (unsigned long long)ign); goto next_line; }
            if (is_key(p, "SigCgt")) { dprintf(fd, "SigCgt:\t%016llx\n", (unsigned long long)cgt); goto next_line; }
            if (is_key(p, "NoNewPrivs")) { dprintf(fd, "NoNewPrivs:\t%d\n", m->no_new_privs ? 1 : 0); goto next_line; }
        }
        if (fakeroot) {
            if (is_key(p, "CapPrm")) { dprintf(fd, "CapPrm:\t%s\n", capfull); goto next_line; }
            if (is_key(p, "CapEff")) { dprintf(fd, "CapEff:\t%s\n", capfull); goto next_line; }
        }
        if (m->fake_id && (is_key(p, "Uid") || is_key(p, "Gid"))) {
            int is_uid = p[0] == 'U';
            u32 id[4];   /* real, effective, saved-set, filesystem */
            if (sscanf(p + 4, "%u %u %u %u",
                       &id[0], &id[1], &id[2], &id[3]) == 4) {
                for (int i = 0; i < 4; i++)
                    id[i] = is_uid ? remap_uid(m, id[i]) : remap_gid(m, id[i]);
                dprintf(fd, "%s\t%u\t%u\t%u\t%u\n", is_uid ? "Uid:" : "Gid:",
                        id[0], id[1], id[2], id[3]);
                goto next_line;
            }
        }
        if (m->fake_id && is_key(p, "Groups")) {
            /* The kernel's spelling is "Groups:\t" and then "%u " per group,
             * trailing space and all; readers that split on it notice. */
            dprintf(fd, "Groups:\t");
            const char *g = p + 7;
            u32 gid; int adv;
            while (sscanf(g, " %u%n", &gid, &adv) == 1) {
                dprintf(fd, "%u ", remap_gid(m, gid));
                g += adv;
            }
            dprintf(fd, "\n");
            goto next_line;
        }
        {
            ssize_t w = write(fd, p, strlen(p)); (void)w;
            if (nl) { w = write(fd, "\n", 1); (void)w; }
        }
    next_line:
        if (!next) break;
        p = next;
    }
    if (self && !saw_nnp)
        dprintf(fd, "NoNewPrivs:\t%d\n", m->no_new_privs ? 1 : 0);
    if (scknown && !saw_sec) dprintf(fd, "Seccomp:\t%u\n", scmode);
    if (scknown && !saw_scflt) dprintf(fd, "Seccomp_filters:\t%u\n", scfilters);
    free(buf);
    return 0;
}

/* "/proc/<N>/cmdline" (or that process's own task/<tid>/cmdline, the same
 * file) -> *pid = N, returns 1; else 0. */
static int proc_other_cmdline(const char *canon, s32 *pid) {
    const char *t = proc_other_tail(canon, pid);
    return t && !strcmp(t, "cmdline");
}

/* Per-process address-space files. Nothing in the registry can synthesize
 * these, and the host's answer describes the *emulator* -- its own mappings, at
 * its own foreign-ISA addresses, naming its binary and its libraries -- so for
 * another guest process they are refused rather than passed through. EACCES is
 * the shape of refusal a host already gives here: reading them needs
 * PTRACE_MODE_READ, which yama's ptrace_scope=1 denies between siblings. */
static int proc_addrspace_leaf(const char *t) {
    static const char *n[] = {
        "maps", "smaps", "smaps_rollup", "numa_maps", "pagemap",
        "stack", "mem", "clear_refs", "syscall",
    };
    for (size_t i = 0; i < sizeof n / sizeof n[0]; i++)
        if (!strcmp(t, n[i])) return 1;
    return 0;
}

/* If canon names a synthesized /proc file, open the guest view: returns 1 and
 * sets *ret to a host fd or -errno; returns 0 to fall through to the host. */
int procfs_open(CPU *c, const char *canon, int gflags, s64 *ret) {
    struct Machine *m = c->m;
    int kind;

    if (m->no_proc) return 0;   /* --no-proc: no synthesized /proc files */

    /* /proc/<pid>/cmdline of ANOTHER guest process: served from the shared PID
     * registry (self / own-pid keep using m->cmdline via self_tail below). A
     * non-guest PID is not answered here at all -- path.c has already routed it
     * to the hidden view's ENOENT. For one that IS a guest process the answer
     * comes from here whatever the registry says: a lookup that comes up dry
     * (the entry is mid-rewrite, or its process raced away) writes an empty
     * file, as the kernel does for a process whose cmdline is gone. Falling
     * through instead handed the guest the host file -- the emulator's own
     * command line. */
    s32 opid;
    if (proc_other_cmdline(canon, &opid) && opid != (s32)getpid()) {
        if (!proctab_has(opid)) return 0;
        char cbuf[PROCTAB_CMDLINE];
        u32 clen = 0;
        if (!proctab_cmdline(opid, cbuf, &clen)) clen = 0;
        if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
        if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }
        int fd = synth_memfd();
        if (fd < 0) { *ret = -ENOENT; return 1; }   /* deny, never the host file */
        if (clen) { ssize_t w = write(fd, cbuf, clen); (void)w; }
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        *ret = fd;
        return 1;
    }

    /* /proc/<pid>/{mounts,mountinfo,mountstats} of ANOTHER guest process: the
     * guest mount table is process-independent (this session's rootfs + binds),
     * so serve it from this Machine instead of leaking the host's real mount
     * namespace (self / own-pid go through self_tail below). A non-guest PID
     * misses proctab_has and falls through to the host path's ENOENT. */
    s32 mpid;
    const char *mtail = proc_other_tail(canon, &mpid);
    if (mtail && mpid != (s32)getpid() &&
        (!strcmp(mtail, "mounts") || !strcmp(mtail, "mountinfo") ||
         !strcmp(mtail, "mountstats"))) {
        if (!proctab_has(mpid)) return 0;
        if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
        if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }
        int fd = synth_memfd();
        if (fd < 0) { *ret = -ENOENT; return 1; }   /* deny, never the host file */
        int fmt = !strcmp(mtail, "mountinfo")  ? MNT_MOUNTINFO :
                  !strcmp(mtail, "mountstats") ? MNT_MOUNTSTATS : MNT_MOUNTS;
        put_mounts(fd, m, fmt);
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        *ret = fd;
        return 1;
    }

    /* /proc/<pid>/{environ,auxv} of ANOTHER guest process: served from the guest
     * environ/auxv that process published in the registry (self / own-pid use
     * m->environ / m->auxv via self_tail below). As with cmdline above, a
     * non-guest PID is left to path.c's ENOENT and a guest one is answered from
     * here either way -- a dry lookup is an empty file, never the emulator's
     * own copy. That copy is the whole host environment, and for auxv it is the
     * wrong ISA besides (gdb reads the inferior's AT_HWCAP and goes chasing
     * pauth/SVE regsets the ptrace shim does not have). */
    s32 epid;
    const char *etail = proc_other_tail(canon, &epid);
    if (etail && epid != (s32)getpid() &&
        (!strcmp(etail, "environ") || !strcmp(etail, "auxv"))) {
        if (!proctab_has(epid)) return 0;
        if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
        if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }
        struct ProcSnap snap;
        const char *buf = NULL;
        u32 blen = 0;
        if (proctab_get(epid, &snap)) {
            buf = etail[0] == 'a' ? snap.auxv : snap.env;
            blen = etail[0] == 'a' ? snap.auxv_len : snap.env_len;
        }
        int fd = synth_memfd();
        if (fd < 0) { *ret = -ENOENT; return 1; }   /* deny, never the host file */
        if (blen) { ssize_t w = write(fd, buf, blen); (void)w; }
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        *ret = fd;
        return 1;
    }

    /* Address-space files of ANOTHER guest process: refused, never passed
     * through (see proc_addrspace_leaf). Only for a pid we admit exists -- a
     * non-guest one keeps path.c's ENOENT, so this cannot be used to probe
     * which host pids are real. */
    s32 apid;
    const char *atail = proc_other_tail(canon, &apid);
    if (atail && apid != (s32)getpid() && proc_addrspace_leaf(atail) &&
        proctab_has(apid)) {
        *ret = -EACCES;
        return 1;
    }

    /* /proc/<pid>/{uid_map,gid_map,setgroups} of ANOTHER guest process. This is
     * how a user namespace is normally set up: the child unshares and waits,
     * the PARENT writes its maps -- a process that just unshared has no
     * privilege to map ids into the namespace it came from. Left to the host
     * these writes are refused (they name the initial namespace, whose map is
     * fixed), which is exactly the failure the self spelling was synthesized to
     * avoid. Answered for a process whose faked namespace the registry knows
     * about; for anything else the host file, describing the real initial
     * namespace, remains the truthful answer. */
    s32 upid;
    const char *utail = proc_other_tail(canon, &upid);
    if (utail && upid != (s32)getpid() && proctab_userns(upid)) {
        int k = !strcmp(utail, "uid_map")   ? PF_UIDMAP :
                !strcmp(utail, "gid_map")   ? PF_GIDMAP :
                !strcmp(utail, "setgroups") ? PF_SETGROUPS : -1;
        if (k >= 0) {
            if (gflags & G_O_DIRECTORY) { *ret = -ENOTDIR; return 1; }
            int fd = synth_memfd();
            if (fd < 0) { *ret = -ENOENT; return 1; }   /* deny, never the host file */
            put_idmap(fd, m, k, upid);
            lseek(fd, 0, SEEK_SET);
            if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
            pf_track(m, fd, k, upid, 0);   /* written through, and re-read after */
            *ret = fd;
            return 1;
        }
    }

    /* /proc/<pid>/status: several of its lines describe the emulator and not
     * the guest process the file is supposed to be about (see put_status).
     * Tracked for refresh, since what those lines say changes as the process
     * runs. If a memfd or the host file is unavailable the host's own answer
     * still passes through -- it is wrong in places, not useless. */
    int stgt = status_target(canon);
    if (stgt) {
        if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
        if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }
        int fd = synth_memfd();
        if (fd < 0) return 0;                       /* no memfd: passthrough */
        int self = stgt == PS_SELF;
        s32 tid = 0;
        if (put_status(fd, m, canon, self, &tid) < 0) { close(fd); return 0; }
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        if (tid > 0) pf_track(m, fd, PF_STATUS, tid, self);
        *ret = fd;
        return 1;
    }

    const char *tail = self_tail(canon);
    if (tail) {
        if      (!strcmp(tail, "cmdline"))    kind = PF_CMDLINE;
        else if (!strcmp(tail, "environ"))    kind = PF_ENVIRON;
        else if (!strcmp(tail, "auxv"))       kind = PF_AUXV;
        else if (!strcmp(tail, "maps"))       kind = PF_MAPS;
        else if (!strcmp(tail, "mounts"))     kind = PF_MOUNTS;
        else if (!strcmp(tail, "mountinfo"))  kind = PF_MOUNTINFO;
        else if (!strcmp(tail, "mountstats")) kind = PF_MOUNTSTATS;
        /* Only this process's: another guest's limits live in its own Machine,
         * which is not shared, and its host file describes its emulator. */
        else if (!strcmp(tail, "limits"))     kind = PF_LIMITS;
        /* Writable, and only while the guest believes it has a user namespace
         * of its own -- otherwise the host files are the truthful answer. */
        else if (m->fake_userns && !strcmp(tail, "uid_map"))   kind = PF_UIDMAP;
        else if (m->fake_userns && !strcmp(tail, "gid_map"))   kind = PF_GIDMAP;
        else if (m->fake_userns && !strcmp(tail, "setgroups")) kind = PF_SETGROUPS;
        else return 0;
    } else if (!strcmp(canon, "/proc/mounts")) {
        kind = PF_MOUNTS;   /* the /etc/mtab symlink usually lands here */
    } else if (!strcmp(canon, "/proc/loadavg")) {
        kind = PF_LOADAVG;
    } else if (!strcmp(canon, "/proc/uptime")) {
        kind = PF_UPTIME;
    } else if (!strcmp(canon, "/proc/version")) {
        kind = PF_VERSION;
    } else if (!strcmp(canon, "/proc/stat")) {
        if (!stat_blocked()) return 0;   /* readable host file is richer */
        kind = PF_STAT;
    } else if (!strcmp(canon, "/proc/sys/kernel/overflowuid") ||
               !strcmp(canon, "/proc/sys/kernel/overflowgid")) {
        int is_gid = !strcmp(canon, "/proc/sys/kernel/overflowgid");
        if (!overflowid_blocked(is_gid)) return 0;   /* readable host file wins */
        kind = PF_OVERFLOWID;
    } else {
        return 0;
    }
    if (kind == PF_CMDLINE && !m->cmdline) return 0;
    if (kind == PF_ENVIRON && !m->environ) return 0;
    if (kind == PF_AUXV    && !m->auxv)    return 0;
    int writable = kind == PF_UIDMAP || kind == PF_GIDMAP || kind == PF_SETGROUPS;
    if (!writable && (gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
    if (gflags & G_O_DIRECTORY)                        { *ret = -ENOTDIR; return 1; }

    int fd = synth_memfd();
    if (fd < 0) return 0;   /* no memfd: degrade to host passthrough */

    ssize_t wr = 0;
    switch (kind) {
    case PF_CMDLINE:    wr = write(fd, m->cmdline, m->cmdline_len); break;
    case PF_ENVIRON:    wr = write(fd, m->environ, m->environ_len); break;
    case PF_AUXV:       wr = write(fd, m->auxv, m->auxv_len); break;
    case PF_MAPS:       put_maps(fd, m); break;
    case PF_MOUNTS:     put_mounts(fd, m, MNT_MOUNTS); break;
    case PF_MOUNTINFO:  put_mounts(fd, m, MNT_MOUNTINFO); break;
    case PF_MOUNTSTATS: put_mounts(fd, m, MNT_MOUNTSTATS); break;
    case PF_LOADAVG:    put_loadavg(fd); break;
    case PF_UPTIME:     put_uptime(fd, m); break;
    case PF_VERSION:    put_version(fd); break;
    case PF_STAT:       put_stat(fd, m); break;
    case PF_OVERFLOWID: put_overflowid(fd); break;
    case PF_LIMITS:     put_limits(fd, m); break;
    case PF_UIDMAP: case PF_GIDMAP: case PF_SETGROUPS:
                        put_idmap(fd, m, kind, 0); break;
    }
    (void)wr;   /* memfd write: no short/failed writes short of ENOMEM */
    lseek(fd, 0, SEEK_SET);
    if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);   /* guest didn't ask */
    if (kind == PF_LOADAVG || kind == PF_UPTIME || kind == PF_STAT ||
        kind == PF_LIMITS || writable)
        pf_track(m, fd, kind, 0, 1);   /* time-varying, or written through */
    *ret = fd;
    return 1;
}
