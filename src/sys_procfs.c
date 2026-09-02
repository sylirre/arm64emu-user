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
 * property of the process being asked about, but the Vm and Rss block,
 * TracerPid, Seccomp, the signal masks, NoNewPrivs and (under --fake-id)
 * Uid/Gid/Groups and the capability sets all describe the emulator instead,
 * and the host kernel's x86_* arch-hook lines describe the host CPU (see
 * put_status); statm and stat carry that same address-space block and are
 * synthesized with it. Another guest process's address-space files (maps,
 * smaps, pagemap, mem, ...) have no guest answer to synthesize and the host's
 * describes the emulator, so those are refused with EACCES rather than passed
 * through. Everything else under /proc
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
    PF_OVERFLOWID, PF_STATUS, PF_LIMITS, PF_STATM, PF_PIDSTAT,
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
static int put_pidstat(int fd, struct Machine *m, const ProcMem *pm,
                       const AsMem *mi, int self, const char *canon,
                       s32 *tid_out);
static int put_statm(int fd, struct Machine *m, const ProcMem *pm,
                     const AsMem *mi, const char *canon);
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
static int stat_probe_blocked(void) {
    if (getenv("A64_PROCSTAT_FORCE_SYNTH")) return 1;
    int fd = open("/proc/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    close(fd);
    return 0;
}
static int stat_blocked(void) {
    static int blocked = -1;
    return PROBE_ONCE(blocked, stat_probe_blocked());
}

/* A host kernel whose /proc is older than the one sys_uname advertises, so
 * whole fields and lines the guest ABI promises are simply not there to
 * rewrite: /proc/<pid>/stat stops at field 44 (start_data..exit_code are 3.3)
 * and status has no RssAnon/RssFile/RssShmem (4.5). Real on an Android 7
 * device (3.1) and nowhere else, so A64_PROCFS_FORCE_OLD stands in for one --
 * it hides exactly those from the host's own files, which is what makes the
 * emulator's two append paths reachable on an ordinary machine. */
static int procfs_old_host(void) {
    static int on = -1;
    return PROBE_ONCE(on, getenv("A64_PROCFS_FORCE_OLD") != NULL);
}

/* Same try-host-first gate for /proc/sys/kernel/overflow{u,g}id, which Android
 * SELinux denies an app along with the rest of /proc/sys. A guest that cannot
 * read them is not a hypothetical: it is the first thing bubblewrap does, and
 * it dies outright ("Can't read /proc/sys/kernel/overflowuid"). Probed once per
 * file per process; A64_OVERFLOWID_FORCE_SYNTH forces the fallback in tests. */
static int overflowid_probe_blocked(int is_gid) {
    if (getenv("A64_OVERFLOWID_FORCE_SYNTH")) return 1;
    int fd = open(is_gid ? "/proc/sys/kernel/overflowgid"
                         : "/proc/sys/kernel/overflowuid",
                  O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    close(fd);
    return 0;
}
static int overflowid_blocked(int is_gid) {
    static int blocked[2] = { -1, -1 };
    return PROBE_ONCE(blocked[is_gid], overflowid_probe_blocked(is_gid));
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

/* Online CPUs, as the synthesized /proc/stat reports them: one cpuN line each,
 * kernel-style (Linux prints the online mask, not the possible one).
 *
 * A64_PROCSTAT_HOTPLUG_SIM walks the count down on every sample (N, N-1, ...,
 * 1, N, ...). A host that takes cores offline is what breaks the counters'
 * monotonicity, and no ordinary development or CI machine ever does -- only
 * phones do -- so without this the regression is reachable on an Android
 * device alone. Descending rather than alternating so that consecutive
 * samples nearly always shrink: whether a *random* pattern catches the bug
 * depends on which way the count happened to move between two reads. */
static u64 stat_ncpu(void) {
    static int sim = -1;
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    u64 v = n > 0 ? (u64)n : 1;
    if (PROBE_ONCE(sim, getenv("A64_PROCSTAT_HOTPLUG_SIM") != NULL)) {
        static unsigned tick;
        u64 top = v > 4 ? v : 4;
        unsigned t = __atomic_fetch_add(&tick, 1u, __ATOMIC_RELAXED);
        v = top - (u64)(t % (unsigned)top);
    }
    return v;
}

/* CPU-time estimate for the synthesized /proc/stat, in USER_HZ = 100
 * jiffies (matching the G_AT_CLKTCK auxv): the real split is unknowable
 * without the host file, so busy time is the integral of the sysinfo()
 * load average over wall time (seeded from the 15-minute average, advanced
 * by the 1-minute average, capped at ncpu) and idle takes the rest of the
 * elapsed CPU-seconds.
 *
 * Both figures are *accumulated*, never recomputed from the current uptime
 * and CPU count, because ncpu is not a constant: Android hotplugs cores for
 * power (a Nougat armv7 device was measured walking 3 -> 2 -> 3 -> 2 -> 1
 * within fifteen seconds). Deriving the total as up_j * ncpu each time made
 * every core that went offline walk the counters backwards, and a
 * delta-computing reader -- top, vmstat, procps in general -- subtracts
 * consecutive samples, so a backwards step there is not a small error but a
 * huge bogus one. Accumulating instead keeps every increment >= 0 whatever
 * the host does with its cores, which is the one property those readers
 * actually require of the file. */
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
    if (!m->stat_last_ns) {
        /* Seed: split the whole of boot-so-far by the 15-minute average. */
        m->stat_busy = up_j * l15 >> 16;
        u64 total = up_j * ncpu;
        m->stat_idle = total > m->stat_busy ? total - m->stat_busy : 0;
        m->stat_last_ns = now;
    } else if (now > m->stat_last_ns) {
        u64 dt_j = (now - m->stat_last_ns) / 10000000;   /* whole jiffies */
        u64 busy_inc = dt_j * l1 >> 16;                  /* <= dt_j * ncpu */
        m->stat_busy += busy_inc;
        m->stat_idle += dt_j * ncpu - busy_inc;
        /* Advance by what was consumed, not to `now`: a reader polling faster
         * than a jiffy would otherwise throw away the remainder every time and
         * see counters frozen forever. */
        m->stat_last_ns += dt_j * 10000000;
    }
    *busy_j = m->stat_busy;
    *idle_j = m->stat_idle;
    EMU_UNLOCK(&est_lock, EMU_LK_EST);
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
    struct stat st;   /* both halves of the identity: see procfs_pre_read */
    if (fstat(fd, &st) != 0 || (u64)st.st_ino != m->pf_fds[i].ino ||
        (u64)st.st_dev != m->pf_fds[i].dev) {
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
    EMU_LOCK(&pf_lock, EMU_LK_PF);
    if (m->pf_fds_count < PF_MAX_FDS) {
        m->pf_fds[m->pf_fds_count].fd = fd;
        m->pf_fds[m->pf_fds_count].kind = (u8)kind;
        m->pf_fds[m->pf_fds_count].self = (u8)self;
        m->pf_fds[m->pf_fds_count].pid = pid;
        m->pf_fds[m->pf_fds_count].dev = (u64)st.st_dev;
        m->pf_fds[m->pf_fds_count].ino = (u64)st.st_ino;
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
    /* Device and inode, not the inode alone: the number repeats across
     * filesystems, and everything below rewrites this descriptor from byte
     * zero -- an entry that matched a recycled fd by luck would truncate
     * whatever the guest opened next. */
    if (fstat(fd, &st) != 0 || (u64)st.st_ino != m->pf_fds[i].ino ||
        (u64)st.st_dev != m->pf_fds[i].dev) {
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
    /* As PF_STATUS: what these say changes as the process runs, the figures
     * for another guest come from its registry entry and the rest from its
     * host file, and the tid the open resolved names that file directly. */
    case PF_STATM: case PF_PIDSTAT: {
        int self = m->pf_fds[i].self;
        char path[64];
        AsMem lm, *mi = NULL;
        ProcMem pm;
        snprintf(path, sizeof path, "/proc/%d/%s", (int)m->pf_fds[i].pid,
                 m->pf_fds[i].kind == PF_STATM ? "statm" : "stat");
        if (self) {
            as_procmem(&m->as, &pm);
            as_meminfo(&m->as, &lm);
            if (lm.rss_ok) mi = &lm;
        } else if (!proctab_mem_get(m->pf_fds[i].pid, &pm)) {
            break;                       /* keep the snapshot we have */
        }
        int st = m->pf_fds[i].kind == PF_STATM
                     ? put_statm(fd, m, &pm, mi, path)
                     : put_pidstat(fd, m, &pm, mi, self, path, NULL);
        if (st < 0) m->pf_fds[i] = m->pf_fds[--m->pf_fds_count];
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
static int synth_memfd(void) {
    /* A64_PROCSYNTH_FORCE_FAIL: pretend there is no anonymous backing at all
     * -- the tier a host with neither memfd_create nor a writable directory is
     * served by. What matters about that tier is that it must not degrade into
     * handing the guest the emulator's own /proc files, so the suite runs the
     * leak check over it. Probed once per process (a fork inherits it). */
    static int forced = -1;
    if (PROBE_ONCE(forced, getenv("A64_PROCSYNTH_FORCE_FAIL") != NULL)) {
        errno = ENOSYS;
        return -1;
    }
    return a64_anonfd("proc-synth");
}

/* What to answer when there is no anonymous backing for a synthesized view.
 * Never 0 ("fall through to the host file"): these files describe the EMULATOR
 * -- its environment, command line, address space, mount table, limits -- and
 * handing them to the guest is the leak the synthesis exists to prevent. A
 * guest that ran the process out of descriptors gets the error its own open(2)
 * would have hit; anything else reads as a file that is not there. */
static s64 synth_denied(void) {
    return (errno == EMFILE || errno == ENFILE) ? -errno : -ENOENT;
}

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

/* ---- the guest's own memory footprint ----
 *
 * Every size a guest can read about itself -- the Vm and Rss block of
 * /proc/<pid>/status, all of /proc/<pid>/statm, and the address fields of
 * /proc/<pid>/stat -- describes the GUEST's address space, which the emulator
 * knows exactly (mem.c keeps the region list) and the host file does not: the
 * host process is the emulator, holding the guest's memory plus its own code,
 * software page tables, JIT cache and malloc, at its own foreign-ISA
 * addresses. Left alone, a guest that had mapped 74 MB read VmSize 145 MB, a
 * VmStk of 148 kB for an 8 MB stack, and a VmExe naming the emulator's text.
 * It is the same reason /proc/<pid>/limits is synthesized, and the same reason
 * RLIMIT_AS and RLIMIT_DATA are enforced here rather than handed to the host:
 * the two must describe one address space, or a guest reading its own usage
 * against its own limit gets nonsense.
 *
 * Another guest process's sizes are not in reach of its own region list --
 * that lives in its own emulator and is not shared -- so they come from what
 * it published in the shared PID registry (proctab.c) on every change to its
 * address space. All three files take that route, because all three describe
 * one address space and a reader may compare them: status reporting 81804 kB
 * where that process's own stat and statm reported 9948 is worse than either
 * figure alone.
 *
 * The resident half is the exception, and the one thing here that is not the
 * guest's own: sampling it means walking the address space being described
 * (mincore, in as_meminfo), which a reader can do only for itself and only on
 * a host that answers. Everywhere else the host's figure stands -- bounded, so
 * that a resident set larger than the whole address space that holds it can
 * never be reported (rss_bound). */
#define PG_UP_G(x) (((x) + GUEST_PAGE_MASK) & ~(u64)GUEST_PAGE_MASK)

/* The executable's code span out of a ProcMem, split as task_mem splits it:
 * the executable's own code span is "text", everything else executable and
 * unwritable -- the interpreter, the shared libraries -- is "lib". */
static void pm_text_lib(const ProcMem *pm, u64 *text, u64 *lib) {
    u64 t = 0;
    if (pm->end_code > pm->start_code)
        t = PG_UP_G(pm->end_code) - (pm->start_code & ~(u64)GUEST_PAGE_MASK);
    if (t > pm->exec) t = pm->exec;   /* task_mem: text = min(text, exec_vm) */
    *text = t;
    *lib = pm->exec - t;
}

/* The status lines this answers, in the kernel's own order. VM_RSSFIRST..
 * VM_RSSLAST are the ones that need a resident-set sample; the rest are sizes,
 * which come out of the ProcMem every guest process publishes. */
enum {
    VM_PEAK, VM_SIZE, VM_LCK, VM_PIN,
    VM_HWM, VM_RSS, VM_RSSANON, VM_RSSFILE, VM_RSSSHMEM,
    VM_DATA, VM_STK, VM_EXE, VM_LIB, VM_PTE, VM_SWAP, VM_NKEYS
};
#define VM_RSSFIRST VM_HWM
#define VM_RSSLAST  VM_RSSSHMEM
static const char *const vm_keys[VM_NKEYS] = {
    "VmPeak", "VmSize", "VmLck", "VmPin",
    "VmHWM", "VmRSS", "RssAnon", "RssFile", "RssShmem",
    "VmData", "VmStk", "VmExe", "VmLib", "VmPTE", "VmSwap"
};

/* The value for one of the size lines, in kB. mlock is a no-op here and there
 * is no guest swap, so VmLck/VmPin/VmSwap are structurally zero rather than
 * unknown. VmPTE is the emulator's own second-level tables: eight bytes per
 * mapped guest page, which is exactly what a kernel's leaf page tables cost,
 * so the figure means what the guest expects it to mean even though the shape
 * of the table is not a kernel's. The resident lines are not here: they need a
 * sample, and rss_line_kb answers them. */
static u64 vm_value_kb(const ProcMem *pm, const AsMem *mi, int k) {
    u64 text, lib;
    switch (k) {
    case VM_PEAK:     return pm->peak >> 10;
    case VM_SIZE:     return pm->size >> 10;
    case VM_HWM:      return mi->rss_peak >> 10;
    case VM_RSS:      return (mi->rss_anon + mi->rss_file + mi->rss_shmem) >> 10;
    case VM_RSSANON:  return mi->rss_anon >> 10;
    case VM_RSSFILE:  return mi->rss_file >> 10;
    case VM_RSSSHMEM: return mi->rss_shmem >> 10;
    case VM_DATA:     return pm->data >> 10;
    case VM_STK:      return pm->stack >> 10;
    case VM_EXE:      pm_text_lib(pm, &text, &lib); return text >> 10;
    case VM_LIB:      pm_text_lib(pm, &text, &lib); return lib >> 10;
    case VM_PTE:      return pm->pgtables >> 10;
    default:          return 0;   /* VmLck, VmPin, VmSwap */
    }
}

/* A resident figure the emulator could not sample inside the guest's own
 * address space: another process's -- a reader cannot walk an address space
 * that is not its own -- or our own on a host that will not answer mincore(2).
 * The host's figure stands there, and it is not nothing: the emulator's
 * backing IS the guest's memory, so the host's resident set contains the
 * guest's and over-estimates it.
 *
 * What it must not do is exceed what the guest mapped, which a kernel's never
 * can. Unbounded it did: `ps` inside the guest printed RSS 21m against VSZ
 * 9964 kB, and a reader computing VmSize - VmRSS in unsigned arithmetic gets
 * an enormous number rather than a small one. So every such figure is bounded
 * by the guest's own size, and the RssAnon/RssFile/RssShmem components are
 * bounded in turn by what is left of the bounded total, in the order the file
 * prints them -- which keeps their sum exactly VmRSS, as a kernel keeps it. */
static u64 rss_bound(u64 host, u64 *budget) {
    if (host > *budget) host = *budget;
    *budget -= host;
    return host;
}

/* One resident line of status, in kB: sampled where we could sample, and the
 * host's own figure bounded where we could not. `p` is the host's line, whose
 * number is what gets bounded; *budget carries the bounded VmRSS down to the
 * three components. */
static u64 rss_line_kb(const ProcMem *pm, const AsMem *mi, int k,
                       const char *p, u64 *budget) {
    if (mi) return vm_value_kb(pm, mi, k);
    u64 host = strtoull(p + strlen(vm_keys[k]) + 1, NULL, 10);
    switch (k) {
    case VM_HWM: { u64 b = pm->peak >> 10; return rss_bound(host, &b); }
    case VM_RSS: {
        /* The bounded total, which the three components then partition -- so
         * it sets the budget rather than drawing on it. */
        u64 b = pm->size >> 10;
        return *budget = rss_bound(host, &b);
    }
    case VM_RSSANON: case VM_RSSFILE: case VM_RSSSHMEM:
        return rss_bound(host, budget);
    default: return host;    /* unreachable: only the resident lines get here,
                                and only those have a size to be bounded by */
    }
}

/* /proc/<pid>/statm: size resident shared text lib data dt, in guest pages.
 * `lib` and `dt` have read 0 since 2.6 -- the kernel prints both as literals,
 * so this does too.
 *
 * The sizes are always the guest's: ours from our own region list, another
 * process's from what it published. The two resident columns need a sample
 * inside the address space being described, so they are ours only when we
 * could take one -- for another process, or on a host that will not answer
 * mincore(2), the host file's figures stand, bounded (see rss_bound). Returns
 * 0, or -1 when the host file could not be read. */
static int put_statm(int fd, struct Machine *m, const ProcMem *pm,
                     const AsMem *mi, const char *canon) {
    u64 text, lib;
    pm_text_lib(pm, &text, &lib);
    unsigned long long resident = 0, shared = 0;
    if (mi) {
        shared = (mi->rss_file + mi->rss_shmem) >> 12;
        resident = shared + (mi->rss_anon >> 12);
    } else {
        char buf[256];
        int hfd = open(canon, O_RDONLY | O_CLOEXEC);
        if (hfd < 0) return -1;
        ssize_t n = read(hfd, buf, sizeof buf - 1);
        close(hfd);
        if (n <= 0) return -1;
        buf[n] = 0;
        unsigned long long ign;
        if (sscanf(buf, "%llu %llu %llu", &ign, &resident, &shared) != 3)
            return -1;
        u64 budget = pm->size >> 12;
        resident = rss_bound(resident, &budget);
        budget = resident;                  /* shared is part of resident */
        shared = rss_bound(shared, &budget);
    }
    (void)m;
    dprintf(fd, "%llu %llu %llu %llu 0 %llu 0\n",
            (unsigned long long)(pm->size >> 12), resident, shared,
            (unsigned long long)(text >> 12),
            (unsigned long long)((pm->data + pm->stack) >> 12));
    return 0;
}

#define STATUS_MAX 16384    /* a status file is ~2 KB; Groups: is the long line */
#define STATUS_CAP (1u << 20)   /* refuse to rewrite anything past this */

/* Guest view of /proc/<pid>/status: pass the host file through, rewriting the
 * lines that describe the EMULATOR rather than the guest and dropping the ones
 * that describe the host's architecture. Everything else -- State, PPid,
 * FDSize, Threads, the context-switch counters -- is a real property of the
 * process being asked about and stands as it is.
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
 * Seccomp and the Vm sizes from the PID registry -- and leave the host's
 * approximation of the rest standing, the same split every other cross-process
 * /proc file here makes: its blocked set would have to be republished on every
 * sigprocmask and every delivery to be worth reading, and being per-thread it
 * does not belong in a per-process record anyway.
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
    if (hfd < 0) return -1;              /* no host file: the caller's open
                                            fails the same way, nothing leaks */
    size_t cap = STATUS_MAX, n = 0;
    char *buf = malloc(cap);
    if (!buf) { close(hfd); return -2; }
    for (;;) {
        ssize_t r = read(hfd, buf + n, cap - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (n < cap - 1) continue;
        /* Only Groups: can grow without bound (towards NGROUPS_MAX), and a
         * rewrite of half a file would be worse than none -- so grow rather
         * than give up, and stop only at an absurdity. Handing back the raw
         * host file is not an option: its Uid, Seccomp and Sig* lines describe
         * the emulator, which is exactly what the rewrite exists to hide. */
        if (cap >= STATUS_CAP) { free(buf); close(hfd); return -2; }
        char *nb = realloc(buf, cap * 2);
        if (!nb) { free(buf); close(hfd); return -2; }
        buf = nb;
        cap *= 2;
    }
    close(hfd);
    if (!n) { free(buf); return -2; }    /* readable but empty: not rewritable */
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
            u64 h = sig_action_handler(m, s);            /* under the siglock
                                                            stand-in (signal.c) */
            if (h == 1) ign |= 1ull << (s - 1);          /* SIG_IGN */
            else if (h) cgt |= 1ull << (s - 1);          /* a guest handler */
        }
    }
    /* The guest's own address-space sizes in place of the emulator's; see the
     * block comment above. Ours come from our own region list, another guest
     * process's from what it published in the shared registry (proctab.c) --
     * the same split its stat and statm make, and this file has to agree with
     * those two. Tgid, not Pid: a thread's task/<tid>/status describes the
     * address space of the process it belongs to. The resident half needs a
     * sample taken inside that address space, which is ours to take only for
     * ourselves; `budget` carries the bounded VmRSS to its components. */
    ProcMem pm;
    AsMem lm, *mi = NULL;
    int pm_ok;
    if (self) {
        as_procmem(&m->as, &pm);
        as_meminfo(&m->as, &lm);
        if (lm.rss_ok) mi = &lm;
        pm_ok = 1;
    } else {
        pm_ok = tgid > 0 && proctab_mem_get(tgid, &pm);
    }
    u64 budget = pm_ok ? pm.size >> 10 : 0;
    u32 vseen = 0;

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
        if (pm_ok) {
            /* The Vm and Rss block, describing the guest's address space
             * rather than the emulator's. Rewritten where the host file has
             * the line and appended below where it does not -- RssAnon,
             * RssFile and RssShmem are 4.5 and later. */
            for (int k = 0; k < VM_NKEYS; k++) {
                if (!is_key(p, vm_keys[k])) continue;
                /* Stand in for a host too old to have this line at all. */
                if (procfs_old_host() && k >= VM_RSSANON && k <= VM_RSSSHMEM)
                    goto next_line;
                u64 v = (k >= VM_RSSFIRST && k <= VM_RSSLAST)
                            ? rss_line_kb(&pm, mi, k, p, &budget)
                            : vm_value_kb(&pm, mi, k);
                dprintf(fd, "%s:\t%8llu kB\n", vm_keys[k],
                        (unsigned long long)v);
                vseen |= 1u << k;
                goto next_line;
            }
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
    /* A host file missing one of the Vm/Rss keys is a host kernel older than
     * it (RssAnon/RssFile/RssShmem are 4.5). The guest ABI promises the whole
     * block, and a reader that greps for a line reads its absence as zero, so
     * what the loop never saw is appended -- as NoNewPrivs and Seccomp are,
     * and for the same reason. */
    if (pm_ok)
        for (int k = 0; k < VM_NKEYS; k++) {
            if (vseen & (1u << k)) continue;
            u64 v;
            if (mi || k < VM_RSSFIRST || k > VM_RSSLAST) {
                v = vm_value_kb(&pm, mi, k);
            } else if (k == VM_RSSANON) {
                /* No sample of our own, and a host file with no split to
                 * bound: what is left of the bounded VmRSS is resident and
                 * unattributed, and anonymous is what it is. That is also what
                 * the sampled tier reports -- the guest's images are read into
                 * anonymous guest pages, so RssFile and RssShmem are zero
                 * there too -- and it keeps the three summing to VmRSS, which
                 * is the one thing every reader of this file relies on. On a
                 * host too old for these lines (they are 4.5) the components
                 * used to be dropped entirely, so a guest read its own VmRSS
                 * against three zeroes. */
                v = budget;
                budget = 0;
            } else if (k == VM_RSSFILE || k == VM_RSSSHMEM) {
                v = 0;
            } else {
                continue;   /* VmHWM / VmRSS: no host figure, nothing to bound */
            }
            dprintf(fd, "%s:\t%8llu kB\n", vm_keys[k], (unsigned long long)v);
        }
    if (self && !saw_nnp)
        dprintf(fd, "NoNewPrivs:\t%d\n", m->no_new_privs ? 1 : 0);
    if (scknown && !saw_sec) dprintf(fd, "Seccomp:\t%u\n", scmode);
    if (scknown && !saw_scflt) dprintf(fd, "Seccomp_filters:\t%u\n", scfilters);
    free(buf);
    return 0;
}

/* One field of /proc/<pid>/stat that describes the guest's address space
 * rather than the emulator's, by its 1-based position in the line. Everything
 * else there -- the pid, the state, the times, the scheduling numbers -- is a
 * real property of the task and stands. `rss` is in pages, the rest in bytes,
 * as the kernel prints them. Returns 0 for a field this does not answer. */
static int pidstat_field(struct Machine *m, const ProcMem *pm, const AsMem *mi,
                         int self, const char *tok, int f, u64 *out) {
    switch (f) {
    case 23: *out = pm->size; return 1;                       /* vsize */
    case 24: {                                                /* rss, pages */
        /* A sample taken inside the address space this file describes, where
         * one could be taken; otherwise the host's own figure -- its
         * emulator's -- bounded by what the guest mapped (see rss_bound). */
        if (mi) {
            *out = (mi->rss_anon + mi->rss_file + mi->rss_shmem) >> 12;
            return 1;
        }
        u64 budget = pm->size >> 12;
        *out = rss_bound(strtoull(tok, NULL, 10), &budget);
        return 1;
    }
    case 25:                                                  /* rsslim */
        /* This process's own RLIMIT_RSS, which is a property of the process
         * and not of any sample: it stands whether or not the resident set
         * could be measured. Another guest's limit table lives in its own
         * Machine and is not shared, so its host file's figure stands. */
        if (!self) return 0;
        *out = m->rlim[G_RLIMIT_RSS].rlim_cur;
        if (*out == G_RLIM_INFINITY) *out = ~0ULL;
        return 1;
    case 26: *out = pm->start_code;  return 1;
    case 27: *out = pm->end_code;    return 1;
    case 28: *out = pm->start_stack; return 1;
    case 45: *out = pm->start_data;  return 1;
    case 46: *out = pm->end_data;    return 1;
    case 47: *out = pm->start_brk;   return 1;
    case 48: *out = pm->arg_start;   return 1;
    case 49: *out = pm->arg_end;     return 1;
    case 50: *out = pm->env_start;   return 1;
    case 51: *out = pm->env_end;     return 1;
    default: return 0;
    }
}

/* Guest view of /proc/<pid>/stat: the host line with those fields replaced.
 * Returns 0, or -1 when there is no host file (the caller's open reports that
 * itself) / -2 when there is one that cannot be parsed.
 *
 * The comm field is parenthesized and may itself contain spaces and
 * parentheses, so the split starts at the LAST ')' -- the same rule every
 * reader of this file has to follow. */
static int put_pidstat(int fd, struct Machine *m, const ProcMem *pm,
                       const AsMem *mi, int self, const char *canon,
                       s32 *tid_out) {
    int hfd = open(canon, O_RDONLY | O_CLOEXEC);
    if (hfd < 0) return -1;
    char buf[4096];
    ssize_t n = read(hfd, buf, sizeof buf - 1);
    close(hfd);
    if (n <= 0) return -2;
    buf[n] = 0;
    char *rp = strrchr(buf, ')');
    if (!rp || !rp[1]) return -2;
    /* Field 1 names the task this file describes -- which spelling of the path
     * got here does not matter, and a refresh can reach it as /proc/<tid>. */
    if (tid_out) *tid_out = (s32)strtol(buf, NULL, 10);

    *rp = 0;
    dprintf(fd, "%s)", buf);       /* pid and comm stand as the host has them */
    int f = 2;
    int shorth = procfs_old_host();
    for (char *tok = strtok(rp + 1, " \t\n"); tok; tok = strtok(NULL, " \t\n")) {
        u64 v;
        if (shorth && f >= 44) break;      /* stand in for a pre-3.3 kernel */
        if (pidstat_field(m, pm, mi, self, tok, ++f, &v))
            dprintf(fd, " %llu", (unsigned long long)v);
        else
            dprintf(fd, " %s", tok);
    }
    /* Rewriting a field cannot conjure one the host never printed. A kernel
     * older than 3.3 stops at field 44 -- start_data, end_data, start_brk,
     * arg_start, arg_end, env_start, env_end and exit_code were all added
     * there -- and a guest that sys_uname has told it is on a modern kernel
     * then reads zero for every one of them: on an Android 7 device (3.1) the
     * guest could not find its own argv or environment in its own stat line,
     * and neither could anything reading another guest's. The seven that
     * describe the address space are exactly the ones synthesized above;
     * exit_code is 0 for a task that is still running, which every task this
     * file is opened for is. */
    while (f < 52) {
        u64 v;
        if (pidstat_field(m, pm, mi, self, "0", ++f, &v))
            dprintf(fd, " %llu", (unsigned long long)v);
        else
            dprintf(fd, " 0");
    }
    dprintf(fd, "\n");
    return 0;
}

/* "/proc/<N>/cmdline" (or that process's own task/<tid>/cmdline, the same
 * file) -> *pid = N, returns 1; else 0. */
static int proc_other_cmdline(const char *canon, s32 *pid) {
    const char *t = proc_other_tail(canon, pid);
    return t && !strcmp(t, "cmdline");
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
        if (fd < 0) { *ret = synth_denied(); return 1; }   /* never the host file */
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
        if (fd < 0) { *ret = synth_denied(); return 1; }   /* never the host file */
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
        if (fd < 0) { *ret = synth_denied(); return 1; }   /* never the host file */
        if (blen) { ssize_t w = write(fd, buf, blen); (void)w; }
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        *ret = fd;
        return 1;
    }

    /* Address-space files of ANOTHER guest process: refused, never passed
     * through (see proc_addrspace_leaf in path.c). Only for a pid we admit
     * exists -- a non-guest one keeps path.c's ENOENT, so this cannot be used
     * to probe which host pids are real. EACCES is the shape of refusal a host
     * already gives here: reading them needs PTRACE_MODE_READ, which yama's
     * ptrace_scope=1 denies between siblings. */
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
        if (fd < 0) { *ret = synth_denied(); return 1; }
        int self = stgt == PS_SELF;
        s32 tid = 0;
        int st = put_status(fd, m, canon, self, &tid);
        if (st < 0) {
            close(fd);
            /* -1 is "there is no host file to rewrite": the caller's own open
             * reports that, and reports it exactly. -2 is "there is one but it
             * cannot be rewritten", and the raw file describes the emulator. */
            if (st == -1) return 0;
            *ret = -ENOMEM;
            return 1;
        }
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        if (tid > 0) pf_track(m, fd, PF_STATUS, tid, self);
        *ret = fd;
        return 1;
    }

    /* /proc/<pid>/statm and /proc/<pid>/stat: their sizes are the emulator's
     * address space, which is not the guest's (see the memory block above).
     * These are the two files ps and top actually read -- status is not -- so
     * leaving them alone would have left `ps` inside the guest reporting the
     * emulator's VSZ and RSS, for every process including itself. Tracked for
     * refresh: every number in them moves as the process runs. */
    s32 szpid = 0;
    const char *sztail = self_tail(canon);
    if (!sztail) {
        /* Another guest process's: its sizes come from what it published in
         * the shared registry (proctab.c), the way its cmdline and seccomp
         * state do. A pid that is not a guest process never reaches here --
         * path.c has already routed it to the hidden view's ENOENT. */
        const char *ot = proc_other_tail(canon, &szpid);
        if (ot && szpid != (s32)getpid() && proctab_has(szpid)) sztail = ot;
        else szpid = 0;
    }
    if (sztail && (!strcmp(sztail, "statm") || !strcmp(sztail, "stat"))) {
        int is_statm = sztail[4] == 'm';
        /* The task a refresh must go back to: another guest's pid, or our own
         * -- which put_pidstat replaces with the exact task the file named
         * (a thread's task/<tid>/stat is not the leader's). */
        s32 sttid = szpid ? szpid : (s32)getpid();
        AsMem lm, *mi = NULL;
        ProcMem pm;
        if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
        if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }
        if (szpid) {
            /* Nothing published yet (the process is mid-registration): the
             * host file is wrong in places, not useless. */
            if (!proctab_mem_get(szpid, &pm)) return 0;
        } else {
            as_procmem(&m->as, &pm);
            as_meminfo(&m->as, &lm);
            if (lm.rss_ok) mi = &lm;
        }
        int fd = synth_memfd();
        if (fd < 0) { *ret = synth_denied(); return 1; }
        int st = is_statm ? put_statm(fd, m, &pm, mi, canon)
                          : put_pidstat(fd, m, &pm, mi, !szpid, canon, &sttid);
        if (st < 0) {
            close(fd);
            if (st == -1) return 0;   /* no host file: report that exactly */
            *ret = -ENOMEM;
            return 1;
        }
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        pf_track(m, fd, is_statm ? PF_STATM : PF_PIDSTAT, sttid, !szpid);
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
        /* The address-space files of THIS process. The deny above covered only
         * another guest's, and everything under /proc that is not synthesized
         * passes through -- so open("/proc/self/mem") handed the guest a
         * read-write descriptor onto the emulator's own host address space, and
         * /proc/self/map_files/ handed out host descriptors for everything the
         * emulator has mapped. Neither is a leak of information the emulator
         * could have answered differently: there is no guest answer at all for
         * them, which is exactly why the same refusal is right here. "maps" is
         * on that list too and never reaches this line -- it is synthesized
         * above, from the guest address space, which is the whole point. */
        else if (proc_addrspace_leaf(tail)) { *ret = -EACCES; return 1; }
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
    if (fd < 0) {
        /* Only the host-global views may fall through to the host file: they
         * carry no guest state and the host's own answer is the truthful one
         * (PF_STAT and PF_OVERFLOWID are only synthesized when it cannot be
         * read at all, so falling through re-reports that same failure). The
         * rest describe THIS process, and the host file describes the emulator
         * running it -- its environment, command line, address space, mount
         * table and limits. Deny those instead. */
        if (kind == PF_LOADAVG || kind == PF_UPTIME || kind == PF_VERSION ||
            kind == PF_STAT || kind == PF_OVERFLOWID)
            return 0;
        *ret = synth_denied();
        return 1;
    }

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
