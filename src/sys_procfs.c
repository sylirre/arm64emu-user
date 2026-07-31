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
 * this Machine (self) or the shared PID registry (another guest process). Under
 * --fake-id, /proc/<pid>/status is also synthesized: the host file's
 * Uid:/Gid:/Groups: lines carry the real invoking uid, but ps/top read them to
 * name the user, so those lines are rewritten through the fake-id remap (a static
 * snapshot; the rest of the file passes through). Everything else under /proc
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

enum {
    PF_CMDLINE, PF_MAPS, PF_MOUNTS, PF_MOUNTINFO,
    PF_LOADAVG, PF_UPTIME, PF_VERSION, PF_STAT,
    PF_ENVIRON, PF_MOUNTSTATS, PF_AUXV,
    PF_UIDMAP, PF_GIDMAP, PF_SETGROUPS,
    PF_OVERFLOWID,
};

/* put_mounts format selector. */
enum { MNT_MOUNTS = 0, MNT_MOUNTINFO = 1, MNT_MOUNTSTATS = 2 };

/* Guards the pf_fds refresh registry (one struct Machine per process;
 * these files are opened rarely, so a single lock is fine). */
static pthread_mutex_t pf_lock = PTHREAD_MUTEX_INITIALIZER;
/* Leaf lock for the /proc/stat busy estimate — the writers run both with
 * and without pf_lock held (open vs refresh path). */
static pthread_mutex_t est_lock = PTHREAD_MUTEX_INITIALIZER;

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
    pthread_mutex_lock(&est_lock);
    if (!m->stat_last_ns)
        m->stat_busy = up_j * l15 >> 16;
    else if (now > m->stat_last_ns)
        m->stat_busy += (now - m->stat_last_ns) / 10000000 * l1 >> 16;
    m->stat_last_ns = now;
    u64 busy = m->stat_busy;
    pthread_mutex_unlock(&est_lock);
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
 * A guest that thinks it unshared CLONE_NEWUSER writes /proc/self/uid_map,
 * gid_map and setgroups exactly once and expects the values back; the host
 * files describe the *initial* namespace, whose map is fixed, so a real write
 * is refused (bubblewrap dies with "setting up uid map"). These three are
 * therefore synthesized from Machine state whenever the namespace was faked,
 * and pass through untouched otherwise -- outside the fiction the host file is
 * the truthful answer. The recorded maps are reported, not applied: they
 * change no id the guest sees (that is what --fake-id does). */
static void put_idmap(int fd, struct Machine *m, int kind) {
    const char *s = kind == PF_UIDMAP ? m->uid_map :
                    kind == PF_GIDMAP ? m->gid_map :
                    (m->setgroups_deny ? "deny\n" : "allow\n");
    if (*s) { ssize_t w = write(fd, s, strlen(s)); (void)w; }
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
    pthread_mutex_lock(&pf_lock);
    int i;
    for (i = 0; i < m->pf_fds_count; i++)
        if (m->pf_fds[i].fd == fd) break;
    if (i == m->pf_fds_count) { pthread_mutex_unlock(&pf_lock); return 0; }
    struct stat st;
    if (fstat(fd, &st) != 0 || (u64)st.st_ino != m->pf_fds[i].ino) {
        m->pf_fds[i] = m->pf_fds[--m->pf_fds_count];   /* stale: fd reused */
        pthread_mutex_unlock(&pf_lock);
        return 0;
    }
    int kind = m->pf_fds[i].kind;
    pthread_mutex_unlock(&pf_lock);
    if (kind != PF_UIDMAP && kind != PF_GIDMAP && kind != PF_SETGROUPS) return 0;
    if (off < 0) off = lseek(fd, 0, SEEK_CUR);
    if (off != 0) { *ret = -EINVAL; return 1; }

    if (kind == PF_SETGROUPS) {
        /* "allow" or "deny", and only until gid_map is set -- afterwards the
         * kernel refuses, since the decision has already been used. */
        int deny;
        if (len >= 4 && !memcmp(buf, "deny", 4))       deny = 1;
        else if (len >= 5 && !memcmp(buf, "allow", 5)) deny = 0;
        else { *ret = -EINVAL; return 1; }
        if (m->gid_map_set)                { *ret = -EPERM; return 1; }
        if (m->setgroups_deny && !deny)    { *ret = -EPERM; return 1; }
        m->setgroups_deny = (u8)deny;
        m->setgroups_set = 1;
        *ret = (s64)len;
        return 1;
    }
    if (kind == PF_UIDMAP ? m->uid_map_set : m->gid_map_set) {
        *ret = -EPERM;   /* only one successful write to a map */
        return 1;
    }
    char fmt[IDMAP_MAX];
    fmt[0] = 0;
    int r = idmap_format((const char *)buf, len, fmt, sizeof fmt);
    if (r < 0) { *ret = r; return 1; }
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
static void pf_track(struct Machine *m, int fd, int kind) {
    struct stat st;
    if (fstat(fd, &st) != 0) return;
    pthread_mutex_lock(&pf_lock);
    if (m->pf_fds_count < PF_MAX_FDS) {
        m->pf_fds[m->pf_fds_count].fd = fd;
        m->pf_fds[m->pf_fds_count].kind = (u8)kind;
        m->pf_fds[m->pf_fds_count].ino = (u64)st.st_ino;
        m->pf_fds_count++;
    }
    pthread_mutex_unlock(&pf_lock);
}

void procfs_unmark_fd(struct Machine *m, int fd) {
    if (!m->pf_fds_count) return;
    pthread_mutex_lock(&pf_lock);
    for (int i = 0; i < m->pf_fds_count; i++)
        if (m->pf_fds[i].fd == fd) {
            m->pf_fds[i] = m->pf_fds[--m->pf_fds_count];
            break;
        }
    pthread_mutex_unlock(&pf_lock);
}

void procfs_pre_read(CPU *c, int fd, s64 off) {
    struct Machine *m = c->m;
    if (!m->pf_fds_count) return;   /* unlocked fast path; benign race */
    pthread_mutex_lock(&pf_lock);
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
    /* Re-read after a write must show what was written. */
    case PF_UIDMAP: case PF_GIDMAP: case PF_SETGROUPS:
        put_idmap(fd, m, m->pf_fds[i].kind);
        break;
    }
    lseek(fd, 0, SEEK_SET);
out:
    pthread_mutex_unlock(&pf_lock);
}

/* Anonymous backing for a synthesized /proc view. Bionic only declares the
 * wrapper on newer API levels; the raw syscall is on the Android 8 allow-list. */
static int synth_memfd(void) {
#if defined(__BIONIC__) && defined(SYS_memfd_create)
    return (int)syscall(SYS_memfd_create, "proc-synth", 1 /* MFD_CLOEXEC */);
#else
    return memfd_create("proc-synth", MFD_CLOEXEC);
#endif
}

/* True if canon names "/proc/<pid>/status" for a VISIBLE process: self,
 * own-pid, or a registered guest pid. A hidden (non-guest) pid returns 0 so the
 * path layer's ENOENT stands and no foreign process's status can leak -- the
 * same visibility rule the other-pid handlers rely on. */
static int status_target(const char *canon) {
    const char *t = self_tail(canon);
    if (t) return !strcmp(t, "status");
    s32 pid;
    t = proc_other_tail(canon, &pid);
    return t && !strcmp(t, "status") && proctab_has(pid);
}

/* Copy the host /proc/<pid>/status through, rewriting only the Uid:/Gid:/Groups:
 * numeric fields via the fake-id remap so ps/top resolve the fake identity's
 * user/group (they read the Uid: line, which otherwise carries the emulator's
 * real host uid). Only called under m->fake_id; canon is the passthrough host
 * path. Returns 0 on success, -1 if the host file can't be read (caller then
 * falls through to plain passthrough). */
static int put_status(int fd, struct Machine *m, const char *canon) {
    FILE *hf = fopen(canon, "re");
    if (!hf) return -1;
    char line[4096];
    while (fgets(line, sizeof line, hf)) {
        if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4)) {
            int is_uid = line[0] == 'U';
            u32 id[4];   /* real, effective, saved-set, filesystem */
            if (sscanf(line + 4, "%u %u %u %u",
                       &id[0], &id[1], &id[2], &id[3]) == 4) {
                for (int i = 0; i < 4; i++)
                    id[i] = is_uid ? remap_uid(m, id[i]) : remap_gid(m, id[i]);
                dprintf(fd, "%s\t%u\t%u\t%u\t%u\n", is_uid ? "Uid:" : "Gid:",
                        id[0], id[1], id[2], id[3]);
                continue;
            }
        } else if (!strncmp(line, "Groups:", 7)) {
            dprintf(fd, "Groups:");
            const char *p = line + 7;
            u32 g; int adv;
            while (sscanf(p, " %u%n", &g, &adv) == 1) {
                dprintf(fd, " %u", remap_gid(m, g));
                p += adv;
            }
            dprintf(fd, "\n");
            continue;
        }
        size_t len = strlen(line);
        ssize_t w = write(fd, line, len); (void)w;
    }
    fclose(hf);
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
     * non-guest PID misses here and, under the hidden view, path.c has already
     * routed it to an ENOENT. */
    s32 opid;
    if (proc_other_cmdline(canon, &opid) && opid != (s32)getpid()) {
        char cbuf[PROCTAB_CMDLINE];
        u32 clen = 0;
        if (!proctab_cmdline(opid, cbuf, &clen)) return 0;
        if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
        if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }
        int fd = synth_memfd();
        if (fd < 0) return 0;
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
        if (fd < 0) return 0;
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
     * m->environ / m->auxv via self_tail below). Off the registry (non-guest /
     * raced) it falls through to the host path's ENOENT rather than leaking the
     * emulator's own copy (gdb reads the inferior's auxv for AT_HWCAP; the host
     * file's wrong-ISA value sends it chasing pauth/SVE regsets the ptrace shim
     * doesn't have). */
    s32 epid;
    const char *etail = proc_other_tail(canon, &epid);
    if (etail && epid != (s32)getpid() &&
        (!strcmp(etail, "environ") || !strcmp(etail, "auxv"))) {
        if (!proctab_has(epid)) return 0;
        if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
        if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }
        struct ProcSnap snap;
        if (!proctab_get(epid, &snap)) return 0;
        const char *buf = snap.env;
        u32 blen = snap.env_len;
        if (etail[0] == 'a') { buf = snap.auxv; blen = snap.auxv_len; }
        int fd = synth_memfd();
        if (fd < 0) return 0;
        if (blen) { ssize_t w = write(fd, buf, blen); (void)w; }
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        *ret = fd;
        return 1;
    }

    /* /proc/<pid>/status under --fake-id: the host file's Uid:/Gid:/Groups:
     * lines carry the real invoking uid, but ps/top read them to name the user.
     * Rewrite those lines through the fake-id remap. Off fake-id the host file
     * is already correct and passes through. A static snapshot (uid never
     * changes), so no pf_track refresh entry is needed. */
    if (m->fake_id && status_target(canon)) {
        if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
        if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }
        int fd = synth_memfd();
        if (fd < 0) return 0;                       /* no memfd: passthrough */
        if (put_status(fd, m, canon) < 0) { close(fd); return 0; }
        lseek(fd, 0, SEEK_SET);
        if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
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
    case PF_UIDMAP: case PF_GIDMAP: case PF_SETGROUPS:
                        put_idmap(fd, m, kind); break;
    }
    (void)wr;   /* memfd write: no short/failed writes short of ENOMEM */
    lseek(fd, 0, SEEK_SET);
    if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);   /* guest didn't ask */
    if (kind == PF_LOADAVG || kind == PF_UPTIME || kind == PF_STAT || writable)
        pf_track(m, fd, kind);   /* time-varying, or written through */
    *ret = fd;
    return 1;
}
