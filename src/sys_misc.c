/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Miscellaneous syscalls: randomness, rlimits, sysinfo, futex basics. */
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "sys.h"

/* Guest GRND_* values (identical on every architecture). Guest literals, not
 * host macros: an old host libc has no GRND_INSECURE to borrow. */
#define G_GRND_NONBLOCK 0x1
#define G_GRND_RANDOM   0x2
#define G_GRND_INSECURE 0x4

SYSDEF(getrandom) {
    size_t len = (size_t)a1;
    unsigned flags = (unsigned)a2;
    if (len > 65536) len = 65536;
    u8 buf[65536];
    if (!getenv("A64_GETRANDOM_FORCE_DEV")) {
        ssize_t n = syscall(SYS_getrandom, buf, len, flags);
        if (n >= 0) {
            if (copy_to_guest(c, a0, buf, (size_t)n) < 0)
                return (u64)(s64)-EFAULT;
            return (u64)n;
        }
        if (errno != ENOSYS) return host_err();
    }
    /* The host kernel predates getrandom(2) (< 3.17 -- Android 7 devices run
     * 3.x), or a seccomp filter blocked it (the SIGSYS net answers ENOSYS).
     * The guest ABI still has the syscall: uname presents a modern kernel,
     * and OpenSSL's seeding *skips* its /dev/urandom fallback on anything
     * >= 4.8 precisely because getrandom must exist there -- so forwarding
     * the host's ENOSYS leaves TLS software with no entropy source at all
     * (apk update died dereferencing the NULL SSL object that came of it).
     * Serve the call from the host's random devices, with the kernel's own
     * flag rules. */
    if (flags & ~(G_GRND_NONBLOCK | G_GRND_RANDOM | G_GRND_INSECURE))
        return (u64)(s64)-EINVAL;
    if ((flags & (G_GRND_RANDOM | G_GRND_INSECURE)) ==
        (G_GRND_RANDOM | G_GRND_INSECURE))
        return (u64)(s64)-EINVAL;
    /* GRND_INSECURE asks for the urandom source without the seeded wait; a
     * pre-4.8 host never blocks urandom reads anyway, so both flavors read
     * urandom. GRND_RANDOM keeps its own device and its blocking rules. */
    int rnd = (flags & G_GRND_RANDOM) != 0;
    int fd = open(rnd ? "/dev/random" : "/dev/urandom",
                  O_RDONLY | O_CLOEXEC |
                      ((flags & G_GRND_NONBLOCK) ? O_NONBLOCK : 0));
    if (fd < 0) return host_err();
    size_t got = 0;
    for (;;) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r > 0) {
            got += (size_t)r;
            /* The random source is entropy-limited and may return short, as
             * getrandom(GRND_RANDOM) does; urandom serves the full request. */
            if (rnd || got >= len) break;
        } else if (r < 0 && errno == EINTR) {
            if (got) break;                 /* getrandom returns what it has */
        } else {
            if (!got) {
                u64 e = r < 0 ? host_err() : 0;   /* len==0 lands here as 0 */
                close(fd);
                return e;
            }
            break;
        }
    }
    close(fd);
    if (copy_to_guest(c, a0, buf, got) < 0) return (u64)(s64)-EFAULT;
    return (u64)got;
}

/* Limits that bound an address space are answered and enforced from the guest's
 * own table and never handed to the host: the host process is the emulator, and
 * capping *it* to what the guest asked for kills the emulator where the guest
 * expected one mmap to fail (see struct Machine's rlim[] for the full story and
 * the Bionic numbers that make it unmissable). Everything else is stored in the
 * table too -- so the guest reads back one coherent set -- and also applied to
 * the host, which is what actually enforces those. */
static int rlim_virtual(int res) {
    return res == G_RLIMIT_AS || res == G_RLIMIT_DATA || res == G_RLIMIT_STACK;
}

/* Seed the guest's table from the host's, once, at startup. Every later change
 * comes through set/prlimit, and fork copies the table with the rest of the
 * Machine while execve leaves it alone -- which is what a kernel does. */
void rlim_init(struct Machine *m) {
    for (int r = 0; r < G_RLIM_NLIMITS; r++) {
        struct rlimit h;
        if (getrlimit(r, &h) == 0) {
            m->rlim[r].rlim_cur = h.rlim_cur == RLIM_INFINITY
                                      ? G_RLIM_INFINITY : (u64)h.rlim_cur;
            m->rlim[r].rlim_max = h.rlim_max == RLIM_INFINITY
                                      ? G_RLIM_INFINITY : (u64)h.rlim_max;
        } else {
            m->rlim[r].rlim_cur = m->rlim[r].rlim_max = G_RLIM_INFINITY;
        }
    }
}

/* Apply one guest limit, table first and host after where the host is the one
 * enforcing it. Returns 0 or -errno; the table is left untouched on refusal. */
static s64 rlim_set(struct Machine *m, int res, const GRlimit *g) {
    if (res < 0 || res >= G_RLIM_NLIMITS) return -EINVAL;
    if (g->rlim_cur > g->rlim_max) return -EINVAL;
    /* Only privilege can raise a hard limit, and the guest's fake root is not
     * privilege the host would honour -- so the ceiling is the one it has. */
    if (g->rlim_max > m->rlim[res].rlim_max) return -EPERM;
    if (!rlim_virtual(res)) {
        struct rlimit h = {
            g->rlim_cur == G_RLIM_INFINITY ? RLIM_INFINITY : (rlim_t)g->rlim_cur,
            g->rlim_max == G_RLIM_INFINITY ? RLIM_INFINITY : (rlim_t)g->rlim_max,
        };
        if (setrlimit(res, &h) < 0) return -errno;
    }
    m->rlim[res] = *g;
    return 0;
}

SYSDEF(getrlimit) {
    int res = (int)a0;
    if (res < 0 || res >= G_RLIM_NLIMITS) return (u64)(s64)-EINVAL;
    return copy_to_guest(c, a1, &c->m->rlim[res], sizeof(GRlimit)) < 0
               ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(setrlimit) {
    GRlimit g;
    if ((int)a0 < 0 || (int)a0 >= G_RLIM_NLIMITS) return (u64)(s64)-EINVAL;
    if (copy_from_guest(c, &g, a1, sizeof g) < 0) return (u64)(s64)-EFAULT;
    s64 e = rlim_set(c->m, (int)a0, &g);
    return e < 0 ? (u64)e : 0;
}

SYSDEF(prlimit64) {
    pid_t pid = (pid_t)(s32)a0;
    int res = (int)a1;
    struct Machine *m = c->m;
    if (res < 0 || res >= G_RLIM_NLIMITS) return (u64)(s64)-EINVAL;
    /* pid 0 and our own pid mean this process. Another guest process's limits
     * would have to come from its Machine, which is not shared -- report the
     * kernel's answer for a pid we cannot act on rather than silently applying
     * the change here, which is what handing this to the host used to do. */
    if (pid != 0 && pid != (pid_t)getpid())
        return (u64)(s64)(proctab_has((s32)pid) ? -EPERM : -ESRCH);
    GRlimit old = m->rlim[res];
    if (a2) {
        GRlimit g;
        if (copy_from_guest(c, &g, a2, sizeof g) < 0) return (u64)(s64)-EFAULT;
        s64 e = rlim_set(m, res, &g);
        if (e < 0) return (u64)e;
    }
    if (a3 && copy_to_guest(c, a3, &old, sizeof old) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(sysinfo) {
    struct sysinfo h;
    if (sysinfo(&h) < 0) return host_err();
    /* guest struct sysinfo (arm64/LP64) is exactly 112 bytes: s64 uptime,
     * u64 loads[3] + 6 mem fields, u16 procs/pad, then (after 4 bytes of
     * alignment padding for the u64s) totalhigh/freehigh, u32 mem_unit, and a
     * zero-length _f[] tail. An earlier version carried a bogus trailing u8
     * f[8], inflating the struct to 120 bytes; copy_to_guest then wrote 8 bytes
     * past the guest's stack buffer, smashing its stack canary. */
    struct {
        s64 uptime;
        u64 loads[3];
        u64 totalram, freeram, sharedram, bufferram;
        u64 totalswap, freeswap;
        u16 procs, pad;
        u32 pad2;
        u64 totalhigh, freehigh;
        u32 mem_unit;
        u32 pad3;   /* explicit tail pad: ILP32 hosts align u64 to 4 */
    } g;
    _Static_assert(sizeof g == 112, "guest struct sysinfo must be 112 bytes");
    memset(&g, 0, sizeof g);
    g.uptime = h.uptime;
    for (int i = 0; i < 3; i++) g.loads[i] = h.loads[i];
    g.totalram = h.totalram; g.freeram = h.freeram;
    g.sharedram = h.sharedram; g.bufferram = h.bufferram;
    g.totalswap = h.totalswap; g.freeswap = h.freeswap;
    g.procs = h.procs;
    g.mem_unit = h.mem_unit;
    return copy_to_guest(c, a0, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* futex: guest threads are host threads on one shared mapping, so waits and
 * wakes pass through on the translated address. Argument 4 is a timespec for
 * the waiting ops but a plain count (val2) for the requeue/wake-op family,
 * whose argument 5 is a second futex word; both must be forwarded. Dropping
 * them turns FUTEX_REQUEUE into a no-op, and musl's condvar broadcast wakes
 * only the first waiter directly -- every later one is handed off by
 * requeueing it onto the mutex (unlock_requeue), so those threads sleep
 * forever (observed as node hanging at exit joining its V8 worker pool). */
SYSDEF(futex) {
    int op = (int)a1 & 127;
    void *uaddr = mem_host_ptr(c, a0, 4, ACC_READ);
    if (!uaddr) return (u64)(s64)-EFAULT;
    /* The kernel's own futex_cmd_has_timeout() list. LOCK_PI2 belongs here too:
     * left out, its timeout pointer took the val2 path below and reached the
     * kernel truncated, so glibc's pthread_mutex_clocklock on a PI mutex got
     * EFAULT (it only falls back on ENOSYS). */
    int takes_ts = op == 0 /*WAIT*/ || op == 6 /*LOCK_PI*/ ||
                   op == 9 /*WAIT_BITSET*/ || op == 11 /*WAIT_REQUEUE_PI*/ ||
                   op == 13 /*LOCK_PI2*/;
    int takes_u2 = op == 3 /*REQUEUE*/ || op == 4 /*CMP_REQUEUE*/ ||
                   op == 5 /*WAKE_OP*/ || op == 11 ||
                   op == 12 /*CMP_REQUEUE_PI*/;
    GTimespec gts;
    int have_ts = 0;
    if (takes_ts && a3) {
        if (copy_from_guest(c, &gts, a3, sizeof gts) < 0) return (u64)(s64)-EFAULT;
        have_ts = 1;
    }
    void *uaddr2 = NULL;
    if (takes_u2) {
        /* WAKE_OP writes through uaddr2; the requeue ops only key on it. */
        uaddr2 = mem_host_ptr(c, a4, 4, op == 5 ? ACC_WRITE : ACC_READ);
        if (!uaddr2) return (u64)(s64)-EFAULT;
    }
    long r;
    if (have_ts) {
        /* Only plain FUTEX_WAIT takes its timeout as a duration; every other op
         * that takes one (WAIT_BITSET, the PI family, WAIT_REQUEUE_PI) takes an
         * absolute deadline, which needs no adjusting when we restart the call.
         * A duration does: it must not start over (syscall.c).
         *
         * Only when there is something to subtract, though -- the guest's
         * timespec holds 64-bit seconds, and a 32-bit host's time_t would
         * truncate them on the way out to a host struct timespec and back. */
        if (op == 0) {
            if (g_tls.sc_waited_ns) {
                struct timespec rel = { (time_t)gts.tv_sec, (long)gts.tv_nsec };
                syscall_wait_begin(&rel);
                gts.tv_sec = (s64)rel.tv_sec;
                gts.tv_nsec = (s64)rel.tv_nsec;
            } else {
                syscall_wait_begin(NULL);   /* nothing to shrink: only start the clock */
            }
        }
        /* GTimespec is exactly struct __kernel_timespec, so the guest's timeout
         * needs no conversion -- but on a 32-bit host it must not go to plain
         * SYS_futex, whose timespec is two 32-bit words there. It would read
         * tv_sec's low half as the seconds and its *high* half (always 0) as the
         * nanoseconds, so every sub-second wait returned ETIMEDOUT at once and
         * timed condvar/semaphore waits busy-spun. */
#if defined(SYS_futex_time64) && __SIZEOF_LONG__ == 4
        r = syscall(SYS_futex_time64, uaddr, (int)a1, (u32)a2, &gts, uaddr2, (u32)a5);
        if (r < 0 && errno == ENOSYS) {   /* kernel older than 5.1 */
            struct { s32 tv_sec, tv_nsec; } t32 =
                { (s32)gts.tv_sec, (s32)gts.tv_nsec };
            r = syscall(SYS_futex, uaddr, (int)a1, (u32)a2, &t32, uaddr2, (u32)a5);
        }
#else
        r = syscall(SYS_futex, uaddr, (int)a1, (u32)a2, &gts, uaddr2, (u32)a5);
#endif
    } else {
        /* val2 (wake/requeue count) for the ops that take one, else no timeout. */
        unsigned long arg3 = takes_ts ? 0 : (u32)a3;
        r = syscall(SYS_futex, uaddr, (int)a1, (u32)a2, arg3, uaddr2, (u32)a5);
    }
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(membarrier) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)-ENOSYS;
}

SYSDEF(getcpu) {
    u32 zero = 0;
    if (a0 && copy_to_guest(c, a0, &zero, 4) < 0) return (u64)(s64)-EFAULT;
    if (a1 && copy_to_guest(c, a1, &zero, 4) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

/* ---- memfd_create fallback tier ------------------------------------------
 * A host kernel without memfd_create (< 3.17: the Android 7 devices) answers
 * ENOSYS, but the guest ABI promises the syscall -- apk-tools 3 writes every
 * install trigger into a sealed memfd and execs it. The tier serves the call
 * from an unlinked file in the session's tmpfs backing dir (a64_mfdfile) and
 * moves what the host cannot hold -- the seals, which live on the inode and
 * must survive execve, fork and SCM_RIGHTS -- into the broker's seal
 * registry (proctab.c), which also pins the inode with a daemon-held dup so
 * its number cannot recycle into an unrelated file under a live entry.
 *
 * Enforcement is the emulator's job too (the backing file is sealless to the
 * host): the write family, ftruncate, fallocate and mmap ask this cache
 * first. Classification is free for ordinary fds: the ONLY ways a tier
 * memfd's fd number can appear in a process are memfd_create itself, an
 * SCM_RIGHTS receipt, and dup -- each marks the slot, everything else stays
 * class 0 and never pays a lookup (guest execve reloads in-process, so the
 * cache survives it; the CLOEXEC walk closes through mfd_track_close).
 * Seals only ever accumulate, so a cached RESTRICTIVE bit is trusted after
 * an identity fstat, while a permissive answer re-asks the broker -- another
 * process may have sealed the inode since. A64_MEMFD_FORCE_FILE forces the
 * tier on any host, which is how it is differentially tested against the
 * qemu oracle on machines whose kernel has the real thing. */
#define G_MFD_CLOEXEC        0x1u
#define G_MFD_ALLOW_SEALING  0x2u
#define G_MFD_HUGETLB        0x4u
#define G_MFD_NOEXEC_SEAL    0x8u
#define G_MFD_EXEC           0x10u

#define MFDC_N 1024
static u8  mfdc_cls[MFDC_N];      /* 0 plain (default), 1 tier memfd, 2 check */
static u64 mfdc_dev[MFDC_N], mfdc_ino[MFDC_N];
static u32 mfdc_hint[MFDC_N];     /* seal bits already seen (monotonic) */
static int mfdc_any;              /* some slot ever left class 0 */

void mfd_track_create(int fd, u64 dev, u64 ino) {
    mfdc_any = 1;
    if (fd < 0 || fd >= MFDC_N) return;
    mfdc_cls[fd] = 1; mfdc_dev[fd] = dev; mfdc_ino[fd] = ino; mfdc_hint[fd] = 0;
}
void mfd_track_recv(int fd) {
    mfdc_any = 1;
    if (fd < 0 || fd >= MFDC_N) return;
    mfdc_cls[fd] = 2; mfdc_hint[fd] = 0;
}
void mfd_track_dup(int oldfd, int newfd) {
    if (!mfdc_any || newfd < 0 || newfd >= MFDC_N) return;
    if (oldfd < 0 || oldfd >= MFDC_N) { mfdc_cls[newfd] = 2; mfdc_hint[newfd] = 0; return; }
    mfdc_cls[newfd] = mfdc_cls[oldfd]; mfdc_dev[newfd] = mfdc_dev[oldfd];
    mfdc_ino[newfd] = mfdc_ino[oldfd]; mfdc_hint[newfd] = mfdc_hint[oldfd];
}
void mfd_track_close(int fd) {
    if (!mfdc_any || fd < 0 || fd >= MFDC_N) return;
    mfdc_cls[fd] = 0; mfdc_hint[fd] = 0;
}

/* fd -> current seals (>= 0) with backing identity, or -1 if not a tier
 * memfd. One fstat when the slot claims (or might claim) memfd-hood; one
 * broker exchange when the answer needs the CURRENT mask. */
s32 mfd_resolve(CPU *c, int fd, u64 *dev, u64 *ino, char *name_out) {
    if (!mfdc_any || fd < 0) return -1;
    int idx = fd < MFDC_N ? fd : -1;
    if (idx >= 0 && mfdc_cls[idx] == 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        if (idx >= 0) mfdc_cls[idx] = 0;
        return -1;
    }
    if (idx >= 0 && mfdc_cls[idx] == 1 &&
        (mfdc_dev[idx] != (u64)st.st_dev || mfdc_ino[idx] != (u64)st.st_ino))
        mfdc_cls[idx] = 2;               /* number reused behind our back */
    s32 seals = mfdbroker_lookup(c->m, (u64)st.st_dev, (u64)st.st_ino, name_out);
    if (seals < 0) {
        if (idx >= 0) mfdc_cls[idx] = 0;
        return -1;
    }
    if (idx >= 0) {
        mfdc_cls[idx] = 1;
        mfdc_dev[idx] = (u64)st.st_dev; mfdc_ino[idx] = (u64)st.st_ino;
        mfdc_hint[idx] |= (u32)seals;
    }
    if (dev) *dev = (u64)st.st_dev;
    if (ino) *ino = (u64)st.st_ino;
    return seals;
}

int mfd_write_denied(CPU *c, int fd) {
    if (!mfdc_any || fd < 0) return 0;
    if (fd < MFDC_N) {
        if (mfdc_cls[fd] == 0) return 0;             /* the whole fast path */
        if (mfdc_cls[fd] == 1 &&
            (mfdc_hint[fd] & (G_F_SEAL_WRITE | G_F_SEAL_FUTURE_WRITE))) {
            struct stat st;                          /* identity, not seals */
            if (fstat(fd, &st) == 0 && (u64)st.st_dev == mfdc_dev[fd] &&
                (u64)st.st_ino == mfdc_ino[fd])
                return 1;
        }
    }
    s32 seals = mfd_resolve(c, fd, NULL, NULL, NULL);
    return seals >= 0 && (seals & (G_F_SEAL_WRITE | G_F_SEAL_FUTURE_WRITE));
}

int mfd_ftruncate_denied(CPU *c, int fd, u64 newsize) {
    if (!mfdc_any || fd < 0) return 0;
    if (fd < MFDC_N && mfdc_cls[fd] == 0) return 0;
    s32 seals = mfd_resolve(c, fd, NULL, NULL, NULL);
    if (seals < 0 || !(seals & (G_F_SEAL_SHRINK | G_F_SEAL_GROW))) return 0;
    struct stat st;
    if (fstat(fd, &st) < 0) return 0;
    if ((seals & G_F_SEAL_SHRINK) && newsize < (u64)st.st_size) return 1;
    if ((seals & G_F_SEAL_GROW) && newsize > (u64)st.st_size) return 1;
    return 0;
}

int mfd_fallocate_denied(CPU *c, int fd, int mode, u64 off, u64 len) {
    if (!mfdc_any || fd < 0) return 0;
    if (fd < MFDC_N && mfdc_cls[fd] == 0) return 0;
    s32 seals = mfd_resolve(c, fd, NULL, NULL, NULL);
    if (seals < 0) return 0;
    if ((mode & 0x2 /* FALLOC_FL_PUNCH_HOLE */) &&
        (seals & (G_F_SEAL_WRITE | G_F_SEAL_FUTURE_WRITE))) return 1;
    if ((seals & G_F_SEAL_GROW) && !(mode & 0x1 /* KEEP_SIZE */)) {
        struct stat st;
        if (fstat(fd, &st) == 0 && off + len > (u64)st.st_size) return 1;
    }
    return 0;
}

/* F_ADD_SEALS / F_GET_SEALS for a tier memfd; anything else falls through to
 * the host (a native memfd gets the kernel's own answer, and on the old host
 * a plain fd keeps its historical EINVAL). */
int mfd_fcntl(CPU *c, int fd, int cmd, u64 arg, u64 *ret) {
    if (cmd != 1033 /* F_ADD_SEALS */ && cmd != 1034 /* F_GET_SEALS */)
        return 0;
    u64 dev, ino;
    s32 seals = mfd_resolve(c, fd, &dev, &ino, NULL);
    if (seals < 0) return 0;
    if (cmd == 1034) { *ret = (u64)(u32)seals; return 1; }
    u32 mask = (u32)arg;
    if (mask & ~G_F_SEAL_ALL) { *ret = (u64)(s64)-EINVAL; return 1; }
    s32 rc = mfdbroker_addseals(c->m, dev, ino, mask);
    if (rc == 0 && fd < MFDC_N && mfdc_cls[fd] == 1) mfdc_hint[fd] |= mask;
    *ret = rc < 0 ? (u64)(s64)rc : 0;
    return 1;
}

/* Guest readlink of a /proc fd entry whose target is one of the tier's
 * backing files: the real target would leak a host path the guest has no
 * business seeing (and none it could use -- the file is unlinked). Present
 * the kernel's own spelling instead. The basename test keeps every ordinary
 * link out of the stat+lookup. */
int mfd_link_rewrite(CPU *c, const char *hostlink, char *buf) {
    if (!strstr(buf, "/a64-memfd.")) return 0;
    struct stat st;
    if (stat(hostlink, &st) < 0) return 0;
    char name[MFD_NAME_MAX];
    if (mfdbroker_lookup(c->m, (u64)st.st_dev, (u64)st.st_ino, name) < 0)
        return 0;
    snprintf(buf, PATH_MAX, "/memfd:%s (deleted)", name);
    return 1;
}

SYSDEF(memfd_create) {
    /* MFD_* flag values are arch-uniform, the fd is 1:1. The kernel caps the
     * name at 249 chars, so a string that overflows the buffer would be its
     * EINVAL anyway. Bionic only declares the wrapper on newer API levels;
     * the raw syscall is on the Android 8 seccomp allow-list. */
    char name[512];
    long n = copy_str_from_guest(c, name, a0, sizeof name);
    if (n == -ENAMETOOLONG) return (u64)(s64)-EINVAL;
    if (n < 0) return (u64)(s64)n;
    int r = -1;
    if (!getenv("A64_MEMFD_FORCE_FILE")) {
#if defined(__BIONIC__) && defined(SYS_memfd_create)
        r = (int)syscall(SYS_memfd_create, name, (unsigned)a1);
#else
        r = memfd_create(name, (unsigned)a1);
#endif
        if (r >= 0) {
            struct stat st;                  /* class the native fd too: its */
            if (fstat(r, &st) == 0)          /* number may shadow a stale    */
                mfd_track_close(r);          /* tier slot from a reuse       */
            return (u64)r;
        }
        if (errno != ENOSYS) return host_err();
    }
    /* The tier (see the block comment above). Kernel flag rules first. */
    unsigned gf = (unsigned)a1;
    if (n - 1 > 249) return (u64)(s64)-EINVAL;
    if (gf & ~(G_MFD_CLOEXEC | G_MFD_ALLOW_SEALING | G_MFD_HUGETLB |
               G_MFD_NOEXEC_SEAL | G_MFD_EXEC))
        return (u64)(s64)-EINVAL;
    if ((gf & G_MFD_NOEXEC_SEAL) && (gf & G_MFD_EXEC)) return (u64)(s64)-EINVAL;
    if (gf & G_MFD_HUGETLB)     /* nothing to build hugetlb from on this host */
        return (u64)(s64)-EINVAL;
    u32 seals0 = 0;
    unsigned eff = gf;
    if (gf & G_MFD_NOEXEC_SEAL) {           /* implies sealing, per the kernel */
        eff |= G_MFD_ALLOW_SEALING;
        seals0 |= G_F_SEAL_EXEC;
    }
    if (!(eff & G_MFD_ALLOW_SEALING)) seals0 |= G_F_SEAL_SEAL;
    int fd = a64_mfdfile((gf & G_MFD_CLOEXEC) != 0);
    if (fd < 0) return (u64)(s64)-ENOMEM;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return (u64)(s64)-ENOMEM; }
    if (mfdbroker_reg(c->m, fd, seals0, name) < 0) {
        close(fd);                /* no registry, no seals: fail loud rather
                                   * than hand out a memfd that forgets them */
        return (u64)(s64)-ENOMEM;
    }
    mfd_track_create(fd, (u64)st.st_dev, (u64)st.st_ino);
    return (u64)fd;
}

SYSDEF(sethostname) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)-EPERM;
}

SYSDEF(syslog) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return 0;
}

SYSDEF(personality) {
    (void)c; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    static unsigned cur = 0;
    if ((u32)a0 == 0xffffffff) return cur;
    unsigned old = cur;
    cur = (unsigned)a0;
    return old;
}

/* Capability-set versions, as the kernel names them. */
#define G_CAP_VER_1 0x19980330u
#define G_CAP_VER_2 0x20071026u
#define G_CAP_VER_3 0x20080522u   /* what the kernel prefers, and reports */

SYSDEF(capget) {
    /* header {version, pid}. Report the full capability set for fake-root,
     * otherwise none. */
    struct { u32 version; s32 pid; } hdr;
    if (copy_from_guest(c, &hdr, a0, sizeof hdr) < 0) return (u64)(s64)-EFAULT;

    /* Version negotiation, as cap_validate_magic does. A version the kernel
     * does not know is answered by writing the preferred one *back into the
     * header*, and libcap asks exactly that way at startup: it calls capget
     * with a deliberately bogus version and a NULL data pointer purely to read
     * the answer out of the header. Ignoring the field left that probe seeing
     * its own zero, so libcap could not tell which layout to use. The kernel
     * reports success for the NULL-data probe and EINVAL when data was really
     * wanted. */
    unsigned nsets;
    switch (hdr.version) {
        case G_CAP_VER_1: nsets = 1; break;
        case G_CAP_VER_2:
        case G_CAP_VER_3: nsets = 2; break;
        default: {
            u32 pref = G_CAP_VER_3;
            if (copy_to_guest(c, a0, &pref, 4) < 0) return (u64)(s64)-EFAULT;
            return a1 ? (u64)(s64)-EINVAL : 0;
        }
    }

    /* The header's pid was ignored outright, so asking about a process that
     * does not exist reported a capability set for it. Guest pids are host
     * pids, so the host can answer whether it is there; a pid we exist but may
     * not signal comes back EPERM, which is not ESRCH and not our concern. */
    if (hdr.pid < 0) return (u64)(s64)-EINVAL;
    if (hdr.pid && hdr.pid != getpid() &&
        kill((pid_t)hdr.pid, 0) < 0 && errno == ESRCH)
        return (u64)(s64)-ESRCH;

    if (a1) {
        struct { u32 eff, perm, inh; } d[2];
        u32 all = (c->m->fake_id && c->m->cred.euid == 0) ? 0xffffffffu : 0;
        for (int i = 0; i < 2; i++) { d[i].eff = all; d[i].perm = all; d[i].inh = 0; }
        if (copy_to_guest(c, a1, d, sizeof(d[0]) * (size_t)nsets) < 0)
            return (u64)(s64)-EFAULT;
    }
    return 0;
}

SYSDEF(capset) {
    /* Accept capability changes under fake-root; otherwise deny like the host. */
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (c->m->fake_id && c->m->cred.euid == 0) return 0;
    return (u64)(s64)-EPERM;
}

/* ---- kernel key management. Passes through to the host keyring (the guest
 * process is a host process, so its session keyring works); pointer arguments
 * are bounced through host buffers per operation. Used by PAM (pam_keyinit)
 * for `su -l` and by keyutils.
 *
 * On Bionic (Termux) the Android 8+ app seccomp filter blocks the whole
 * family — a forwarded call raises SIGSYS instead of failing. Report the
 * facility as absent (-ENOSYS), like a kernel built without CONFIG_KEYS;
 * guests degrade the same way. A64_KEYRING_ENOSYS compile-checks that branch
 * on the glibc dev host. ---- */
#if defined(__BIONIC__) || defined(A64_KEYRING_ENOSYS)
#define KEYRING_ENOSYS 1
#endif

#define G_KEYCTL_JOIN_SESSION_KEYRING 1
#define G_KEYCTL_UPDATE               2
#define G_KEYCTL_DESCRIBE             6
#define G_KEYCTL_READ                 11
#define G_KEYCTL_INSTANTIATE          12
#define G_KEYCTL_GET_SECURITY         17
#define G_KEYCTL_CAPABILITIES         30

SYSDEF(keyctl) {
#ifdef KEYRING_ENOSYS
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)-ENOSYS;
#else
    long op = (long)a0;
    switch (op) {
        case G_KEYCTL_JOIN_SESSION_KEYRING: {   /* (name-or-NULL) */
            if (!a1) { long r = syscall(SYS_keyctl, op, (char *)NULL); return r < 0 ? host_err() : (u64)r; }
            char name[256];
            if (copy_str_from_guest(c, name, a1, sizeof name) < 0) return (u64)(s64)-EFAULT;
            long r = syscall(SYS_keyctl, op, name);
            return r < 0 ? host_err() : (u64)r;
        }
        case G_KEYCTL_DESCRIBE:      /* (key, char *buf, size_t buflen) */
        case G_KEYCTL_READ:
        case G_KEYCTL_GET_SECURITY: {
            u64 bufva = a2, buflen = a3;
            if (buflen > (1u << 20)) buflen = 1u << 20;
            u8 *buf = malloc(buflen ? (size_t)buflen : 1);
            if (!buf) return (u64)(s64)-ENOMEM;
            long r = syscall(SYS_keyctl, op, (long)a1, buf, (size_t)buflen);
            if (r < 0) { free(buf); return host_err(); }
            size_t out = (size_t)r < buflen ? (size_t)r : (size_t)buflen;
            if (bufva && out && copy_to_guest(c, bufva, buf, out) < 0) { free(buf); return (u64)(s64)-EFAULT; }
            free(buf);
            return (u64)r;
        }
        case G_KEYCTL_CAPABILITIES: {   /* (char *buf, size_t buflen) */
            u64 buflen = a2;
            if (buflen > 256) buflen = 256;
            u8 buf[256] = {0};
            long r = syscall(SYS_keyctl, op, buf, (size_t)buflen);
            if (r < 0) return host_err();
            size_t out = (size_t)r < buflen ? (size_t)r : (size_t)buflen;
            if (a1 && out && copy_to_guest(c, a1, buf, out) < 0) return (u64)(s64)-EFAULT;
            return (u64)r;
        }
        default: {   /* integer-only operations (GET_KEYRING_ID/REVOKE/LINK/...) */
            long r = syscall(SYS_keyctl, op, (long)a1, (long)a2, (long)a3, (long)a4);
            return r < 0 ? host_err() : (u64)r;
        }
    }
#endif
}

SYSDEF(add_key) {   /* (type, desc, payload, plen, keyring) */
#ifdef KEYRING_ENOSYS
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)-ENOSYS;
#else
    char type[64], desc[256];
    if (copy_str_from_guest(c, type, a0, sizeof type) < 0) return (u64)(s64)-EFAULT;
    if (copy_str_from_guest(c, desc, a1, sizeof desc) < 0) return (u64)(s64)-EFAULT;
    size_t plen = (size_t)a3;
    if (plen > (1u << 20)) return (u64)(s64)-EINVAL;
    u8 *pl = NULL;
    if (a2 && plen) {
        pl = malloc(plen);
        if (!pl) return (u64)(s64)-ENOMEM;
        if (copy_from_guest(c, pl, a2, plen) < 0) { free(pl); return (u64)(s64)-EFAULT; }
    }
    (void)a5;
    long r = syscall(SYS_add_key, type, desc, pl, plen, (int)a4);
    free(pl);
    return r < 0 ? host_err() : (u64)r;
#endif
}

SYSDEF(request_key) {   /* (type, desc, callout-or-NULL, keyring) */
#ifdef KEYRING_ENOSYS
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)-ENOSYS;
#else
    char type[64], desc[256], callout[256];
    if (copy_str_from_guest(c, type, a0, sizeof type) < 0) return (u64)(s64)-EFAULT;
    if (copy_str_from_guest(c, desc, a1, sizeof desc) < 0) return (u64)(s64)-EFAULT;
    char *cp = NULL;
    if (a2) {
        if (copy_str_from_guest(c, callout, a2, sizeof callout) < 0) return (u64)(s64)-EFAULT;
        cp = callout;
    }
    (void)a4; (void)a5;
    long r = syscall(SYS_request_key, type, desc, cp, (int)a3);
    return r < 0 ? host_err() : (u64)r;
#endif
}
