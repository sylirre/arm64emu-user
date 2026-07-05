/* Miscellaneous syscalls: randomness, rlimits, sysinfo, futex basics. */
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "sys.h"

SYSDEF(getrandom) {
    size_t len = (size_t)a1;
    if (len > 65536) len = 65536;
    u8 buf[65536];
    ssize_t n = getrandom(buf, len, (unsigned)a2);
    if (n < 0) return host_err();
    if (copy_to_guest(c, a0, buf, (size_t)n) < 0) return (u64)(s64)-EFAULT;
    return (u64)n;
}

static u64 rlim_out(CPU *c, u64 va, const struct rlimit *h) {
    GRlimit g = {
        h->rlim_cur == RLIM_INFINITY ? ~0ULL : (u64)h->rlim_cur,
        h->rlim_max == RLIM_INFINITY ? ~0ULL : (u64)h->rlim_max,
    };
    return copy_to_guest(c, va, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(getrlimit) {
    struct rlimit h;
    if (getrlimit((int)a0, &h) < 0) return host_err();
    return rlim_out(c, a1, &h);
}

SYSDEF(setrlimit) {
    GRlimit g;
    if (copy_from_guest(c, &g, a1, sizeof g) < 0) return (u64)(s64)-EFAULT;
    struct rlimit h = {
        g.rlim_cur == ~0ULL ? RLIM_INFINITY : (rlim_t)g.rlim_cur,
        g.rlim_max == ~0ULL ? RLIM_INFINITY : (rlim_t)g.rlim_max,
    };
    return setrlimit((int)a0, &h) < 0 ? host_err() : 0;
}

SYSDEF(prlimit64) {
    pid_t pid = (pid_t)(s32)a0;
    struct rlimit nh, oh, *nhp = NULL;
    if (a2) {
        GRlimit g;
        if (copy_from_guest(c, &g, a2, sizeof g) < 0) return (u64)(s64)-EFAULT;
        nh.rlim_cur = g.rlim_cur == ~0ULL ? RLIM_INFINITY : (rlim_t)g.rlim_cur;
        nh.rlim_max = g.rlim_max == ~0ULL ? RLIM_INFINITY : (rlim_t)g.rlim_max;
        nhp = &nh;
    }
    if (prlimit(pid, (int)a1, nhp, a3 ? &oh : NULL) < 0) return host_err();
    if (a3) return rlim_out(c, a3, &oh);
    return 0;
}

SYSDEF(sysinfo) {
    struct sysinfo h;
    if (sysinfo(&h) < 0) return host_err();
    /* guest struct sysinfo (LP64): 4 s64, then loads/mem in u64, u16 procs... */
    struct {
        s64 uptime;
        u64 loads[3];
        u64 totalram, freeram, sharedram, bufferram;
        u64 totalswap, freeswap;
        u16 procs, pad;
        u32 pad2;
        u64 totalhigh, freehigh;
        u32 mem_unit;
        u8 f[8];
    } g;
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

/* futex: without CLONE_VM threads every guest futex word is process-private,
 * so WAIT can only be satisfied by a signal/timeout and WAKE finds no waiters.
 * Pass through to the host on the translated address: correct for the
 * single-threaded milestones and already right for M6 shared memory. */
SYSDEF(futex) {
    int op = (int)a1 & 127;
    void *uaddr = mem_host_ptr(c, a0, 4, ACC_READ);
    if (!uaddr) return (u64)(s64)-EFAULT;
    struct timespec ts, *tsp = NULL;
    if ((op == 0 /*WAIT*/ || op == 9 /*WAIT_BITSET*/) && a3) {
        GTimespec g;
        if (copy_from_guest(c, &g, a3, sizeof g) < 0) return (u64)(s64)-EFAULT;
        ts.tv_sec = (time_t)g.tv_sec;
        ts.tv_nsec = (long)g.tv_nsec;
        tsp = &ts;
    }
    long r = syscall(SYS_futex, uaddr, (int)a1, (u32)a2, tsp,
                     (void *)0, (u32)a5);
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

SYSDEF(capget) {
    /* header {version, pid}; report no capabilities */
    struct { u32 version; s32 pid; } hdr;
    if (copy_from_guest(c, &hdr, a0, sizeof hdr) < 0) return (u64)(s64)-EFAULT;
    if (a1) {
        struct { u32 eff, perm, inh; } d[2];
        memset(d, 0, sizeof d);
        int n = (hdr.version == 0x19980330) ? 1 : 2;
        if (copy_to_guest(c, a1, d, sizeof(d[0]) * (size_t)n) < 0)
            return (u64)(s64)-EFAULT;
    }
    return 0;
}
