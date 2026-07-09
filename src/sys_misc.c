/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Miscellaneous syscalls: randomness, rlimits, sysinfo, futex basics. */
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "sys.h"

SYSDEF(getrandom) {
    size_t len = (size_t)a1;
    if (len > 65536) len = 65536;
    u8 buf[65536];
    ssize_t n = syscall(SYS_getrandom, buf, len, (unsigned)a2);
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

SYSDEF(memfd_create) {
    /* MFD_* flag values are arch-uniform, the fd is 1:1. The kernel caps the
     * name at 249 chars, so a string that overflows the buffer would be its
     * EINVAL anyway. Bionic only declares the wrapper on newer API levels;
     * the raw syscall is on the Android 8 seccomp allow-list. */
    char name[512];
    long n = copy_str_from_guest(c, name, a0, sizeof name);
    if (n == -ENAMETOOLONG) return (u64)(s64)-EINVAL;
    if (n < 0) return (u64)(s64)n;
    int r;
#if defined(__BIONIC__) && defined(SYS_memfd_create)
    r = (int)syscall(SYS_memfd_create, name, (unsigned)a1);
#else
    r = memfd_create(name, (unsigned)a1);
#endif
    return r < 0 ? host_err() : (u64)r;
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
    /* header {version, pid}. Report the full capability set for fake-root,
     * otherwise none. */
    struct { u32 version; s32 pid; } hdr;
    if (copy_from_guest(c, &hdr, a0, sizeof hdr) < 0) return (u64)(s64)-EFAULT;
    if (a1) {
        struct { u32 eff, perm, inh; } d[2];
        u32 all = (c->m->fake_id && c->m->cred.euid == 0) ? 0xffffffffu : 0;
        for (int i = 0; i < 2; i++) { d[i].eff = all; d[i].perm = all; d[i].inh = 0; }
        int n = (hdr.version == 0x19980330) ? 1 : 2;
        if (copy_to_guest(c, a1, d, sizeof(d[0]) * (size_t)n) < 0)
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
