/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Time syscalls: clockid values and semantics are shared; only the struct
 * widths need marshalling (guest timespec/timeval are 2 x s64). */
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>

#include "sys.h"

static int ts_in(CPU *c, u64 va, struct timespec *ts) {
    GTimespec g;
    if (copy_from_guest(c, &g, va, sizeof g) < 0) return -EFAULT;
    ts->tv_sec = (time_t)g.tv_sec;
    ts->tv_nsec = (long)g.tv_nsec;
    return 0;
}

static int ts_out(CPU *c, u64 va, const struct timespec *ts) {
    GTimespec g = { (s64)ts->tv_sec, (s64)ts->tv_nsec };
    return copy_to_guest(c, va, &g, sizeof g) < 0 ? -EFAULT : 0;
}

SYSDEF(clock_gettime) {
    struct timespec ts;
    if (clock_gettime((clockid_t)a0, &ts) < 0) return host_err();
    int r = ts_out(c, a1, &ts);
    return r < 0 ? (u64)(s64)r : 0;
}

SYSDEF(clock_getres) {
    struct timespec ts;
    if (clock_getres((clockid_t)a0, &ts) < 0) return host_err();
    if (!a1) return 0;
    int r = ts_out(c, a1, &ts);
    return r < 0 ? (u64)(s64)r : 0;
}

SYSDEF(clock_nanosleep) {
    struct timespec req, rem;
    int r = ts_in(c, a2, &req);
    if (r < 0) return (u64)(s64)r;
    /* An absolute deadline survives a restart untouched; a relative one has to
     * be told what an earlier attempt already slept (syscall.c). */
    syscall_wait_begin((a1 & 1 /*TIMER_ABSTIME*/) ? NULL : &req);
    int e = clock_nanosleep((clockid_t)a0, (int)a1, &req, &rem);
    if (e) {
        if (e == EINTR && a3 && !(a1 & 1 /*TIMER_ABSTIME*/)) ts_out(c, a3, &rem);
        return (u64)(s64)-e;
    }
    return 0;
}

SYSDEF(nanosleep) {
    struct timespec req, rem;
    int r = ts_in(c, a0, &req);
    if (r < 0) return (u64)(s64)r;
    syscall_wait_begin(&req);   /* a restart must not sleep the whole span again */
    if (nanosleep(&req, &rem) < 0) {
        if (errno == EINTR && a1) ts_out(c, a1, &rem);
        return host_err();
    }
    return 0;
}

SYSDEF(gettimeofday) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (a0) {
        GTimeval g = { (s64)tv.tv_sec, (s64)tv.tv_usec };
        if (copy_to_guest(c, a0, &g, sizeof g) < 0) return (u64)(s64)-EFAULT;
    }
    if (a1) {   /* obsolete timezone: zeros */
        s32 tz[2] = {0, 0};
        if (copy_to_guest(c, a1, tz, sizeof tz) < 0) return (u64)(s64)-EFAULT;
    }
    return 0;
}

/* guest struct itimerval: 2 x GTimeval pairs */
SYSDEF(setitimer) {
    struct itimerval nv, ov;
    if (a1) {
        GTimeval g[2];
        if (copy_from_guest(c, g, a1, sizeof g) < 0) return (u64)(s64)-EFAULT;
        nv.it_interval.tv_sec = (time_t)g[0].tv_sec;
        nv.it_interval.tv_usec = (suseconds_t)g[0].tv_usec;
        nv.it_value.tv_sec = (time_t)g[1].tv_sec;
        nv.it_value.tv_usec = (suseconds_t)g[1].tv_usec;
    }
    if (setitimer((int)a0, a1 ? &nv : NULL, a2 ? &ov : NULL) < 0) return host_err();
    if (a2) {
        GTimeval g[2] = {
            { (s64)ov.it_interval.tv_sec, (s64)ov.it_interval.tv_usec },
            { (s64)ov.it_value.tv_sec, (s64)ov.it_value.tv_usec },
        };
        if (copy_to_guest(c, a2, g, sizeof g) < 0) return (u64)(s64)-EFAULT;
    }
    return 0;
}

SYSDEF(getitimer) {
    struct itimerval ov;
    if (getitimer((int)a0, &ov) < 0) return host_err();
    GTimeval g[2] = {
        { (s64)ov.it_interval.tv_sec, (s64)ov.it_interval.tv_usec },
        { (s64)ov.it_value.tv_sec, (s64)ov.it_value.tv_usec },
    };
    return copy_to_guest(c, a1, g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* timerfd: clockids are shared and TFD_NONBLOCK/TFD_CLOEXEC equal
 * O_NONBLOCK/O_CLOEXEC, which are identical on asm-generic and x86 (the
 * eventfd2 reasoning), so flags pass straight through; the fd is 1:1.
 * guest struct itimerspec: 2 x GTimespec {it_interval, it_value}. */
SYSDEF(timerfd_create) {
    int r = timerfd_create((int)(s32)a0, (int)(s32)a1);
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(timerfd_settime) {
    if (!a2) return (u64)(s64)-EFAULT;   /* kernel: new_value is mandatory */
    GTimespec g[2];
    if (copy_from_guest(c, g, a2, sizeof g) < 0) return (u64)(s64)-EFAULT;
    struct itimerspec nv, ov;
    nv.it_interval.tv_sec = (time_t)g[0].tv_sec;
    nv.it_interval.tv_nsec = (long)g[0].tv_nsec;
    nv.it_value.tv_sec = (time_t)g[1].tv_sec;
    nv.it_value.tv_nsec = (long)g[1].tv_nsec;
    if (timerfd_settime((int)a0, (int)(s32)a1, &nv, a3 ? &ov : NULL) < 0)
        return host_err();
    if (a3) {
        GTimespec o[2] = {
            { (s64)ov.it_interval.tv_sec, (s64)ov.it_interval.tv_nsec },
            { (s64)ov.it_value.tv_sec, (s64)ov.it_value.tv_nsec },
        };
        if (copy_to_guest(c, a3, o, sizeof o) < 0) return (u64)(s64)-EFAULT;
    }
    return 0;
}

SYSDEF(timerfd_gettime) {
    struct itimerspec ov;
    if (timerfd_gettime((int)a0, &ov) < 0) return host_err();
    GTimespec g[2] = {
        { (s64)ov.it_interval.tv_sec, (s64)ov.it_interval.tv_nsec },
        { (s64)ov.it_value.tv_sec, (s64)ov.it_value.tv_nsec },
    };
    return copy_to_guest(c, a1, g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* ---- POSIX interval timers (timer_create family) ----
 *
 * Host libc wrappers over a per-process slot table: the guest timer_t is a
 * small slot index, the slot holds the opaque host libc timer_t handle. The
 * table is process state like the fd table -- fork does not inherit POSIX
 * timers (the host already dropped them, the child just clears its inherited
 * copy of the table) and execve deletes them (ours is an in-process reload,
 * so the host timers would otherwise survive into -- and signal -- the new
 * image). Slots are claimed with the usual CAS idiom so guest threads can
 * race timer_create/timer_delete without a lock.
 *
 * Notification passes through: signal numbers are shared, a SIGEV_THREAD_ID
 * tid is the host tid (guest tid == host tid), and the fired signal's
 * SI_TIMER siginfo rides the existing capture ring into the guest frame like
 * any other host-caught signal. The guest's 64-bit sigval does NOT ride the
 * host signal, though: the host timer carries only the slot index in its
 * sival_int, and the capture handler swaps in the slot's stored guest value
 * (ptimer_siginfo) -- an 8-byte guest pointer cannot survive a 32-bit host
 * kernel's 4-byte sigval (the glibc SIGEV_THREAD helper's struct-timer
 * pointer sits at a 39-bit guest VA), and as a bonus the guest's si_timerid
 * becomes the guest timer id on every host. SIGEV_THREAD itself never
 * reaches the syscall level (guest libc implements it in userspace with a
 * helper thread + SIGEV_THREAD_ID) and must never reach the *host* wrapper
 * either, where it would spawn a host helper thread on a junk guest function
 * pointer: anything but SIGNAL/NONE/THREAD_ID is -EINVAL, exactly the
 * kernel's rule. */
#define PTIMER_MAX 64
static struct {
    int state;                /* 0 free, 1 mid-claim, 2 live (atomic) */
    timer_t host;
    u64 gvalue;               /* the guest sigevent's 64-bit sigval */
} g_ptimers[PTIMER_MAX];

/* Capture-time SI_TIMER fixup (host_catcher, so async-signal-safe: plain
 * loads only): the full guest sigval for the timer at `slot`. Returns 1 and
 * fills *val for a live slot, 0 otherwise (raced deletion: the caller keeps
 * the raw host value). */
int ptimer_siginfo(s32 slot, u64 *val) {
    if (slot < 0 || slot >= PTIMER_MAX) return 0;
    if (__atomic_load_n(&g_ptimers[slot].state, __ATOMIC_ACQUIRE) != 2) return 0;
    *val = g_ptimers[slot].gvalue;
    return 1;
}

/* Live-slot lookup for a guest timer id. Returns 0 and fills *ht, or -EINVAL. */
static int ptimer_get(u64 gid, timer_t *ht) {
    if (gid >= PTIMER_MAX) return -EINVAL;
    if (__atomic_load_n(&g_ptimers[gid].state, __ATOMIC_ACQUIRE) != 2)
        return -EINVAL;
    *ht = g_ptimers[gid].host;
    return 0;
}

/* execve: delete the host timers (they must not fire into the new image). */
void ptimers_exec_clear(void) {
    for (int i = 0; i < PTIMER_MAX; i++)
        if (__atomic_load_n(&g_ptimers[i].state, __ATOMIC_ACQUIRE) == 2) {
            timer_delete(g_ptimers[i].host);
            __atomic_store_n(&g_ptimers[i].state, 0, __ATOMIC_RELEASE);
        }
}

/* fork child: the host did not inherit the timers; drop the table copy. */
void ptimers_fork_clear(void) {
    memset(g_ptimers, 0, sizeof g_ptimers);
}

SYSDEF(timer_create) {
    /* Claim the slot first: its index is the guest timer id, and the
     * kernel-default notification (NULL sigevent) carries that id in
     * sival_int, so it must exist before the sigevent is built. */
    int slot = -1;
    for (int i = 0; i < PTIMER_MAX; i++) {
        int free_slot = 0;
        if (__atomic_compare_exchange_n(&g_ptimers[i].state, &free_slot, 1,
                                        false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_RELAXED)) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return (u64)(s64)-EAGAIN;   /* kernel: out of timers */

    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    /* The host sigval carries only the slot index; the capture handler swaps
     * in the guest's full 64-bit value from the slot (see the block comment). */
    sev.sigev_value.sival_int = slot;
    u64 gvalue = (u64)slot;   /* NULL-sigevent kernel default: sival = timer id */
    int err = 0;
    if (a1) {
        GSigevent g;
        if (copy_from_guest(c, &g, a1, sizeof g) < 0) {
            err = -EFAULT;
        } else switch (g.sigev_notify) {
        case G_SIGEV_THREAD_ID:
#ifdef sigev_notify_thread_id
            sev.sigev_notify_thread_id = (pid_t)g.sigev_tid;
#else
            sev._sigev_un._tid = (pid_t)g.sigev_tid;   /* glibc union field */
#endif
            /* fall through */
        case G_SIGEV_SIGNAL:
        case G_SIGEV_NONE: {
            int signo = (int)g.sigev_signo;
            /* Guest 32/33 -- its libc's internal SIGTIMER/SIGCANCEL; the
             * glibc/musl SIGEV_THREAD helper arms 32 -- collide with the
             * *host* libc's own internal numbers and cannot be raised
             * directly: raise a reserved host carrier instead, translated
             * back to the guest number at capture (sig_arm_rt_remap). */
            if (g.sigev_notify != G_SIGEV_NONE && (signo == 32 || signo == 33))
                signo = sig_arm_rt_remap(signo);
            sev.sigev_notify = (int)g.sigev_notify;
            sev.sigev_signo = signo;
            gvalue = g.sigev_value;
            break;
        }
        default:
            err = -EINVAL;   /* incl. SIGEV_THREAD: not kernel-valid */
        }
    } else {
        /* NULL sigevent: the kernel defaults to SIGEV_SIGNAL/SIGALRM with the
         * timer id in sival_int; the guest id is the slot, set above. */
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGALRM;
    }
    timer_t ht;
    if (!err && timer_create((clockid_t)(s32)a0, &sev, &ht) < 0)
        err = -errno;
    if (!err) {
        /* timer_t in the syscall ABI is __kernel_timer_t, i.e. int: the kernel
         * put_user()s 4 bytes, and both musl and glibc pass the address of a
         * stack int. Writing 8 would clobber whatever follows it. */
        s32 gid = (s32)slot;
        if (copy_to_guest(c, a2, &gid, 4) < 0) {
            timer_delete(ht);
            err = -EFAULT;
        }
    }
    if (err) {
        __atomic_store_n(&g_ptimers[slot].state, 0, __ATOMIC_RELEASE);
        return (u64)(s64)err;
    }
    g_ptimers[slot].host = ht;
    g_ptimers[slot].gvalue = gvalue;
    __atomic_store_n(&g_ptimers[slot].state, 2, __ATOMIC_RELEASE);
    return 0;
}

SYSDEF(timer_settime) {
    timer_t ht;
    int r = ptimer_get(a0, &ht);
    if (r < 0) return (u64)(s64)r;
    if (!a2) return (u64)(s64)-EINVAL;   /* kernel: new_value is mandatory */
    GTimespec g[2];
    if (copy_from_guest(c, g, a2, sizeof g) < 0) return (u64)(s64)-EFAULT;
    struct itimerspec nv, ov;
    nv.it_interval.tv_sec = (time_t)g[0].tv_sec;
    nv.it_interval.tv_nsec = (long)g[0].tv_nsec;
    nv.it_value.tv_sec = (time_t)g[1].tv_sec;
    nv.it_value.tv_nsec = (long)g[1].tv_nsec;
    /* TIMER_ABSTIME (1) is a shared constant: flags pass through. */
    if (timer_settime(ht, (int)(s32)a1, &nv, a3 ? &ov : NULL) < 0)
        return host_err();
    if (a3) {
        GTimespec o[2] = {
            { (s64)ov.it_interval.tv_sec, (s64)ov.it_interval.tv_nsec },
            { (s64)ov.it_value.tv_sec, (s64)ov.it_value.tv_nsec },
        };
        if (copy_to_guest(c, a3, o, sizeof o) < 0) return (u64)(s64)-EFAULT;
    }
    return 0;
}

SYSDEF(timer_gettime) {
    timer_t ht;
    int r = ptimer_get(a0, &ht);
    if (r < 0) return (u64)(s64)r;
    struct itimerspec ov;
    if (timer_gettime(ht, &ov) < 0) return host_err();
    GTimespec g[2] = {
        { (s64)ov.it_interval.tv_sec, (s64)ov.it_interval.tv_nsec },
        { (s64)ov.it_value.tv_sec, (s64)ov.it_value.tv_nsec },
    };
    return copy_to_guest(c, a1, g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(timer_getoverrun) {
    timer_t ht;
    int r = ptimer_get(a0, &ht);
    if (r < 0) return (u64)(s64)r;
    int ov = timer_getoverrun(ht);
    return ov < 0 ? host_err() : (u64)ov;
}

SYSDEF(timer_delete) {
    timer_t ht;
    int r = ptimer_get(a0, &ht);
    if (r < 0) return (u64)(s64)r;
    timer_delete(ht);
    __atomic_store_n(&g_ptimers[a0].state, 0, __ATOMIC_RELEASE);
    return 0;
}
