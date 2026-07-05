/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Time syscalls: clockid values and semantics are shared; only the struct
 * widths need marshalling (guest timespec/timeval are 2 x s64). */
#include <sys/time.h>
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
