/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Signal syscalls. Until M5 (full guest delivery), dispositions are stored in
 * the task and mirrored onto the host coarsely: SIG_IGN/SIG_DFL pass through
 * so process-fatal semantics (pipelines, Ctrl-C on the group) behave; guest
 * handler invocation arrives with the sigframe machinery in M5. */
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "sys.h"

#define GSIG_DFL 0
#define GSIG_IGN 1

SYSDEF(rt_sigaction) {
    int sig = (int)a0;
    if (sig < 1 || sig > 64 || a3 != 8) return (u64)(s64)-EINVAL;
    struct Machine *m = c->m;
    if (a2) {   /* old action out */
        GSigactionK old = {
            .handler = m->sigact[sig].handler,
            .flags = m->sigact[sig].flags,
            .restorer = m->sigact[sig].restorer,
            .mask = m->sigact[sig].mask,
        };
        if (copy_to_guest(c, a2, &old, sizeof old) < 0) return (u64)(s64)-EFAULT;
    }
    if (a1) {
        GSigactionK ga;
        if (copy_from_guest(c, &ga, a1, sizeof ga) < 0) return (u64)(s64)-EFAULT;
        if (sig == SIGKILL || sig == SIGSTOP) return (u64)(s64)-EINVAL;
        m->sigact[sig].handler = ga.handler;
        m->sigact[sig].flags = ga.flags;
        m->sigact[sig].restorer = ga.restorer;
        m->sigact[sig].mask = ga.mask;
        sig_host_update(m, sig);   /* install/remove the host catcher */
    }
    return 0;
}

SYSDEF(rt_sigprocmask) {
    /* The blocked set is per-thread (g_tls, POSIX). */
    int how = (int)a0;
    if (a3 != 8) return (u64)(s64)-EINVAL;
    u64 old = g_tls.sigmask;
    if (a1) {
        u64 set;
        if (copy_from_guest(c, &set, a1, 8) < 0) return (u64)(s64)-EFAULT;
        switch (how) {
            case 0: g_tls.sigmask |= set; break;       /* SIG_BLOCK */
            case 1: g_tls.sigmask &= ~set; break;      /* SIG_UNBLOCK */
            case 2: g_tls.sigmask = set; break;        /* SIG_SETMASK */
            default: return (u64)(s64)-EINVAL;
        }
        /* SIGKILL/SIGSTOP cannot be blocked */
        g_tls.sigmask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
        sig_sync_host_mask();   /* propagate job-control-signal block state */
    }
    if (a2 && copy_to_guest(c, a2, &old, 8) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(rt_sigreturn) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    sig_return(c);
    return c->x[0];   /* x0 was restored from the frame; keep it */
}

SYSDEF(rt_sigpending) {
    if (a1 != 8) return (u64)(s64)-EINVAL;
    u64 none = 0;
    return copy_to_guest(c, a0, &none, 8) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(rt_sigsuspend) {
    if (a1 != 8) return (u64)(s64)-EINVAL;
    u64 set;
    if (copy_from_guest(c, &set, a0, 8) < 0) return (u64)(s64)-EFAULT;
    set &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    /* Install the temporary mask and remember the caller's so the delivery
     * frame records it; sigreturn restores it (kernel semantics: the guest
     * handler runs under the temporary mask). */
    g_tls.saved_sigmask = g_tls.sigmask;
    g_tls.have_saved_sigmask = 1;
    g_tls.sigmask = set;
    sig_sync_host_mask();
    /* Sleep until the capture queue holds a deliverable signal. A bare
     * pause() loses the race against a signal captured *before* it parks:
     * the kernel's sigsuspend swaps the mask and sleeps atomically, but here
     * a SIGCHLD that arrived while the guest still had it blocked sits in
     * the queue already and pause() would wait for a second arrival that
     * never comes (`sh -c 'sleep 0.2 & wait'` hung this way). The host
     * catcher interrupts nanosleep (no SA_RESTART), so the tick only bounds
     * the check-to-sleep window. On return the run loop delivers to the
     * guest handler. */
    while (!sig_pending_deliverable(c->m)) {
        struct timespec ts = { 0, 20 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return (u64)(s64)-EINTR;
}

SYSDEF(rt_sigtimedwait) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)-ENOSYS;
}

SYSDEF(sigaltstack) {
    struct Machine *m = c->m;
    if (a1) {
        struct { u64 sp; s32 flags; s32 pad; u64 size; } old = {
            m->sig_altstack_sp,
            (s32)(m->sig_altstack_size ? m->sig_altstack_flags : 2 /*SS_DISABLE*/),
            0,
            m->sig_altstack_size,
        };
        if (copy_to_guest(c, a1, &old, sizeof old) < 0) return (u64)(s64)-EFAULT;
    }
    if (a0) {
        struct { u64 sp; s32 flags; s32 pad; u64 size; } ss;
        if (copy_from_guest(c, &ss, a0, sizeof ss) < 0) return (u64)(s64)-EFAULT;
        if (ss.flags & 2 /*SS_DISABLE*/) {
            m->sig_altstack_sp = m->sig_altstack_size = 0;
        } else {
            if (ss.size < 2048) return (u64)(s64)-ENOMEM;
            m->sig_altstack_sp = ss.sp;
            m->sig_altstack_size = ss.size;
            m->sig_altstack_flags = (u32)ss.flags;
        }
    }
    return 0;
}

SYSDEF(kill) {
    return kill((pid_t)(s32)a0, (int)a1) < 0 ? host_err() : 0;
}

SYSDEF(tkill) {
    /* Thread-directed signal. Secondary guest threads carry synthetic tids
     * (sys_proc.c), so translate to the host thread carrying the target --
     * the raw value addresses whatever host process it collides with, which
     * broke raise()/pthread_kill from worker threads. tid_to_host returns 0
     * for the caller itself (the common raise() case). */
    (void)a2; (void)a3; (void)a4; (void)a5;
    s32 tid = (s32)a0;
    if (tid <= 0) return (u64)(s64)-EINVAL;
    pid_t htid = tid_to_host(c->m, tid);
    if (htid == 0) htid = (pid_t)syscall(SYS_gettid);
    return syscall(SYS_tkill, htid, (int)a1) < 0 ? host_err() : 0;
}

SYSDEF(tgkill) {
    /* As tkill: translate the tid within the caller's own thread group.
     * Foreign thread groups pass through -- their main-thread tid is a real
     * host pid; their secondary tids are private to that emulator instance
     * and get the kernel's ESRCH. */
    (void)a3; (void)a4; (void)a5;
    s32 tgid = (s32)a0, tid = (s32)a1;
    if (tgid <= 0 || tid <= 0) return (u64)(s64)-EINVAL;
    pid_t htid = (pid_t)tid;
    if (tgid == getpid()) {
        htid = tid_to_host(c->m, tid);
        if (htid == 0) htid = (pid_t)syscall(SYS_gettid);
    }
    return syscall(SYS_tgkill, (pid_t)tgid, htid, (int)a2) < 0 ? host_err() : 0;
}

SYSDEF(rt_sigqueueinfo) {
    /* (tgid, sig, siginfo*). Read the queueing fields from the guest LP64
     * siginfo (code@8; SI_QUEUE union: pid@16, uid@20, value@24) and re-send
     * through the host kernel, which enforces the same rules the guest
     * expects (si_code >= 0 to another process -> EPERM, bad pid -> ESRCH).
     * The receiving emulator instance queues it via host_catcher and frames
     * the payload back into the guest handler's siginfo. glibc has no
     * wrapper; the raw syscall is on the Android 8 seccomp allow-list. */
    (void)a3; (void)a4; (void)a5;
    u8 gsi[32];
    if (copy_from_guest(c, gsi, a2, sizeof gsi) < 0) return (u64)(s64)-EFAULT;
    s32 code, pid; u32 uid; u64 value;
    memcpy(&code, gsi + 8, 4);
    memcpy(&pid, gsi + 16, 4);
    memcpy(&uid, gsi + 20, 4);
    memcpy(&value, gsi + 24, 8);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = (int)(s32)a1;
    si.si_code = code;
    si.si_pid = (pid_t)pid;
    si.si_uid = (uid_t)uid;
    /* An ILP32 host truncates a pointer-sized payload to its 32-bit sival;
     * int payloads (the sigqueue API) are preserved everywhere. */
    si.si_value.sival_ptr = (void *)(uintptr_t)value;
    long r = syscall(SYS_rt_sigqueueinfo, (pid_t)(s32)a0, (int)(s32)a1, &si);
    return r < 0 ? host_err() : 0;
}
