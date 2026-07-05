/* Signal syscalls. Until M5 (full guest delivery), dispositions are stored in
 * the task and mirrored onto the host coarsely: SIG_IGN/SIG_DFL pass through
 * so process-fatal semantics (pipelines, Ctrl-C on the group) behave; guest
 * handler invocation arrives with the sigframe machinery in M5. */
#include <signal.h>
#include <string.h>

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
    int how = (int)a0;
    if (a3 != 8) return (u64)(s64)-EINVAL;
    struct Machine *m = c->m;
    u64 old = m->sigmask;
    if (a1) {
        u64 set;
        if (copy_from_guest(c, &set, a1, 8) < 0) return (u64)(s64)-EFAULT;
        switch (how) {
            case 0: m->sigmask |= set; break;          /* SIG_BLOCK */
            case 1: m->sigmask &= ~set; break;         /* SIG_UNBLOCK */
            case 2: m->sigmask = set; break;           /* SIG_SETMASK */
            default: return (u64)(s64)-EINVAL;
        }
        /* SIGKILL/SIGSTOP cannot be blocked */
        m->sigmask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
        sig_sync_host_mask(m);   /* propagate job-control-signal block state */
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
    struct Machine *m = c->m;
    u64 set;
    if (copy_from_guest(c, &set, a0, 8) < 0) return (u64)(s64)-EFAULT;
    set &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    /* Install the temporary mask, remember the caller's mask so the frame
     * built at delivery records it, and block in the host until a signal
     * arrives. The run loop then delivers it to the guest handler. */
    m->saved_sigmask = m->sigmask;
    m->have_saved_sigmask = 1;
    m->sigmask = set;
    sig_sync_host_mask(m);
    /* Wait for any signal; the host catcher queues it, then we return EINTR
     * and the loop delivers to the guest (which restores saved_sigmask via
     * the sigframe ucontext on sigreturn). */
    pause();
    m->sigmask = m->saved_sigmask;
    sig_sync_host_mask(m);
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
    (void)a2; (void)a3; (void)a4; (void)a5;
    return kill((pid_t)(s32)a0, (int)a1) < 0 ? host_err() : 0;
}

SYSDEF(tgkill) {
    (void)a3; (void)a4; (void)a5;
    /* single-threaded process: tgkill(tgid, tid, sig) == kill(tgid, sig) */
    return kill((pid_t)(s32)a0, (int)a2) < 0 ? host_err() : 0;
}
