/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Cross-process ptrace(2) control channel.
 *
 * A guest process is a separate host process (fork) with a private address
 * space and a private CPU register file, so a guest tracer's emulator instance
 * cannot read or write a guest tracee's state directly. The emulator instead
 * mediates ptrace the same way it mediates every other syscall: the *tracee*
 * services ptrace requests about itself while it is parked at a stop point.
 *
 * Model:
 *   - A MAP_SHARED anonymous registry (created in ptrace_init before the first
 *     fork, so every guest process in the session maps it at the same address)
 *     holds one PtLink per traced *task*, keyed by tracee tid (== host tid;
 *     a main thread's tid is its pid). Tracing is per-thread, as in the
 *     kernel: each thread of a multithreaded tracee has its own link, its own
 *     thread-local self state below, and services requests about itself.
 *   - Each link carries the tracer<->tracee relationship, the current stop
 *     state, and a small futex mailbox. When a tracee reaches a stop point
 *     (syscall entry/exit, signal delivery, execve, ...) it publishes the stop,
 *     wakes the tracer's wait4, and then blocks in a service loop answering
 *     PEEK/POKE/GETREGSET/SETREGSET/CONT/SYSCALL/... using its *own* CPU and
 *     copy_{to,from}_guest. A request while the tracee is running (not stopped)
 *     fails -ESRCH, exactly as real ptrace requires.
 *   - The tracer side (guest ptrace/wait4 handlers) posts commands to the
 *     mailbox and reads back results; wait4 discovers stops by scanning the
 *     registry and blocks on a global generation futex between events.
 *
 * This needs no host ptrace privilege (important on Android/SELinux/seccomp
 * where host ptrace is denied) and no shared guest RAM. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "machine.h"
#include "guest_abi.h"
#include "ptrace.h"

/* ---- thread-local tracee-self state (fast gates read by the hot paths) ---- */
__thread int g_ptrace_active;
__thread int g_ptrace_syscall_armed;
__thread int g_ptrace_singlestep;
/* One-shot: skip the next syscall-exit stop. Set on an auto-attached fork child
 * so the spurious "exit" of the clone it was born from (which it never entered
 * at a syscall-entry stop) is not reported and does not desync the tracer's
 * entry/exit pairing. */
__thread int g_ptrace_skip_syscall_stop;
/* Set by the reserved-signal kick handler; drained by ptrace_service_kick. */
__thread volatile sig_atomic_t g_ptrace_kick;

/* Process-level count of traced threads. Signal dispositions are process-wide,
 * so the host catchers a tracee needs -- every signal that can be caught, the
 * ignored ones included, for the tracer to see (sig_host_update) -- must stay
 * installed while *any* thread must report its stops/death, not just the
 * calling one. */
static int g_ptrace_traced;

int ptrace_traced(void) {
    return __atomic_load_n(&g_ptrace_traced, __ATOMIC_SEQ_CST) > 0;
}

/* Adopt/drop bookkeeping around g_ptrace_traced: the counter moves first, then
 * the process dispositions are re-mirrored so sig_host_update sees the new
 * traced state (the drop only re-mirrors when the last traced thread is gone). */
static void pt_traced_inc(struct Machine *m) {
    __atomic_add_fetch(&g_ptrace_traced, 1, __ATOMIC_SEQ_CST);
    sig_trace_update_all(m);
}
static int pt_traced_dec(struct Machine *m) {
    if (__atomic_sub_fetch(&g_ptrace_traced, 1, __ATOMIC_SEQ_CST) != 0) return 0;
    sig_trace_update_all(m);
    return 1;   /* the last one */
}

/* ---- shared registry ---- */
#define PTRACE_MAX  256      /* max concurrent tracees in the session */
#define PT_MBOX     1024     /* mailbox payload cap (>= largest regset, 528) */

/* Link state. */
enum { PT_ST_RUNNING = 0, PT_ST_STOPPED = 1, PT_ST_EXITED = 2 };

/* Mailbox commands (tracer -> stopped tracee). */
enum {
    PT_CMD_NONE = 0,
    PT_CMD_PEEK,        /* addr -> 8-byte word in data[] */
    PT_CMD_PEEKUSR,     /* addr = user-area offset -> word */
    PT_CMD_POKE,        /* addr, arg = value */
    PT_CMD_READ,        /* addr, arg = len (<= PT_MBOX): guest mem -> data[]; result = bytes */
    PT_CMD_WRITE,       /* addr, arg = len (<= PT_MBOX): data[] -> guest mem; result = bytes */
    PT_CMD_GETREGS,     /* addr = NT_* which -> regset in data[] */
    PT_CMD_SETREGS,     /* addr = NT_* which, rlen bytes in data[] */
    PT_CMD_RESUME,      /* addr = inject sig, arg = PT_RES_* submode */
    PT_CMD_DETACH,      /* addr = inject sig */
};

/* Resume submodes. */
enum { PT_RES_CONT = 0, PT_RES_SYSCALL = 1, PT_RES_SINGLESTEP = 2 };

typedef struct {
    s32 tracee;          /* 0 = free (CAS-claimed); tracee tid (== host tid;
                          * a main thread's tid is its pid) */
    s32 tgid;            /* tracee's thread group (process) id */
    s32 tracer;          /* tracer pid, 0 once detached */
    u32 options;         /* PTRACE_O_* */
    u32 state;           /* PT_ST_* (release/acquire flag for the stop fields) */
    u32 reported;        /* a wait (wait4, or waitid without WNOWAIT) has
                          * consumed the current stop */
    u32 stop_sig;        /* WSTOPSIG of the current stop */
    u32 event;           /* PTRACE_EVENT_* of the current stop (0 = none) */
    u32 syscall_stop;    /* current stop is a syscall-entry/exit stop */
    u32 attach_pending;  /* tracer ATTACH/SEIZE'd us: adopt at the next boundary */
    u32 attach_stopped;  /* ...while the host had the process stopped: adopt into
                          * a group stop (the tracer woke it to adopt at all) */
    u32 interrupt_pending; /* JOBCTL_TRAP_STOP: a PTRACE_INTERRUPT, or a SEIZEd
                          * auto-attached child's first stop -- a
                          * PTRACE_EVENT_STOP trap at the next boundary, or
                          * after the stop the tracee is in */
    u32 trap_notify;     /* JOBCTL_TRAP_NOTIFY: the group-stop state changed
                          * under a SEIZEd tracee (a group stop began, or a
                          * SIGCONT ended one) -- the same trap, to tell it */
    u32 seize;           /* attached via SEIZE (no initial SIGSTOP; group stops) */
    u32 listening;       /* PTRACE_LISTEN: parked in an EVENT_STOP trap, not a
                          * stop to ptrace(2) or wait(2), until a trap_notify or
                          * an interrupt makes it trap again */
    s32 exit_status;     /* PT_ST_EXITED: wait-status word for the tracer */
    s32 pgid;            /* the tracee's process group as of its last stop or
                          * death (claimed with the one it had): what a wait
                          * for a group asks once the task itself is gone */
    u64 eventmsg;        /* PTRACE_GETEVENTMSG payload */
    u8  siginfo[128];    /* the current stop's siginfo, in the guest's layout:
                          * what GETSIGINFO reads and SETSIGINFO rewrites (its
                          * last_siginfo); has_siginfo 0 for a stop that has
                          * none -- an ATTACHed tracee's group-stop, where
                          * both are EINVAL */
    u32 has_siginfo;
    PtRusage ru;         /* accounting as of the current stop (pt_ru_stamp) */
    /* futex mailbox: tracer bumps cmd_seq to submit, tracee bumps done_seq. */
    u32 cmd_seq, done_seq;
    u32 cmd;
    u64 addr, arg;
    s64 result;
    u32 rlen;
    u8  data[PT_MBOX];
} PtLink;

typedef struct {
    u32 global_gen;      /* bumped on every stop/exit; the wait4 sleep futex */
    u32 any_trace;       /* set once anyone in the session starts tracing */
    PtLink links[PTRACE_MAX];
} PtTable;

static PtTable *g_tab;            /* MAP_SHARED, or NULL if unavailable */
/* The calling thread's own tracee entry, or NULL. Thread-local like the rest
 * of the tracee-self state: every traced thread has its own link. */
static __thread PtLink *g_self_link;
/* The stop this thread is parked in is a job-control trap (pt_jobctl_trap),
 * and the one it just left ended with its tracer's death (pt_service_loop). */
static __thread int pt_in_jobctl, pt_orphaned;

/* pt_stop's answer for a listening trap a trap_notify or an interrupt ended:
 * trap again (pt_jobctl_trap). Never a signal number. */
#define PT_RETRAP (-1)

/* A group stop this thread has not taken part in yet (signal.c, "group
 * stop"). */
static int pt_jc_due(void) {
    return __atomic_load_n(&g_machine.jc_active, __ATOMIC_ACQUIRE) &&
           g_tls.jc_seen != __atomic_load_n(&g_machine.jc_gseq, __ATOMIC_ACQUIRE);
}

/* ---- futex helpers (cross-process: no FUTEX_PRIVATE_FLAG) ---- */
static void fx_wake(volatile u32 *a) {
    syscall(SYS_futex, (u32 *)a, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}
static void fx_wait(volatile u32 *a, u32 val, int ms) {
    if (ms < 0) { syscall(SYS_futex, (u32 *)a, FUTEX_WAIT, val, NULL, NULL, 0); return; }
    /* As in sys_misc.c futex: a 32-bit host's plain SYS_futex takes a pair of
     * 32-bit words, so a libc timespec built with _TIME_BITS=64 would be read
     * as {low half of tv_sec, 0} and the wait would not wait at all -- here
     * that would spin the mailbox instead of parking on it. */
#if defined(SYS_futex_time64) && __SIZEOF_LONG__ == 4
    struct { s64 tv_sec, tv_nsec; } ts = { ms / 1000, (s64)(ms % 1000) * 1000000 };
    if (syscall(SYS_futex_time64, (u32 *)a, FUTEX_WAIT, val, &ts, NULL, 0) < 0 &&
        errno == ENOSYS) {
        struct { s32 tv_sec, tv_nsec; } t32 = { ms / 1000, (ms % 1000) * 1000000 };
        syscall(SYS_futex, (u32 *)a, FUTEX_WAIT, val, &t32, NULL, 0);
    }
#else
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    syscall(SYS_futex, (u32 *)a, FUTEX_WAIT, val, &ts, NULL, 0);
#endif
}

/* A job-control stop signal: the kernel turns these into a group-stop rather than
 * a catchable signal, and (for a SEIZE'd tracee) reports the group-stop with
 * PTRACE_EVENT_STOP. */
static int pt_is_stopsig(int sig) {
    return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU;
}

/* Wake tracer `tr` after publishing an event (a stop or a synthetic exit).
 * Two channels, because the tracer may be waiting either way:
 *  - SIGCHLD, exactly as the kernel raises on a tracee state change: an async
 *    tracer (gdb) waits in an event loop driven by its own SIGCHLD handler.
 *  - The reserved kick signal carrying PT_WAKE_MAGIC: its handler (sig_kick_net,
 *    installed in every emulator process, no SA_RESTART) is a pure no-op whose
 *    EINTR knocks a tracer out of a *blocking* host wait4/waitid so it re-checks
 *    the registry. This works regardless of the tracer's SIGCHLD disposition
 *    (SIG_DFL SIGCHLD is discarded by the host without interrupting anything). */
static void pt_wake_tracer(s32 tr) {
    if (tr <= 0) return;
    kill(tr, SIGCHLD);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = PTRACE_KICKSIG;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = getuid();
    si.si_value.sival_int = PT_WAKE_MAGIC;
    syscall(SYS_rt_sigqueueinfo, (pid_t)tr, PTRACE_KICKSIG, &si);
}

void ptrace_init(void) {
    void *p = mmap(NULL, sizeof(PtTable), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_tab = (p == MAP_FAILED) ? NULL : p;   /* degrade to "no ptrace" on failure */
}

/* ---- registry helpers ---- */
static PtLink *pt_find(s32 tracee) {
    if (!g_tab || tracee <= 0) return NULL;
    for (int i = 0; i < PTRACE_MAX; i++)
        if (__atomic_load_n(&g_tab->links[i].tracee, __ATOMIC_ACQUIRE) == tracee)
            return &g_tab->links[i];
    return NULL;
}

static PtLink *pt_claim(s32 tracee, s32 tgid) {
    if (!g_tab) return NULL;
    PtLink *e = pt_find(tracee);
    if (e) return e;
    for (int i = 0; i < PTRACE_MAX; i++) {
        s32 expect = 0;
        /* Take the slot with a sentinel, fill it, and only then publish the
         * real tid. Every scan of the registry skips a non-positive `tracee`,
         * so no other process can act on a half-initialized link -- one still
         * carrying the *previous* owner's tgid, which a concurrent
         * exit_group fan-out would sweep as one of its own threads and either
         * publish a bogus exit on or free outright, out from under the task
         * that just claimed it. */
        if (__atomic_compare_exchange_n(&g_tab->links[i].tracee, &expect, -1,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            e = &g_tab->links[i];
            e->tgid = tgid;
            e->tracer = 0; e->options = 0; e->state = PT_ST_RUNNING;
            e->reported = 0; e->stop_sig = 0; e->event = 0; e->syscall_stop = 0;
            e->eventmsg = 0; e->has_siginfo = 0;
            e->attach_pending = e->interrupt_pending = 0;
            e->attach_stopped = 0;
            e->trap_notify = 0; e->seize = 0; e->listening = 0;
            e->pgid = (s32)getpgid((pid_t)tracee);   /* ours or the target's */
            memset(&e->ru, 0, sizeof e->ru);   /* never inherit a recycled slot's */
            e->cmd_seq = e->done_seq = 0; e->cmd = PT_CMD_NONE;
            __atomic_store_n(&e->tracee, tracee, __ATOMIC_RELEASE);
            return e;
        }
    }
    return NULL;
}

/* Stamp the calling tracee's own accounting into its link, next to the other
 * stop fields, so the tracer's wait4/waitid can fill a guest rusage for a stop
 * the host wait never sees. RUSAGE_BOTH is kernel-internal; SELF + CHILDREN is
 * the same thing (the kernel sums both, except maxrss where it takes the
 * larger). Sampling at the stop rather than at wait time is also what the guest
 * should see: from here until the tracer collects, this thread only runs the
 * emulator's own service loop, and that host CPU time is not the guest's.
 * A per-thread getrusage is not what the kernel reports either -- RUSAGE_SELF is
 * thread-group-wide, which is what a stopped thread's tracer gets. */
static void pt_ru_stamp(PtLink *e) {
    e->pgid = (s32)getpgid(0);   /* the group a wait for one asks about */
    struct rusage s, ch;
    memset(&s, 0, sizeof s);
    memset(&ch, 0, sizeof ch);
    getrusage(RUSAGE_SELF, &s);
    getrusage(RUSAGE_CHILDREN, &ch);
    s64 ut = (s64)s.ru_utime.tv_sec * 1000000 + s.ru_utime.tv_usec +
             (s64)ch.ru_utime.tv_sec * 1000000 + ch.ru_utime.tv_usec;
    s64 st = (s64)s.ru_stime.tv_sec * 1000000 + s.ru_stime.tv_usec +
             (s64)ch.ru_stime.tv_sec * 1000000 + ch.ru_stime.tv_usec;
    PtRusage r;
    r.utime_sec = ut / 1000000; r.utime_usec = ut % 1000000;
    r.stime_sec = st / 1000000; r.stime_usec = st % 1000000;
    r.maxrss = s.ru_maxrss > ch.ru_maxrss ? s.ru_maxrss : ch.ru_maxrss;
    r.ixrss = s.ru_ixrss + ch.ru_ixrss;
    r.idrss = s.ru_idrss + ch.ru_idrss;
    r.isrss = s.ru_isrss + ch.ru_isrss;
    r.minflt = s.ru_minflt + ch.ru_minflt;
    r.majflt = s.ru_majflt + ch.ru_majflt;
    r.nswap = s.ru_nswap + ch.ru_nswap;
    r.inblock = s.ru_inblock + ch.ru_inblock;
    r.oublock = s.ru_oublock + ch.ru_oublock;
    r.msgsnd = s.ru_msgsnd + ch.ru_msgsnd;
    r.msgrcv = s.ru_msgrcv + ch.ru_msgrcv;
    r.nsignals = s.ru_nsignals + ch.ru_nsignals;
    r.nvcsw = s.ru_nvcsw + ch.ru_nvcsw;
    r.nivcsw = s.ru_nivcsw + ch.ru_nivcsw;
    e->ru = r;   /* ordered by the state release-store that publishes the stop */
}

static void pt_free(PtLink *e) {
    if (!e) return;
    __atomic_store_n(&e->tracer, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&e->tracee, 0, __ATOMIC_RELEASE);   /* slot free */
}

/* ---- regset marshalling (runs in the tracee, has the live CPU) ---- */
static u32 pt_build_regset(CPU *c, u32 which, u8 *out) {
    switch (which) {
    case G_NT_PRSTATUS: {
        GUserRegs r;
        for (int i = 0; i < 31; i++) r.regs[i] = c->x[i];
        r.sp = *cpu_cur_sp(c);
        r.pc = c->pc;
        r.pstate = cpu_pack_spsr(c);
        memcpy(out, &r, sizeof r);
        return (u32)sizeof r;
    }
    case G_NT_PRFPREG: {
        GUserFpsimd f;
        memset(&f, 0, sizeof f);
        fpsr_sync(c);           /* c->fpsr is lazy: fold before marshalling */
        for (int i = 0; i < 32; i++) f.vregs[i] = c->v[i];
        f.fpsr = c->fpsr;
        f.fpcr = c->fpcr;
        memcpy(out, &f, sizeof f);
        return (u32)sizeof f;
    }
    case G_NT_ARM_TLS: {
        u64 tls = c->tpidr[0];
        memcpy(out, &tls, sizeof tls);
        return (u32)sizeof tls;
    }
    case G_NT_ARM_SYSTEM_CALL: {
        s32 nr = (s32)c->x[8];
        memcpy(out, &nr, sizeof nr);
        return (u32)sizeof nr;
    }
    default:
        return 0;
    }
}

/* How many bytes the regset `which` holds (0 = not modelled). The kernel
 * clamps a GETREGSET/SETREGSET iov_len to this and writes the clamped value
 * back, so the tracer needs the size even for a write. */
static u32 pt_regset_size(u32 which) {
    switch (which) {
    case G_NT_PRSTATUS:        return (u32)sizeof(GUserRegs);
    case G_NT_PRFPREG:         return (u32)sizeof(GUserFpsimd);
    case G_NT_ARM_TLS:         return 8;
    case G_NT_ARM_SYSTEM_CALL: return 4;
    default:                   return 0;
    }
}

static int pt_apply_regset(CPU *c, u32 which, const u8 *in, u32 len) {
    switch (which) {
    case G_NT_PRSTATUS: {
        GUserRegs r;
        if (len < sizeof r) return -EINVAL;
        memcpy(&r, in, sizeof r);
        for (int i = 0; i < 31; i++) c->x[i] = r.regs[i];
        *cpu_cur_sp(c) = r.sp;
        c->pc = r.pc;
        cpu_unpack_spsr(c, (u32)r.pstate);
        return 0;
    }
    case G_NT_PRFPREG: {
        GUserFpsimd f;
        if (len < sizeof f) return -EINVAL;
        memcpy(&f, in, sizeof f);
        for (int i = 0; i < 32; i++) c->v[i] = f.vregs[i];
        fpsr_sync(c);           /* drop pending, or it resurrects after this */
        c->fpsr = f.fpsr;
        c->fpcr = f.fpcr;
        return 0;
    }
    case G_NT_ARM_TLS: {
        u64 tls;
        if (len < sizeof tls) return -EINVAL;
        memcpy(&tls, in, sizeof tls);
        c->tpidr[0] = tls;
        return 0;
    }
    case G_NT_ARM_SYSTEM_CALL: {
        s32 nr;
        if (len < sizeof nr) return -EINVAL;
        memcpy(&nr, in, sizeof nr);
        c->x[8] = (u64)(s64)nr;   /* redirect/cancel the in-flight syscall */
        return 0;
    }
    default:
        return -EINVAL;
    }
}

/* ---- a stop's siginfo (what GETSIGINFO hands the tracer) ---- */
static void pt_w32(u8 *si, int off, u32 v) { memcpy(si + off, &v, 4); }
static u32 pt_r32(const u8 *si, int off) { u32 v; memcpy(&v, si + off, 4); return v; }

/* ptrace_do_notify's: a trap -- a syscall stop, an event, a SEIZEd tracee's
 * group-stop or INTERRUPT -- reports its signal and its stop code (the
 * status's high bits, e.g. SIGTRAP|0x80, or PTRACE_EVENT_STOP<<8|signr), from
 * the tracee itself. */
static void pt_si_notify(u8 *si, int signr, int code) {
    memset(si, 0, 128);
    pt_w32(si, 0, (u32)signr);
    pt_w32(si, 8, (u32)code);
    pt_w32(si, 16, (u32)g_tls.tid);
    pt_w32(si, 20, (u32)getuid());
}

/* A signal of the tracee's own that no queue carried (pt_signal_stop): the
 * siginfo it is delivered with. A positive code is a fault's (si_addr); any
 * other is a sent one's (si_pid, and si_uid unless it came from nobody). */
static void pt_si_signal(u8 *si, int sig, int code, s32 pid, u64 addr) {
    memset(si, 0, 128);
    pt_w32(si, 0, (u32)sig);
    pt_w32(si, 8, (u32)code);
    if (code > 0 && code != 0x80 /* SI_KERNEL */) {
        memcpy(si + 16, &addr, 8);
    } else {
        pt_w32(si, 16, (u32)pid);
        pt_w32(si, 20, pid ? (u32)getuid() : 0);
    }
}

/* ---- tracee: service loop + stop core ---- */
/* Host-task liveness, defined with the rest of the tracer side at the bottom:
 * the parked tracee below needs the zombie test, pt_cmd the dead one. */
static int pt_task_zombie(s32 t);
static int pt_task_dead(s32 t);

static void pt_self_detach(void) {
    PtLink *e = g_self_link;
    int was = g_ptrace_active;
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    if (e) { __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE); pt_free(e); }
    /* __ptrace_unlink: a group stop in force stops the thread again, now
     * untraced -- it parks at its next boundary (ptrace_jobctl_service), or,
     * the last traced thread gone, the stop is the host's (sig_jc_untraced).
     * A detach, or a tracer's death, of a live thread only: one that is
     * exiting releases its link elsewhere, and does not stop. */
    if (__atomic_load_n(&g_machine.jc_active, __ATOMIC_ACQUIRE)) {
        g_tls.jc_seen = __atomic_load_n(&g_machine.jc_gseq, __ATOMIC_ACQUIRE) - 1;
        g_ptrace_kick = 1;
        g_sig_npend = 1;
    }
    /* Last one out re-mirrors dispositions, and hands a group stop over. */
    if (was && pt_traced_dec(&g_machine)) sig_jc_untraced(&g_machine);
}

/* What a stop leaves its tracee when the tracer dies: the code the stop has
 * at that moment, which the kernel's exit_ptrace leaves alone. A
 * signal-delivery stop's code is its signal until a wait collects the stop
 * (wait_task_stopped clears it; `reported` is that), so a tracer dead before
 * then leaves the tracee its signal, as ptrace(2) has it: "If the tracee is
 * restarted from signal-delivery-stop, the pending signal is injected". A
 * trap leaves nothing -- a syscall or event stop, a job-control trap: a group
 * stop outlives its tracer all the same, but by __ptrace_unlink's re-arming
 * of JOBCTL_STOP_PENDING, which pt_jobctl_trap does. */
static int pt_orphaned_sig(const PtLink *e) {
    if (e->syscall_stop || e->event || pt_in_jobctl) return 0;
    return __atomic_load_n(&e->reported, __ATOMIC_ACQUIRE) ? 0 : (int)e->stop_sig;
}

/* Serve tracer commands while stopped. Returns the signal to inject on resume
 * (0 = none/suppressed), which matters for signal-delivery stops -- or, if the
 * tracer died, the one the stop leaves (pt_orphaned_sig) -- and hands back in
 * `si` (when not NULL) the stop's siginfo as the tracer left it, read before a
 * detach frees the link. `seen` is the
 * cmd_seq snapshot taken *before* the stop was published (see pt_stop): the
 * tracer can only post a command after observing STOPPED, so any command bumps
 * cmd_seq past `seen` and is never missed by this loop. */
static int pt_service_loop(CPU *c, PtLink *e, u32 seen, u8 *si) {
    int inject = 0;
    for (;;) {
        while (__atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE) == seen) {
            fx_wait(&e->cmd_seq, seen, 500);
            if (__atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE) != seen) break;
            /* Listening (PTRACE_LISTEN): no stop to its tracer any more, and
             * one a trap_notify or an interrupt ends -- the tracee traps
             * again (pt_jobctl_trap), as the kernel's ptrace_signal_wake_up
             * of a listening task sends it back through do_jobctl_trap. */
            if (__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE) &&
                (__atomic_load_n(&e->interrupt_pending, __ATOMIC_ACQUIRE) ||
                 __atomic_load_n(&e->trap_notify, __ATOMIC_ACQUIRE))) {
                __atomic_store_n(&e->listening, 0, __ATOMIC_RELEASE);
                __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE);
                return PT_RETRAP;
            }
            /* Tracer vanished while we were parked: auto-detach and run free, as
             * the kernel's exit_ptrace releases a dead tracer's tracees. kill(2)
             * alone does not see all of "vanished": it succeeds on a ZOMBIE
             * tracer -- one whose own parent has not reaped it yet -- which left
             * us parked in this stop for as long as the corpse lingered,
             * re-kicking something that will never wait for us again. */
            s32 tr = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
            if (tr <= 0 || (kill(tr, 0) != 0 && errno == ESRCH) ||
                pt_task_zombie(tr)) {
                int sig = pt_orphaned_sig(e);
                pt_self_detach();
                pt_orphaned = 1;
                return sig;
            }
            /* Another thread's execve is dismantling our thread group. The
             * kernel's de_thread SIGKILLs every other thread, which ends a
             * traced stop like any other sleep: leave, with nothing to
             * inject, for the safepoint where this thread dies -- or, the main
             * thread, takes the new image over (sys_proc.c). The tracer hears
             * of it there, as the exit or the exec a kernel reports. The kick
             * that called us out ends the wait above at once. */
            if (dethread_callout(c->m)) {
                __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE);
                return 0;
            }
            /* Our stop still unreaped after 500ms: the publish-time wake may
             * have raced the tracer's blocking wait entry (or landed on the
             * wrong thread of a multithreaded tracer). Re-kick until the stop
             * is collected; a no-op for a tracer already handling us. */
            if (!__atomic_load_n(&e->reported, __ATOMIC_ACQUIRE))
                pt_wake_tracer(tr);
        }
        seen = __atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE);
        int leave = 0;
        switch (e->cmd) {
        case PT_CMD_PEEK: {
            u64 w = 0;
            e->result = copy_from_guest(c, &w, e->addr, 8) < 0 ? -EIO : 0;
            memcpy(e->data, &w, 8);
            e->rlen = 8;
            break;
        }
        case PT_CMD_PEEKUSR: {
            u64 w = 0;
            /* Bound written so it cannot wrap: `addr + 8 <= size` is true for
             * an addr just below 2^64, and the read then lands before the
             * image (our own stack). The offset is guest-controlled. */
            if (e->addr <= (u64)sizeof(GUserRegs) - 8 && (e->addr & 7) == 0) {
                u8 buf[sizeof(GUserRegs)];
                pt_build_regset(c, G_NT_PRSTATUS, buf);
                memcpy(&w, buf + e->addr, 8);
                e->result = 0;
            } else {
                e->result = -EIO;
            }
            memcpy(e->data, &w, 8);
            e->rlen = 8;
            break;
        }
        case PT_CMD_POKE:
            /* POKETEXT/POKEDATA write regardless of page write-permission (real
             * ptrace copies-on-write); the code path also patches a read-only
             * code page for a software breakpoint and invalidates JIT blocks. */
            e->result = copy_to_guest_code(c, e->addr, &e->arg, 8) < 0 ? -EIO : 0;
            break;
        case PT_CMD_READ: {
            /* process_vm_readv remote side: copy up to arg bytes of our own guest
             * memory into the mailbox; result = bytes crossed (short on a fault). */
            u32 n = e->arg > PT_MBOX ? PT_MBOX : (u32)e->arg;
            e->rlen = (u32)copy_from_guest_partial(c, e->data, e->addr, n);
            e->result = (s64)e->rlen;
            break;
        }
        case PT_CMD_WRITE: {
            /* process_vm_writev remote side: copy up to arg mailbox bytes into our
             * own guest memory (honoring write permission); result = bytes crossed.
             * Unlike POKE this is an ordinary write, so a read-only page faults. */
            u32 n = e->arg > PT_MBOX ? PT_MBOX : (u32)e->arg;
            e->rlen = (u32)copy_to_guest_partial(c, e->addr, e->data, n);
            e->result = (s64)e->rlen;
            break;
        }
        case PT_CMD_GETREGS: {
            u32 n = pt_build_regset(c, (u32)e->addr, e->data);
            e->rlen = n;
            e->result = n ? 0 : -EINVAL;
            break;
        }
        case PT_CMD_SETREGS:
            e->result = pt_apply_regset(c, (u32)e->addr, e->data, e->rlen);
            /* Hand the regset's own size back so the tracer can report the
             * kernel's clamped iov_len. */
            if (e->result == 0) e->rlen = pt_regset_size((u32)e->addr);
            break;
        case PT_CMD_RESUME:
            g_ptrace_syscall_armed = (e->arg == PT_RES_SYSCALL);
            g_ptrace_singlestep    = (e->arg == PT_RES_SINGLESTEP);
            inject = (int)e->addr;
            if (si) memcpy(si, e->siginfo, 128);   /* as a SETSIGINFO left it */
            e->result = 0;
            __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE);
            leave = 1;
            break;
        case PT_CMD_DETACH:
            inject = (int)e->addr;
            if (si) memcpy(si, e->siginfo, 128);   /* before the link is freed */
            e->result = 0;
            /* Answer *before* releasing the link: pt_self_detach frees the
             * registry slot, which a tracer still waiting on the mailbox would
             * read as "the tracee vanished" and report as ESRCH. */
            __atomic_add_fetch(&e->done_seq, 1, __ATOMIC_RELEASE);
            fx_wake(&e->done_seq);
            pt_self_detach();
            return inject;
        default:
            e->result = -EIO;
            break;
        }
        __atomic_add_fetch(&e->done_seq, 1, __ATOMIC_RELEASE);
        fx_wake(&e->done_seq);
        if (leave) return inject;
    }
}

/* Publish a stop and park until the tracer resumes us. Returns the signal to
 * inject (0 = none). `si` is the stop's siginfo (NULL: a stop that has none),
 * and comes back as the tracer left it -- rewritten by PTRACE_SETSIGINFO, and
 * by ptrace_signal's own rule when the tracer resumed us with a signal other
 * than the one it names: SI_USER, from the tracer. */
static int pt_stop(CPU *c, int stop_sig, int event, int syscall_stop, u8 *si) {
    PtLink *e = g_self_link;
    if (!e) return stop_sig;
    /* Snapshot the mailbox sequence before publishing the stop: a command the
     * tracer posts after it observes STOPPED then always advances past this,
     * so the service loop cannot miss it (the deadlock this closes was a flaky
     * hang when the tracer posted its first request very quickly). */
    u32 seen = __atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE);
    /* ptrace_stop: "any trap clears pending STOP trap, STOP trap clears
     * NOTIFY" -- an INTERRUPT asked for before this stop is answered by it,
     * and one asked for during it is another trap after it. */
    __atomic_store_n(&e->interrupt_pending, 0, __ATOMIC_RELEASE);
    if (event == G_PTRACE_EVENT_STOP) __atomic_store_n(&e->trap_notify, 0, __ATOMIC_RELEASE);
    e->stop_sig = (u32)stop_sig;
    e->event = (u32)event;
    e->syscall_stop = (u32)syscall_stop;
    if (si) memcpy(e->siginfo, si, 128);
    e->has_siginfo = si != NULL;
    s32 tracer = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
    pt_ru_stamp(e);
    __atomic_store_n(&e->reported, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&e->state, PT_ST_STOPPED, __ATOMIC_RELEASE);
    /* Wake the tracer's wait4/waitid: the poll-mode futex, plus the SIGCHLD +
     * wake-kick pair (pt_wake_tracer) that knocks a tracer out of a blocking
     * host wait or a gdb-style SIGCHLD event loop. */
    __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
    fx_wake(&g_tab->global_gen);
    pt_wake_tracer(tracer);
    int ns = pt_service_loop(c, e, seen, si);
    if (ns == PT_RETRAP) return ns;
    /* What the stop did not answer -- an INTERRUPT or a trap_notify that
     * came during it, a group stop begun meanwhile -- is taken at the next
     * boundary (ptrace_service_kick). */
    if (g_self_link && (__atomic_load_n(&g_self_link->interrupt_pending, __ATOMIC_ACQUIRE) ||
                        __atomic_load_n(&g_self_link->trap_notify, __ATOMIC_ACQUIRE) ||
                        pt_jc_due())) {
        g_ptrace_kick = 1;
        g_sig_npend = 1;
    }
    if (ns && si) {
        if ((u32)ns != pt_r32(si, 0)) {
            memset(si, 0, 128);
            pt_w32(si, 0, (u32)ns);
            pt_w32(si, 8, (u32)SI_USER);
            pt_w32(si, 16, (u32)tracer);
            pt_w32(si, 20, (u32)getuid());
        }
    }
    return ns;
}

/* A signal-delivery stop whose call site has no delivery of its own to hand
 * the signal to -- PTRACE_ATTACH's SIGSTOP, an auto-attached child's, a stop
 * signal routed to a traced thread, a single-step's or a legacy exec's
 * SIGTRAP. The kernel's ptrace_signal delivers what such a stop returns: the
 * signal the tracer resumed it with (nothing for 0), or the stop's own if the
 * tracer died without collecting it (pt_orphaned_sig). Here that is queued
 * for this thread as past its stop (sig_inject_local). `code`, `pid` and
 * `addr` are the siginfo the stop's own signal carries; a substitute is
 * SI_USER from the tracer (ptrace_signal's rewrite of a changed signal). */
static void pt_signal_stop(CPU *c, int sig, int event, int code, s32 pid, u64 addr) {
    u8 si[128];
    if (event) pt_si_notify(si, sig, sig | (event << 8));
    else       pt_si_signal(si, sig, code, pid, addr);
    u32 gen = __atomic_load_n(&g_machine.jc_contgen, __ATOMIC_ACQUIRE);
    int ns = pt_stop(c, sig, event, 0, si);
    if (ns > 0) sig_inject_local(ns, si, gen);
}

void ptrace_report_syscall(CPU *c, int is_exit) {
    if (!g_ptrace_active || !g_self_link) return;
    (void)is_exit;
    u8 si[128];
    pt_si_notify(si, SIGTRAP, SIGTRAP |
                 ((g_self_link->options & G_PTRACE_O_TRACESYSGOOD) ? 0x80 : 0));
    pt_stop(c, SIGTRAP, 0, 1 /* syscall stop */, si);
}

/* An event stop (fork, clone, exec, exit, ...): ptrace_event's trap. */
static void pt_event_stop(CPU *c, int event) {
    u8 si[128];
    pt_si_notify(si, SIGTRAP, (event << 8) | SIGTRAP);
    pt_stop(c, SIGTRAP, event, 0, si);
}

void ptrace_report_exec(CPU *c, s32 old_tid) {
    if (!g_ptrace_active || !g_self_link) return;
    int event = (g_self_link->options & G_PTRACE_O_TRACEEXEC) ? G_PTRACE_EVENT_EXEC : 0;
    /* Without PTRACE_O_TRACEEXEC the report is the legacy one, a real SIGTRAP
     * the process sends itself (send_sig) -- and only to a tracer that
     * PTRACE_ATTACHed: a SEIZE'd tracee is told nothing (ptrace_event). */
    if (!event && g_self_link->seize) return;
    /* After execve a fresh tracee is stopped again and must be re-armed by the
     * tracer, so drop any prior syscall/step arming. */
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    /* exec_binprm's ptrace_event(PTRACE_EVENT_EXEC, old_vpid): the tid the
     * exec'ing thread had, which a tracer following threads needs to retire
     * that tid (it will never hear of it again). */
    g_self_link->eventmsg = (u64)(u32)old_tid;
    if (event) pt_event_stop(c, event);
    else       pt_signal_stop(c, SIGTRAP, 0, SI_USER, (s32)getpid(), 0);
}

/* Release the calling thread's own link without a report: the kernel's
 * release_task of a leader de_thread replaced, which wakes the tracer (it may
 * be asleep in wait4) and tells it nothing. */
static void pt_release_silent(struct Machine *m) {
    PtLink *e = g_self_link;
    int was = g_ptrace_active || e;   /* a zombie leader's link still counts */
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    g_ptrace_skip_syscall_stop = 0;
    if (!e) return;
    s32 tr = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
    pt_free(e);
    if (was) pt_traced_dec(m);
    __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
    fx_wake(&g_tab->global_gen);
    pt_wake_tracer(tr);
}

void *ptrace_exec_handover(void) {
    PtLink *e = g_self_link;
    /* The link, and the process's count of traced threads with it, pass to
     * the main thread as they are: nothing is reported, and nothing freed. */
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    g_ptrace_skip_syscall_stop = 0;
    return e;
}

void ptrace_exec_takeover(CPU *c, void *link) {
    pt_release_silent(c->m);
    PtLink *e = link;
    if (!e) return;
    /* Keyed by the main tid from here on: the tracer finds the new image's
     * stops under the pid, as it would the renumbered exec'ing thread's. */
    __atomic_store_n(&e->tracee, (s32)g_tls.tid, __ATOMIC_RELEASE);
    g_self_link = e;
    g_ptrace_active = 1;
}

void ptrace_leader_zombie(void) {
    /* Not a tracee in anything it does from here on -- it runs nothing -- but
     * its link, and its place in the traced count that keeps the death
     * catchers installed, stay until the group's exit publishes the death or
     * an execve revives the thread (pt_release_silent). */
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    g_ptrace_skip_syscall_stop = 0;
}

int ptrace_report_signal(CPU *c, int sig, u8 *si) {
    if (!g_ptrace_active || !g_self_link || sig == SIGKILL) return sig;
    /* A plain signal-delivery-stop, a stop signal's included: the group stop
     * it may bring is a trap of its own, once the tracer resumes the tracee
     * with the signal (do_signal_stop, pt_jobctl_trap). A SEIZEd tracee's
     * stop signal used to be reported as the group stop straight away. */
    return pt_stop(c, sig, 0, 0, si);
}

/* Synchronous-fault stop (software breakpoint BRK, SIGSEGV/SIGBUS/SIGILL/...):
 * report the signal to the tracer with precise siginfo (si_code and, for the
 * fault families, si_addr) before the guest handler/fatal decision. Returns 0
 * if the tracer suppressed it (resume the guest), else the signal to deliver
 * (the original, or one the tracer substituted). SIGKILL is never intercepted. */
int ptrace_report_fault(CPU *c, int sig, u8 *si) {
    if (!g_ptrace_active || !g_self_link || sig == SIGKILL) return sig;
    return pt_stop(c, sig, 0, 0, si);
}

void ptrace_report_singlestep(CPU *c) {
    if (!g_ptrace_active || !g_self_link) return;
    /* A real SIGTRAP (the kernel's single-step handler forces TRAP_TRACE at
     * the pc), stopped for like any signal. */
    pt_signal_stop(c, SIGTRAP, 0, 2 /* TRAP_TRACE */, 0, c->pc);
}

void ptrace_report_exit_stop(CPU *c, int wstatus) {
    if (!g_ptrace_active || !g_self_link) return;
    if (!(g_self_link->options & G_PTRACE_O_TRACEEXIT)) return;
    /* PTRACE_EVENT_EXIT: park before actually exiting, exposing the pending
     * wait-status word via PTRACE_GETEVENTMSG so the tracer can read final
     * registers/exit code. On resume the caller proceeds to the real exit. */
    g_self_link->eventmsg = (u64)(u32)wstatus;
    pt_event_stop(c, G_PTRACE_EVENT_EXIT);
}

/* do_jobctl_trap, with get_signal's loop around it: while a job-control trap
 * is due -- a group stop to take part in (pt_jc_due, or `participate` for
 * the thread that began it), and for a SEIZEd tracee an INTERRUPT or a change
 * of group-stop state (interrupt_pending, trap_notify) -- the tracee traps. A
 * SEIZEd one with PTRACE_EVENT_STOP: the stop signal while a group stop is in
 * progress or complete, SIGTRAP otherwise, with ptrace_do_notify's siginfo.
 * An ATTACHed one has only the group stop: a plain stop of its signal with no
 * siginfo at all (ptrace_stop's NULL). The signal a tracer resumes a trap
 * with is ignored, as do_jobctl_trap ignores it; a listening trap that a
 * notify or an interrupt ended traps again. A tracer gone during the trap
 * leaves the group stop to be taken part in again, untraced (__ptrace_unlink
 * re-arms JOBCTL_STOP_PENDING). */
static void pt_jobctl_trap(CPU *c, int participate) {
    for (;;) {
        PtLink *e = g_self_link;
        if (!e || !g_ptrace_active) return;
        if (pt_jc_due()) {
            participate = 1;
            g_tls.jc_seen = __atomic_load_n(&g_machine.jc_gseq, __ATOMIC_ACQUIRE);
        }
        if (!participate &&
            !(e->seize && (__atomic_load_n(&e->interrupt_pending, __ATOMIC_ACQUIRE) ||
                           __atomic_load_n(&e->trap_notify, __ATOMIC_ACQUIRE))))
            return;
        participate = 0;
        int active = (int)__atomic_load_n(&g_machine.jc_active, __ATOMIC_ACQUIRE);
        int gsig = (int)__atomic_load_n(&g_machine.jc_sig, __ATOMIC_ACQUIRE);
        pt_in_jobctl = 1;
        pt_orphaned = 0;
        if (e->seize) {
            int signr = active ? gsig : SIGTRAP;
            u8 si[128];
            pt_si_notify(si, signr, signr | (G_PTRACE_EVENT_STOP << 8));
            pt_stop(c, signr, G_PTRACE_EVENT_STOP, 0, si);
        } else {
            pt_stop(c, gsig, 0, 0, NULL);
        }
        pt_in_jobctl = 0;
        if (pt_orphaned) {
            if (__atomic_load_n(&g_machine.jc_active, __ATOMIC_ACQUIRE))
                g_tls.jc_seen = __atomic_load_n(&g_machine.jc_gseq, __ATOMIC_ACQUIRE) - 1;
            return;
        }
    }
}

/* What is due at the run-loop boundary once a kick flagged it (the tracer's
 * ATTACH/SEIZE/INTERRUPT, or a group stop calling this thread out), taken in
 * get_signal's order, ahead of any signal: a pending attach to adopt (SEIZE
 * silently; ATTACH with its SIGSTOP queued, sig_raise_attach_stop), then the
 * job-control traps of a tracee (pt_jobctl_trap) -- or, untraced, the part
 * a thread takes in a group stop by parking until SIGCONT (sig_jc_park),
 * which an attach ends: the thread then traps into the stop, as the kernel's
 * attach turns a stopped task into a traced one. The call the kick cut short
 * is the stop's, and resumes as one no handler ran for (sig_after_trap). */
void ptrace_jobctl_service(CPU *c) {
    for (;;) {
        if (g_tab && !g_ptrace_active) {
            /* The kick was thread-targeted (rt_tgsigqueueinfo), so the pending
             * attach to adopt is the one keyed by this thread's own tid. */
            PtLink *e = pt_find((s32)g_tls.tid);
            if (e && __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) > 0 &&
                __atomic_load_n(&e->attach_pending, __ATOMIC_ACQUIRE)) {
                g_self_link = e;
                g_ptrace_active = 1;
                pt_traced_inc(c->m);   /* catch every signal, to report it */
                /* Stopped by the host when attached, and woken to adopt by
                 * the tracer (ptrace_wake_stopped): the kernel's attach makes
                 * a stopped task a traced one still in its group stop
                 * (JOBCTL_TRAP_STOP), so this thread traps into one, and the
                 * others -- continued by the wake -- stop again. Of which
                 * stop signal is not to be read anywhere: SIGSTOP. */
                if (__atomic_exchange_n(&e->attach_stopped, 0, __ATOMIC_ACQ_REL)) {
                    __atomic_store_n(&g_machine.jc_sig, SIGSTOP, __ATOMIC_RELEASE);
                    __atomic_add_fetch(&g_machine.jc_gseq, 1, __ATOMIC_SEQ_CST);
                    __atomic_store_n(&g_machine.jc_active, 1, __ATOMIC_RELEASE);
                    thr_kick_all((s32)g_tls.tid);
                }
                /* ATTACH: the SIGSTOP ptrace_attach sends (SEND_SIG_PRIV) --
                 * queued on this thread, to be taken in the kernel's order
                 * with what else is pending, and reported as it is taken. */
                if (!e->seize) sig_raise_attach_stop();
                /* Adopted, catchers and all: the tracer's ptrace() may
                 * return (it waits for this). */
                __atomic_store_n(&e->attach_pending, 0, __ATOMIC_RELEASE);
                fx_wake(&e->attach_pending);
            }
        }
        if (g_ptrace_active && g_self_link) {
            PtLink *e = g_self_link;
            if (pt_jc_due() ||
                (e->seize && (__atomic_load_n(&e->interrupt_pending, __ATOMIC_ACQUIRE) ||
                              __atomic_load_n(&e->trap_notify, __ATOMIC_ACQUIRE)))) {
                pt_jobctl_trap(c, 0);
                sig_after_trap(c);
            } else if (!e->seize) {
                /* Neither is an ATTACHed tracee's to have. */
                __atomic_store_n(&e->interrupt_pending, 0, __ATOMIC_RELEASE);
                __atomic_store_n(&e->trap_notify, 0, __ATOMIC_RELEASE);
            }
        }
        if (!g_ptrace_active && pt_jc_due()) {
            g_tls.jc_seen = __atomic_load_n(&g_machine.jc_gseq, __ATOMIC_ACQUIRE);
            sig_jc_park(c);
            sig_after_trap(c);
            if (g_ptrace_kick) {   /* woken by a kick: an attach, maybe */
                g_ptrace_kick = 0;
                continue;
            }
        }
        return;
    }
}

void ptrace_service_kick(CPU *c) {
    g_ptrace_kick = 0;
    ptrace_jobctl_service(c);
}

void ptrace_report_exit(CPU *c, int wstatus) {
    (void)c;
    PtLink *e = g_self_link;
    int was = g_ptrace_active;
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    g_ptrace_skip_syscall_stop = 0;
    if (was) pt_traced_dec(&g_machine);
    if (!e) return;
    /* Publish a synthetic exit for the tracer to collect (it frees the link)
     * whenever it cannot reap this death through the host wait: always for a
     * secondary thread (a thread death is never a host-waitable event), and
     * for a process whose tracer is not its host parent (strace -p, or an
     * auto-attached fork child). A direct child's tracer IS its host parent
     * and reaps it through the host wait, so just free. */
    s32 tr = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
    if (tr > 0 && ((s32)g_tls.tid != (s32)getpid() || tr != (s32)getppid())) {
        e->exit_status = wstatus;
        pt_ru_stamp(e);            /* the tracer's wait4 rusage for this death */
        __atomic_store_n(&e->state, PT_ST_EXITED, __ATOMIC_RELEASE);
        __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
        fx_wake(&g_tab->global_gen);
        pt_wake_tracer(tr);   /* SIGCHLD event loop + blocked-wait kick */
        return;   /* keep the link; the tracer frees it on collect */
    }
    pt_free(e);
}

/* Whole-process death: exit_group(2) or a terminating signal. The sibling
 * threads die with the process without running their own exit paths (a parked
 * one dies inside its service loop), so the exiting thread publishes the
 * synthetic exit for every live tracee link of its thread group. The
 * host-reap exception mirrors ptrace_report_exit: a main-thread link whose
 * tracer is the host parent is reaped through the host wait (the process
 * death IS host-visible), so that link is left for ptrace_note_reaped. */
void ptrace_report_exit_group(int wstatus) {
    int was = g_ptrace_active;
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    g_ptrace_skip_syscall_stop = 0;
    if (was) pt_traced_dec(&g_machine);
    if (!g_tab) return;
    /* Links exist only once someone traces; skip the scan in the common
     * untraced exit. */
    if (!__atomic_load_n(&g_tab->any_trace, __ATOMIC_ACQUIRE)) return;
    s32 me = (s32)getpid(), ppid = (s32)getppid();
    int published = 0;
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0 || e->tgid != me) continue;
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED)
            continue;                       /* already published */
        s32 tr = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
        if (tr <= 0) { pt_free(e); continue; }
        if (t == me && tr == ppid) continue;   /* host wait reaps this death */
        e->exit_status = wstatus;
        /* Group-wide accounting, so the dying thread's own sample is equally
         * true of the siblings it is publishing on behalf of. */
        pt_ru_stamp(e);
        __atomic_store_n(&e->state, PT_ST_EXITED, __ATOMIC_RELEASE);
        pt_wake_tracer(tr);                 /* SIGCHLD loop + blocked-wait kick */
        published = 1;
    }
    if (published) {
        __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
        fx_wake(&g_tab->global_gen);
    }
}

/* ---- fork/clone event stops (PTRACE_O_TRACEFORK/VFORK/CLONE) ---- */
int ptrace_self_active(void) { return g_ptrace_active; }

u32 ptrace_self_options(void) {
    return g_self_link ? __atomic_load_n(&g_self_link->options, __ATOMIC_ACQUIRE) : 0;
}

s32 ptrace_self_tracer(void) {
    return g_self_link ? __atomic_load_n(&g_self_link->tracer, __ATOMIC_ACQUIRE) : 0;
}

u32 ptrace_self_seize(void) {
    return g_self_link ? g_self_link->seize : 0;
}

/* Tracer of an arbitrary guest thread, 0 if it is not being traced.
 *
 * Answers /proc/<tid>/status TracerPid (sys_procfs.c), which the host file
 * cannot: this ptrace never host-attaches -- a tracee services its tracer's
 * requests about itself through the mailbox above -- so the host task has no
 * tracer to report even while a guest gdb has it stopped. Any process may ask
 * about any thread, hence the registry scan rather than g_self_link. Guest tid
 * == host tid, so `tid` is both what a link is keyed by and what the caller
 * read out of the status file's Pid: line. */
s32 ptrace_tracer_of(s32 tid) {
    if (!g_tab || tid <= 0) return 0;
    /* Links exist only once someone traces; skip the scan otherwise. */
    if (!__atomic_load_n(&g_tab->any_trace, __ATOMIC_ACQUIRE)) return 0;
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) != tid) continue;
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED)
            continue;                    /* dead, awaiting its tracer's wait */
        return __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
    }
    return 0;
}

/* Parent side: report the fork/clone event stop, carrying the new child's pid
 * for PTRACE_GETEVENTMSG. */
void ptrace_report_event(CPU *c, int event, u64 msg) {
    if (!g_ptrace_active || !g_self_link) return;
    g_self_link->eventmsg = msg;
    pt_event_stop(c, event);
}

/* Child side of a clone/fork. `event` is nonzero when the parent's tracer is
 * following this creation (PTRACE_O_TRACE{FORK,VFORK,CLONE}); the child then
 * auto-attaches to the same tracer and reports an initial (SIGSTOP) stop.
 * Otherwise it runs untraced.
 *
 * What it inherits -- tracer, options, attach flavor -- arrives as arguments,
 * sampled by the parent before the fork, and NOT read here out of the inherited
 * g_self_link pointer. The pointer itself stays valid (the registry is shared at
 * the same address), but what it points at does not: by the time the child runs,
 * the parent has published its own fork event stop, and a tracer that answers it
 * with PTRACE_DETACH frees that link. Reading it then yields tracer 0 at best --
 * a followed fork silently losing its child, where the kernel fixes the child's
 * tracer atomically at clone time -- and, once the freed slot is re-claimed (a
 * strace -f session recycles low slots constantly), a *stranger's* tracer and
 * options, under which this child parks in an initial stop nobody will resume.
 * The thread path has always sampled these in the creator for the same reason. */
void ptrace_fork_child(CPU *c, int event, s32 tracer, u32 options, u32 seize) {
    /* The inherited traced-thread count describes the parent's threads; only
     * the forking thread exists here, untraced until the adopt below. If the
     * parent had traced threads, re-mirror the (also inherited) catcher
     * dispositions back to the untraced state. */
    int inherited = __atomic_exchange_n(&g_ptrace_traced, 0, __ATOMIC_SEQ_CST);
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    g_ptrace_skip_syscall_stop = 0;
    /* A kick the parent's handler had flagged but not yet serviced: it was aimed
     * at the parent's link, which is not ours. Everything else about a pending
     * kick (the queued signal itself) is not inherited across fork anyway --
     * though a kick of our own may have landed in this flag already (below). */
    g_ptrace_kick = 0;
    if (!event || tracer <= 0) {
        if (inherited) sig_trace_update_all(c->m);
        /* Not followed: a fresh untraced pid -- but one clone(2) has already
         * returned to the parent, which may have SEIZEd it (or handed it to a
         * tracer) before this thread got here, its kick landing in the flag
         * just cleared. Re-flag it, or the attach waits for another kick. */
        PtLink *e = pt_find(getpid());
        if (e && __atomic_load_n(&e->attach_pending, __ATOMIC_ACQUIRE)) {
            g_ptrace_kick = 1;
            g_sig_npend = 1;               /* out of the fast path to adopt it */
        }
        return;
    }
    PtLink *e = pt_claim(getpid(), getpid());
    if (!e) {
        if (inherited) sig_trace_update_all(c->m);
        return;                            /* registry full: degrade to untraced */
    }
    __atomic_store_n(&e->options, options, __ATOMIC_RELAXED);  /* options are inherited */
    e->seize = seize;
    __atomic_store_n(&e->tracer, tracer, __ATOMIC_RELEASE);
    __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);
    g_self_link = e;
    g_ptrace_active = 1;
    pt_traced_inc(c->m);   /* catch default-fatal signals to report them */
    /* Initial attach stop: an auto-attached child of a SEIZE'd tracee stops
     * with PTRACE_EVENT_STOP, of an ATTACH'd one with SIGSTOP (kernel
     * behavior). The tracer sees it, (re)sets options and resumes us. */
    if (seize) {   /* ptrace_init_task's JOBCTL_TRAP_STOP: listenable */
        __atomic_store_n(&e->interrupt_pending, 1, __ATOMIC_RELEASE);
        pt_jobctl_trap(c, 0);
    } else {
        pt_signal_stop(c, SIGSTOP, 0, SI_USER, 0, 0);   /* sigaddset'd */
    }
    /* On resume the tracer has typically armed PTRACE_SYSCALL; skip the spurious
     * syscall-exit of the clone we were born from (we never entered it). */
    if (g_ptrace_syscall_armed)
        g_ptrace_skip_syscall_stop = 1;
}

/* ---- CLONE_THREAD auto-attach (PTRACE_O_TRACECLONE): the two halves ---- */
/* Claim half, called on the new host thread *before* the clone startup
 * handshake wake: once the creator can report PTRACE_EVENT_CLONE the new tid
 * is already registry-visible, so a tracer's wait4 poll on it never sees a
 * not-a-tracee window. `tracer` <= 0 (creator untraced or not followed)
 * leaves the thread untraced. */
void ptrace_thread_child_claim(s32 tracer, u32 options, u32 seize) {
    if (tracer <= 0 || !g_tab) return;
    PtLink *e = pt_claim((s32)g_tls.tid, (s32)getpid());
    if (!e) return;                        /* registry full: degrade to untraced */
    __atomic_store_n(&e->options, options, __ATOMIC_RELAXED);
    e->seize = seize;
    __atomic_store_n(&e->tracer, tracer, __ATOMIC_RELEASE);
    __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);
    g_self_link = e;
    g_ptrace_active = 1;
    pt_traced_inc(&g_machine);   /* catch default-fatal signals to report them */
}

/* Stop half, called *after* the handshake wake (so clone() in the creator is
 * not blocked on the tracer resuming us): park in the initial attach stop
 * before any guest code runs, exactly like an auto-attached fork child. No
 * skip_syscall_stop here: a thread starts at the run-loop top, never inside
 * the clone syscall it was born from. */
void ptrace_thread_child_stop(CPU *c) {
    if (!g_ptrace_active || !g_self_link) return;
    if (g_self_link->seize) {   /* JOBCTL_TRAP_STOP, as for a fork child */
        __atomic_store_n(&g_self_link->interrupt_pending, 1, __ATOMIC_RELEASE);
        pt_jobctl_trap(c, 0);
    } else {
        pt_signal_stop(c, SIGSTOP, 0, SI_USER, 0, 0);
    }
}

/* ---- tracee: PTRACE_TRACEME ---- */
static long ptrace_traceme(CPU *c) {
    if (!g_tab) return -EPERM;
    if (g_self_link) return -EPERM;   /* already traced */
    /* The parent has to be a guest process. getppid() is the HOST parent, and
     * for the top-level guest process that is whatever launched the emulator --
     * a shell, a build system, an init. Recorded as the tracer it became a
     * signal target: every stop this process later reaches sends that pid a
     * SIGCHLD and the reserved RT kick (pt_wake_tracer), so a guest program
     * that called TRACEME and raised SIGSTOP killed the process that started
     * the emulator. Nothing would ever collect those stops either -- a host
     * process outside the guest is not running the ptrace protocol. EPERM is
     * the answer the kernel already gives when a tracing relationship cannot be
     * established, and it matches the rest of the containment: to this guest
     * that pid does not exist (kill(2) says ESRCH, /proc hides it). The tracer
     * side (ATTACH/SEIZE) has always checked the registry this way. */
    if (!proctab_has((s32)getppid())) return -EPERM;
    PtLink *e = pt_claim((s32)g_tls.tid, (s32)getpid());
    if (!e) return -ENOMEM;
    __atomic_store_n(&e->tracer, (s32)getppid(), __ATOMIC_RELEASE);
    /* Flip the session-wide "someone is tracing" flag so every wait4 switches to
     * the polling path (a blocked host wait4 can't see a cooperative stop). */
    __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);
    g_self_link = e;
    g_ptrace_active = 1;
    pt_traced_inc(c->m);   /* catch default-fatal signals to report them */
    return 0;
}

/* ---- tracer: mailbox round-trip to a stopped tracee ---- */
/* Post a command to tracee `tid`'s mailbox (its link `e`) and wait for its
 * answer. Returns 0 once answered (the result is in e->result), or -ESRCH if the
 * tracee vanished instead -- which the caller must surface as ptrace's own
 * ESRCH, the kernel's answer for a tracee that is no longer there. On -ESRCH the
 * link may no longer be ours at all, so a caller must check this return before
 * it reads anything back out of e. */
static int pt_cmd(PtLink *e, s32 tid, u32 cmd, u64 addr, u64 arg) {
    /* The link must still be the one we resolved. A slot freed by a detach or by
     * a collected exit is handed to the next task that needs one (pt_claim scans
     * from index 0, and a strace -f session recycles low slots constantly), and
     * posting into a re-claimed link would hand our command -- a POKE, a RESUME
     * -- to a stranger parked in its own stop, who would carry it out on itself.
     * The tracee tid is the identity to check: it is what pt_find matched, and
     * pt_claim publishes it last, after the rest of the link is built. Checked
     * before the post and again on every wake, since a reclaim can land at
     * either point. */
    if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) != tid) return -ESRCH;
    e->cmd = cmd;
    e->addr = addr;
    e->arg = arg;
    u32 d = __atomic_load_n(&e->done_seq, __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&e->cmd_seq, 1, __ATOMIC_RELEASE);
    fx_wake(&e->cmd_seq);
    while (__atomic_load_n(&e->done_seq, __ATOMIC_ACQUIRE) == d) {
        /* Tracee gone while we waited -- its slot freed (detached) or already
         * re-claimed by another task, or its exit published (a sibling thread's
         * exit_group fan-out flips a parked thread's link to EXITED without it
         * ever answering): bail so ptrace doesn't hang. A bail on a link still
         * ours re-reads done_seq first, so an answer that landed between the loop
         * test and the check is never discarded -- and only such a link is
         * written to, since e->result in a re-claimed one is someone else's. */
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        int ours = (t == tid);
        if (!ours ||
            __atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED) {
            if (ours) {
                if (__atomic_load_n(&e->done_seq, __ATOMIC_ACQUIRE) != d) break;
                e->result = -ESRCH;
            }
            return -ESRCH;
        }
        fx_wait(&e->done_seq, d, 500);
        /* A full slice with the mailbox still unanswered: a tracee SIGKILLed
         * while parked in its service loop leaves a live-looking link (nothing
         * runs to publish an exit) and is never going to answer, so check the
         * host task itself. Only after a timeout, so the normal round-trip --
         * which the tracee answers immediately -- never touches /proc. */
        if (__atomic_load_n(&e->done_seq, __ATOMIC_ACQUIRE) == d &&
            pt_task_dead(tid)) {
            if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) == tid)
                e->result = -ESRCH;
            return -ESRCH;
        }
    }
    return 0;
}

/* Kick a running tracee task to a stop point: queue the reserved signal at the
 * specific host thread (guest tid == host tid) carrying the magic so its
 * sig_kick_net tells it apart from a guest signal. Thread-targeted delivery
 * matters: the kick handler sets *thread-local* flags, and a process-directed
 * sigqueue could land on any thread of a multithreaded tracee. */
static void pt_send_kick(s32 tgid, s32 tid) {
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = PTRACE_KICKSIG;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = getuid();
    si.si_value.sival_int = PT_KICK_MAGIC;
    syscall(SYS_rt_tgsigqueueinfo, (pid_t)tgid, (pid_t)tid, PTRACE_KICKSIG, &si);
}

/* Does thread group `id` (a pid, or any thread's tid) have a traced thread?
 * A job-control signal for it is not the host's to send: its SIGSTOP would
 * freeze every traced thread where its tracer cannot reach it, and the five
 * go on the kick signal, in the order sent (signal.c, sig_send_jc). */
int ptrace_group_traced(s32 id) {
    if (!g_tab || id <= 0 || !__atomic_load_n(&g_tab->any_trace, __ATOMIC_ACQUIRE))
        return 0;
    PtLink *hit = pt_find(id);
    s32 tgid = hit ? hit->tgid : (proctab_has(id) ? id : proctab_task_tgid(id));
    if (tgid <= 0) return 0;
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0 || e->tgid != tgid) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) <= 0) continue;
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED) continue;
        return 1;
    }
    return 0;
}

/* The group-stop state of thread group `tgid` changed -- a group stop began,
 * or a SIGCONT ended one: every SEIZEd tracee of it is told with a
 * trap_notify (ptrace_trap_notify), which a listening one wakes to at once
 * and a running one, kicked if `kick`, at its next boundary; one in another
 * stop takes it after that stop. Async-signal-safe: SIGCONT's capture calls
 * it (signal.c, sig_jc_continue). */
void ptrace_jc_notify(s32 tgid, int kick) {
    if (!g_tab || !__atomic_load_n(&g_tab->any_trace, __ATOMIC_ACQUIRE)) return;
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0 || e->tgid != tgid || !e->seize) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) <= 0) continue;
        u32 st = __atomic_load_n(&e->state, __ATOMIC_ACQUIRE);
        if (st == PT_ST_EXITED) continue;
        __atomic_store_n(&e->trap_notify, 1, __ATOMIC_RELEASE);
        if (__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE)) fx_wake(&e->cmd_seq);
        else if (kick && st == PT_ST_RUNNING) pt_send_kick(tgid, t);
    }
}

/* Bring thread `tid` of this process to its run-loop boundary, where
 * ptrace_service_kick finds what is due (sys_proc.c, thr_kick_all). */
void ptrace_kick_thread(s32 tid) {
    pt_send_kick((s32)getpid(), tid);
}

/* process_vm_readv/writev remote side: transfer up to len bytes between the host
 * buffer `buf` and a STOPPED tracee `pid`'s guest memory at guest VA `rva`.
 * write != 0 sends host -> tracee, else tracee -> host. Returns the byte count
 * transferred (0..len; short if the tracee memory faults partway), or a negative
 * errno if `pid` is not a stopped tracee of the caller. Chunks through the
 * fixed-size mailbox; the tracee stays parked in its service loop across chunks
 * (each PT_CMD_READ/WRITE is answered without resuming it). */
long ptrace_vm_block(s32 pid, u64 rva, u8 *buf, size_t len, int write) {
    if (!g_tab) return -EPERM;
    PtLink *e = pt_find(pid);
    if (!e || __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != (s32)getpid())
        return -ESRCH;
    if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_STOPPED)
        return -ESRCH;                       /* only a parked tracee can answer */
    size_t done = 0;
    while (done < len) {
        size_t chunk = len - done;
        if (chunk > PT_MBOX) chunk = PT_MBOX;
        /* A staged payload the round-trip below then refuses to post (the link
         * was re-claimed) is inert: nobody reads mailbox data without a command. */
        if (write) memcpy(e->data, buf + done, chunk);
        if (pt_cmd(e, pid, write ? PT_CMD_WRITE : PT_CMD_READ,
                   rva + done, chunk) < 0)
            return done ? (long)done : -ESRCH;   /* e is not ours to read now */
        if (e->result < 0) return done ? (long)done : (long)e->result;
        size_t got = (size_t)e->result;      /* bytes the tracee actually crossed */
        if (!write && got) memcpy(buf + done, e->data, got);
        done += got;
        if (got < chunk) break;              /* tracee-side page fault: stop short */
    }
    return (long)done;
}

/* ---- tracer: guest ptrace(2) dispatch ---- */
long ptrace_syscall(CPU *c, long req, s32 pid, u64 addr, u64 data) {
    if (req == G_PTRACE_TRACEME)
        return ptrace_traceme(c);
    if (!g_tab) return -EPERM;

    /* Attach to an already-running task -- a process (pid) or any thread of one
     * (tid; strace -p / gdb -p enumerate /proc/<pid>/task and attach each):
     * claim its link, mark ourselves the tracer, and kick that specific thread
     * to adopt the attach at its next run-loop boundary. */
    if (req == G_PTRACE_ATTACH || req == G_PTRACE_SEIZE) {
        if (pid <= 0 || pid == (s32)getpid()) return -EPERM;
        s32 tgid = pid;
        if (!proctab_has(pid)) {
            /* Not a guest pid: maybe a secondary thread's tid (== host tid).
             * Its thread group must be a live guest process. */
            tgid = proctab_task_tgid(pid);   /* a thread's tid: its group (proctab.c) */
            if (tgid <= 0 || !proctab_has(tgid)) return -ESRCH;
        }
        if (tgid == (s32)getpid()) return -EPERM;   /* own thread group (kernel rule) */
        PtLink *e = pt_claim(pid, tgid);
        if (!e) return -ENOMEM;
        s32 zero = 0;
        if (!__atomic_compare_exchange_n(&e->tracer, &zero, (s32)getpid(), false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return -EPERM;                       /* already traced by someone */
        e->seize = (req == G_PTRACE_SEIZE);
        __atomic_store_n(&e->options,
                         e->seize ? ((u32)data & G_PTRACE_O_MASK) : 0,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&e->attach_pending, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);  /* our wait4 polls */
        /* A task the host has stopped -- the whole process, as any group
         * stop does -- runs nothing, so it cannot adopt the attach: strace's
         * child stops itself before it is SEIZEd, and was left there with
         * nobody to continue it. The kernel's attach makes a stopped task a
         * traced one, still in its group stop; here it is told so on its link
         * and woken to adopt, into a group stop of the emulator's. */
        if (ptrace_task_stopped(tgid)) {
            __atomic_store_n(&e->attach_stopped, 1, __ATOMIC_RELEASE);
            ptrace_wake_stopped(tgid);
        }
        pt_send_kick(tgid, pid);
        /* The kernel's attach is done when ptrace() returns: whatever the
         * caller sends next finds the tracee traced -- a stop signal, a
         * SIGCONT, one it ignores -- and it is reported. Here the tracee
         * becomes one at its next boundary, where it adopts the attach and
         * catches every signal (ptrace_jobctl_service); a signal sent before
         * that was the host's to act on, and a SIGTSTP stopped the process
         * outright. So wait for the adoption -- a little: a tracee that
         * cannot get there yet (stopped by the host, in a vfork parent's
         * wait) adopts when it can, as it always did. */
        for (int i = 0; i < 20 && __atomic_load_n(&e->attach_pending, __ATOMIC_ACQUIRE) &&
                        __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) == pid; i++)
            fx_wait(&e->attach_pending, 1, 10);
        return 0;
    }

    PtLink *e = pt_find(pid);
    if (!e || __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != (s32)getpid())
        return -ESRCH;

    /* KILL and INTERRUPT are the two requests the kernel takes whatever the
     * tracee is doing (ptrace_check_attach's ignore_state). */
    if (req == G_PTRACE_KILL) {
        kill(e->tgid, SIGKILL);   /* pid may be a thread tid: kill its process */
        return 0;
    }
    /* Stop a SEIZE'd tracee on demand -- only a SEIZEd one: an ATTACHed
     * tracee has no such stop (EIO). JOBCTL_TRAP_STOP: at least one trap
     * follows. A running tracee is kicked to it; one in a stop takes it after
     * that stop, which is left alone; a listening one traps again at once
     * (ptrace_signal_wake_up(child, LISTENING)). */
    if (req == G_PTRACE_INTERRUPT) {
        if (!e->seize) return -EIO;
        __atomic_store_n(&e->interrupt_pending, 1, __ATOMIC_RELEASE);
        if (__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE))
            fx_wake(&e->cmd_seq);
        else if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_STOPPED)
            pt_send_kick(e->tgid, pid);
        return 0;
    }

    /* Everything else is ptrace_check_attach's: a tracee in a stop of its
     * own, where it answers for itself -- one running, or listening (LISTEN
     * makes a stop "not TRACED" to ptrace(2) and wait(2) alike), is ESRCH.
     * SETOPTIONS, GETEVENTMSG, GETSIGINFO, DETACH and LISTEN included: they
     * used to be answered from the link whatever the tracee was doing, and a
     * resume request on a listening tracee cancelled the listen. */
    if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_STOPPED ||
        __atomic_load_n(&e->listening, __ATOMIC_ACQUIRE))
        return -ESRCH;

    switch (req) {
    case G_PTRACE_SETOPTIONS:
        __atomic_store_n(&e->options, (u32)data & G_PTRACE_O_MASK, __ATOMIC_RELEASE);
        return 0;
    case G_PTRACE_GETEVENTMSG: {
        u64 msg = e->eventmsg;
        return copy_to_guest(c, data, &msg, 8) < 0 ? -EFAULT : 0;
    }
    case G_PTRACE_GETSIGINFO:
        /* The stop's own siginfo (ptrace_getsiginfo): EINVAL for a stop that
         * has none, an ATTACHed tracee's group-stop. */
        if (!e->has_siginfo) return -EINVAL;
        return copy_to_guest(c, data, e->siginfo, sizeof e->siginfo) < 0 ? -EFAULT : 0;
    case G_PTRACE_PEEKTEXT:
    case G_PTRACE_PEEKDATA:
        if (pt_cmd(e, pid, PT_CMD_PEEK, addr, 0) < 0) return -ESRCH;
        if (e->result < 0) return -EIO;
        return copy_to_guest(c, data, e->data, 8) < 0 ? -EFAULT : 0;
    case G_PTRACE_PEEKUSR:
        if (pt_cmd(e, pid, PT_CMD_PEEKUSR, addr, 0) < 0) return -ESRCH;
        if (e->result < 0) return -EIO;
        return copy_to_guest(c, data, e->data, 8) < 0 ? -EFAULT : 0;
    case G_PTRACE_POKETEXT:
    case G_PTRACE_POKEDATA:
        if (pt_cmd(e, pid, PT_CMD_POKE, addr, data) < 0) return -ESRCH;
        return e->result < 0 ? -EIO : 0;
    case G_PTRACE_POKEUSR:
        return -EIO;   /* user-area writes not modelled (gdb uses SETREGSET) */
    case G_PTRACE_SETSIGINFO: {
        /* ptrace_setsiginfo: the tracer's siginfo replaces the stop's, read as
         * copy_siginfo_from_user reads one -- kernel_siginfo's 48 bytes, and
         * for a layout the kernel does not know the rest, which must be zero
         * -- and is what the signal is delivered with if the tracee is resumed
         * with the signal it names. A stop with none (an ATTACHed group-stop)
         * takes none: EINVAL. */
        u8 si[128];
        memset(si, 0, sizeof si);
        if (copy_from_guest(c, si, data, 48) < 0) return -EFAULT;
        if (!sig_layout_known((int)pt_r32(si, 0), (s32)pt_r32(si, 8))) {
            u8 rest[80];
            if (copy_from_guest(c, rest, data + 48, sizeof rest) < 0) return -EFAULT;
            for (size_t i = 0; i < sizeof rest; i++)
                if (rest[i]) return -E2BIG;
        }
        if (!e->has_siginfo) return -EINVAL;
        memcpy(e->siginfo, si, sizeof si);
        return 0;
    }
    case G_PTRACE_GETREGSET: {
        GIovec iov;
        if (copy_from_guest(c, &iov, data, sizeof iov) < 0) return -EFAULT;
        if (pt_cmd(e, pid, PT_CMD_GETREGS, addr, 0) < 0) return -ESRCH;
        if (e->result < 0) return -EINVAL;
        u32 n = e->rlen;
        if (iov.iov_len < n) n = (u32)iov.iov_len;
        if (n && copy_to_guest(c, iov.iov_base, e->data, n) < 0) return -EFAULT;
        /* The kernel returns iov_len clamped to what it copied, not the
         * regset's full size: a caller with a short buffer must not be told
         * more was written than fits in it. */
        iov.iov_len = n;
        return copy_to_guest(c, data, &iov, sizeof iov) < 0 ? -EFAULT : 0;
    }
    case G_PTRACE_SETREGSET: {
        GIovec iov;
        if (copy_from_guest(c, &iov, data, sizeof iov) < 0) return -EFAULT;
        u32 n = iov.iov_len > PT_MBOX ? PT_MBOX : (u32)iov.iov_len;
        if (n && copy_from_guest(c, e->data, iov.iov_base, n) < 0) return -EFAULT;
        e->rlen = n;
        if (pt_cmd(e, pid, PT_CMD_SETREGS, addr, 0) < 0) return -ESRCH;
        if (e->result < 0) return (long)e->result;
        if (e->rlen < iov.iov_len) iov.iov_len = e->rlen;   /* clamped, as above */
        return copy_to_guest(c, data, &iov, sizeof iov) < 0 ? -EFAULT : 0;
    }
    case G_PTRACE_CONT:
        return pt_cmd(e, pid, PT_CMD_RESUME, data, PT_RES_CONT);
    case G_PTRACE_SYSCALL:
        return pt_cmd(e, pid, PT_CMD_RESUME, data, PT_RES_SYSCALL);
    case G_PTRACE_SINGLESTEP:
        return pt_cmd(e, pid, PT_CMD_RESUME, data, PT_RES_SINGLESTEP);
    case G_PTRACE_DETACH:
        return pt_cmd(e, pid, PT_CMD_DETACH, data, 0);
    case G_PTRACE_LISTEN:
        /* Only on a SEIZE'd tracee whose stop is a PTRACE_EVENT_STOP trap (a
         * group-stop or an INTERRUPT), by its siginfo, as the kernel asks --
         * a signal-delivery-stop of a stop signal is not one (EIO). Keep it
         * parked-but-listening: it does not resume, and is no stop to
         * ptrace(2) or wait(2) until a trap_notify (the group-stop state
         * changing: a SIGCONT, a new group stop) or an INTERRUPT has it trap
         * again (pt_service_loop) -- at once if the notify came during this
         * trap already. No mailbox round-trip. */
        if (!e->seize) return -EIO;
        if (!e->has_siginfo ||
            (pt_r32(e->siginfo, 8) >> 8) != G_PTRACE_EVENT_STOP)
            return -EIO;
        __atomic_store_n(&e->listening, 1, __ATOMIC_RELEASE);
        if (__atomic_load_n(&e->trap_notify, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&e->interrupt_pending, __ATOMIC_ACQUIRE))
            fx_wake(&e->cmd_seq);
        return 0;
    default:
        return -EIO;
    }
}

/* ---- tracer: wait4/waitid integration ---- */
/* Is tracee link `e` (task `t`) one the wait selects (the kernel's
 * eligible_pid)? A group is asked of the task itself while it is there --
 * the kernel reads task_pgrp at the wait -- and of the one it had when it
 * died or last stopped once it is not: a death published and reaped by its
 * real parent, or a SIGKILL nobody saw. */
static int pt_selects(const PtLink *e, s32 t, PtWaitSel sel) {
    switch (sel.type) {
    case PT_SEL_PID:
        return t == sel.id;
    case PT_SEL_PGID: {
        s32 g = e->pgid;
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_EXITED) {
            pid_t now = getpgid((pid_t)t);
            if (now > 0) g = (s32)now;
        }
        return g == sel.id;
    }
    default:
        return 1;
    }
}

int ptrace_collect(PtWaitSel sel, int flags, int *status, s32 *outpid, PtRusage *ru) {
    if (!g_tab) return 0;
    s32 me = (s32)getpid();
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) <= 0) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me) continue;
        s32 t = e->tracee;
        if (!pt_selects(e, t, sel)) continue;
        u32 st_state = __atomic_load_n(&e->state, __ATOMIC_ACQUIRE);
        /* Synthetic exit of an auto-attached tracee we cannot host-reap. */
        if (st_state == PT_ST_EXITED) {
            if (!(flags & PT_WAIT_EXITS)) continue;
            *status = e->exit_status;
            *outpid = t;
            if (ru) *ru = e->ru;   /* before pt_free: the slot is reusable after */
            if (!(flags & PT_WAIT_KEEP)) pt_free(e);
            return 1;
        }
        if (st_state != PT_ST_STOPPED) continue;
        if (__atomic_load_n(&e->reported, __ATOMIC_ACQUIRE)) continue;
        /* A listening stop is not a stop to wait(2) (task_stopped_code): not
         * even one only looked at (WNOWAIT) before the LISTEN. */
        if (__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE)) continue;
        int sig = (int)e->stop_sig;
        int st;
        if (e->event) {
            /* A group-stop reports WSTOPSIG == the stop signal with EVENT_STOP in
             * the high bits; every other event (fork/exec/exit, and the SIGTRAP
             * INTERRUPT/initial-SEIZE EVENT_STOP) reports WSTOPSIG == SIGTRAP. */
            if (e->event == G_PTRACE_EVENT_STOP && pt_is_stopsig(sig))
                st = (G_PTRACE_EVENT_STOP << 16) | ((sig & 0xff) << 8) | 0x7f;
            else
                st = (((e->event << 8) | SIGTRAP) << 8) | 0x7f;
        } else {
            if (e->syscall_stop && (e->options & G_PTRACE_O_TRACESYSGOOD))
                sig |= 0x80;
            st = (sig << 8) | 0x7f;
        }
        /* The snapshot the tracee stamped when it published this stop. */
        if (ru) *ru = e->ru;
        /* Collected, unless this is a WNOWAIT look: the kernel's
         * wait_task_stopped clears the stop's code only then, and a stop
         * looked at is reported again. */
        if (!(flags & PT_WAIT_KEEP))
            __atomic_store_n(&e->reported, 1, __ATOMIC_RELEASE);
        *status = st;
        *outpid = t;
        return 1;
    }
    return 0;
}

u32 ptrace_wait_gen(void) {
    return g_tab ? __atomic_load_n(&g_tab->global_gen, __ATOMIC_ACQUIRE) : 0;
}

void ptrace_tracer_wait(u32 gen, int ms) {
    if (!g_tab) return;
    /* `gen` was sampled by the caller before it checked the registry and the
     * host WNOHANG wait, so a state change published in between mismatches
     * here and FUTEX_WAIT returns immediately (no lost wakeup). */
    fx_wait(&g_tab->global_gen, gen, ms);
}

void ptrace_note_reaped(s32 pid) {
    PtLink *e = pt_find(pid);
    if (e && __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) == (s32)getpid())
        pt_free(e);
}

int ptrace_available(void) { return g_tab != NULL; }

int ptrace_any_trace(void) {
    return g_tab && __atomic_load_n(&g_tab->any_trace, __ATOMIC_ACQUIRE);
}

int ptrace_have_tracee(PtWaitSel sel, int dead_too) {
    if (!g_tab) return 0;
    s32 me = (s32)getpid();
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me) continue;
        if (!pt_selects(e, t, sel)) continue;
        /* Dead for sure, and only then: a /proc this host will not show us
         * leaves a tracee counted, as it leaves a parked one attached. */
        if (!dead_too &&
            (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED ||
             (kill(t, 0) != 0 && errno == ESRCH) || pt_task_zombie(t)))
            continue;
        return 1;
    }
    return 0;
}

/* Single-letter state of host task `t` from /proc/<t>/stat. 0 when the file
 * cannot be opened at all -- the task is gone, or this host has no readable
 * /proc -- and '?' when it opened but could not be parsed; the two callers below
 * want opposite answers for those, so they are kept distinguishable. */
static char pt_task_state(s32 t) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)t);
    fdwin_enter();   /* a descriptor of our own, briefly (machine.h) */
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fdwin_leave(); return 0; }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    fdwin_leave();
    if (n <= 0) return '?';
    buf[n] = 0;
    char *rp = strrchr(buf, ')');               /* comm may hold spaces/parens */
    if (!rp || !rp[1]) return '?';
    return (rp[1] == ' ') ? rp[2] : rp[1];      /* "...) S ..." */
}

static int pt_state_is_dead(char st) { return st == 'Z' || st == 'X' || st == 'x'; }

int ptrace_task_stopped(s32 tgid) {
    return tgid > 0 && pt_task_state(tgid) == 'T';
}

void ptrace_wake_stopped(s32 tgid) {
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGCONT;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = getuid();
    si.si_value.sival_int = PT_STOPWAKE_MAGIC;
    syscall(SYS_rt_sigqueueinfo, (pid_t)tgid, SIGCONT, &si);
}

/* Is host task `t` dead to a tracer -- its host process gone or a zombie? A tracee
 * killed by an uncatchable SIGKILL runs no guest code, so it publishes no exit and
 * leaves a zombie its real parent has not reaped (kill(t,0) still succeeds); the
 * /proc state distinguishes a zombie from a live one. Unopenable counts as dead:
 * the caller has already waited out a mailbox timeout on it. */
static int pt_task_dead(s32 t) {
    char st = pt_task_state(t);
    return st ? pt_state_is_dead(st) : 1;
}

/* Is host task `t` a zombie -- dead, but still there because its own parent has
 * not reaped it? Deliberately conservative in the other direction: anything this
 * cannot read answers "no", so the parked-tracee check that pairs it with kill(2)
 * (pt_service_loop) never turns an unreadable /proc into a spurious detach. */
static int pt_task_zombie(s32 t) { return pt_state_is_dead(pt_task_state(t)); }

/* Backstop for a tracee that vanished at the host level without publishing an exit
 * -- an uncatchable SIGKILL (every catchable fatal signal is mediated and reports
 * its real status, so a silent death is a SIGKILL). Report a synthetic
 * WIFSIGNALED(SIGKILL) so a sibling tracer polling in wait4 does not hang. Only
 * fires for a non-child tracee; a host-child's death is reaped via the host wait.
 * Returns 1 and fills status/outpid if such a tracee is found, else 0. */
int ptrace_reap_dead(PtWaitSel sel, int keep, int *status, s32 *outpid, PtRusage *ru) {
    if (!g_tab) return 0;
    s32 me = (s32)getpid();
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me) continue;
        if (!pt_selects(e, t, sel)) continue;
        /* A stopped/exited tracee is alive-and-parked / handled by ptrace_collect. */
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED) continue;
        if (!pt_task_dead(t)) continue;
        *status = SIGKILL;            /* WIFSIGNALED(SIGKILL) */
        *outpid = t;
        /* Killed outright: no guest code ran to stamp a fresh snapshot, so this
         * is the one from its last stop (nothing better exists -- the accounting
         * died with the task). */
        if (ru) *ru = e->ru;
        if (!keep) pt_free(e);
        return 1;
    }
    return 0;
}

void ptrace_wake_waiters(void) {
    if (!g_tab) return;
    /* Poll-mode waiters exist only in tracing sessions (an untraced parent
     * blocks in the real host wait, which the kernel wakes itself); skip the
     * bump + futex syscall on the common untraced exit. */
    if (!__atomic_load_n(&g_tab->any_trace, __ATOMIC_ACQUIRE)) return;
    __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
    fx_wake(&g_tab->global_gen);
}
