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
 * so the default-terminate host catchers (sig_host_update) must stay installed
 * while *any* thread must report its stops/death, not just the calling one. */
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
static void pt_traced_dec(struct Machine *m) {
    if (__atomic_sub_fetch(&g_ptrace_traced, 1, __ATOMIC_SEQ_CST) == 0)
        sig_trace_update_all(m);
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
    u32 reported;        /* wait4 has already consumed the current stop */
    u32 stop_sig;        /* WSTOPSIG of the current stop */
    u32 event;           /* PTRACE_EVENT_* of the current stop (0 = none) */
    u32 syscall_stop;    /* current stop is a syscall-entry/exit stop */
    u32 attach_pending;  /* tracer ATTACH/SEIZE'd us: adopt at the next boundary */
    u32 interrupt_pending; /* tracer PTRACE_INTERRUPT'd us: stop at the next boundary */
    u32 stopsig_pending; /* a stop signal (SIGSTOP/...) was sent to us as a tracee:
                          * report it as a cooperative group-stop, not a host stop */
    u32 seize;           /* attached via SEIZE (no initial SIGSTOP; group stops) */
    u32 listening;       /* PTRACE_LISTEN: parked in a group/INTERRUPT stop, awaiting
                          * SIGCONT (group-stop end); "running" to data ptrace ops */
    s32 exit_status;     /* PT_ST_EXITED: wait-status word for the tracer */
    u64 eventmsg;        /* PTRACE_GETEVENTMSG payload */
    s32 si_signo, si_code, si_errno;   /* stored siginfo for GETSIGINFO */
    u64 fault_addr;      /* siginfo si_addr for fault stops (SIGSEGV/TRAP/...);
                          * not named si_addr — that is a glibc signal.h macro */
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

/* ---- futex helpers (cross-process: no FUTEX_PRIVATE_FLAG) ---- */
static void fx_wake(volatile u32 *a) {
    syscall(SYS_futex, (u32 *)a, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}
static void fx_wait(volatile u32 *a, u32 val, int ms) {
    struct timespec ts;
    if (ms >= 0) { ts.tv_sec = ms / 1000; ts.tv_nsec = (long)(ms % 1000) * 1000000L; }
    syscall(SYS_futex, (u32 *)a, FUTEX_WAIT, val, ms >= 0 ? &ts : NULL, NULL, 0);
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
        if (__atomic_compare_exchange_n(&g_tab->links[i].tracee, &expect, tracee,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            e = &g_tab->links[i];
            e->tgid = tgid;
            e->tracer = 0; e->options = 0; e->state = PT_ST_RUNNING;
            e->reported = 0; e->stop_sig = 0; e->event = 0; e->syscall_stop = 0;
            e->eventmsg = 0; e->si_signo = e->si_code = e->si_errno = 0;
            e->attach_pending = e->interrupt_pending = 0;
            e->stopsig_pending = 0; e->seize = 0; e->listening = 0;
            e->cmd_seq = e->done_seq = 0; e->cmd = PT_CMD_NONE;
            return e;
        }
    }
    return NULL;
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

/* ---- tracee: service loop + stop core ---- */
static void pt_self_detach(void) {
    PtLink *e = g_self_link;
    int was = g_ptrace_active;
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    if (e) { __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE); pt_free(e); }
    if (was) pt_traced_dec(&g_machine);   /* last one out re-mirrors dispositions */
}

/* Serve tracer commands while stopped. Returns the signal to inject on resume
 * (0 = none/suppressed), which matters for signal-delivery stops. `seen` is the
 * cmd_seq snapshot taken *before* the stop was published (see pt_stop): the
 * tracer can only post a command after observing STOPPED, so any command bumps
 * cmd_seq past `seen` and is never missed by this loop. */
static int pt_service_loop(CPU *c, PtLink *e, u32 seen) {
    int inject = 0;
    for (;;) {
        while (__atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE) == seen) {
            fx_wait(&e->cmd_seq, seen, 500);
            if (__atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE) != seen) break;
            /* Tracer vanished while we were parked: auto-detach and run free. */
            s32 tr = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
            if (tr <= 0 || (kill(tr, 0) != 0 && errno == ESRCH)) {
                pt_self_detach();
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
            if (e->addr + 8 <= sizeof(GUserRegs) && (e->addr & 7) == 0) {
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
            break;
        case PT_CMD_RESUME:
            g_ptrace_syscall_armed = (e->arg == PT_RES_SYSCALL);
            g_ptrace_singlestep    = (e->arg == PT_RES_SINGLESTEP);
            inject = (int)e->addr;
            e->result = 0;
            __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE);
            leave = 1;
            break;
        case PT_CMD_DETACH:
            inject = (int)e->addr;
            e->result = 0;
            pt_self_detach();
            leave = 1;
            break;
        default:
            e->result = -EIO;
            break;
        }
        __atomic_add_fetch(&e->done_seq, 1, __ATOMIC_RELEASE);
        fx_wake(&e->done_seq);
        if (leave) return inject;
    }
}

/* Publish a stop and park until the tracer resumes us. Returns the inject sig.
 * si_code/si_addr override the stored siginfo for a fault stop (BRK breakpoint,
 * SIGSEGV, ...); pass 0/0 for syscall/signal/event stops (si_code is then
 * event-derived, matching the wait-status high byte). */
static int pt_stop(CPU *c, int stop_sig, int event, int syscall_stop,
                   int si_code, u64 fault_addr) {
    PtLink *e = g_self_link;
    if (!e) return stop_sig;
    /* Snapshot the mailbox sequence before publishing the stop: a command the
     * tracer posts after it observes STOPPED then always advances past this,
     * so the service loop cannot miss it (the deadlock this closes was a flaky
     * hang when the tracer posted its first request very quickly). */
    u32 seen = __atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE);
    e->stop_sig = (u32)stop_sig;
    e->event = (u32)event;
    e->syscall_stop = (u32)syscall_stop;
    e->si_signo = stop_sig;
    e->si_code = si_code ? si_code : (event ? ((event << 8) | 5 /*SIGTRAP*/) : 0);
    e->fault_addr = fault_addr;
    e->si_errno = 0;
    __atomic_store_n(&e->reported, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&e->state, PT_ST_STOPPED, __ATOMIC_RELEASE);
    /* Wake the tracer's wait4/waitid: the poll-mode futex, plus the SIGCHLD +
     * wake-kick pair (pt_wake_tracer) that knocks a tracer out of a blocking
     * host wait or a gdb-style SIGCHLD event loop. */
    __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
    fx_wake(&g_tab->global_gen);
    pt_wake_tracer(__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE));
    return pt_service_loop(c, e, seen);
}

void ptrace_report_syscall(CPU *c, int is_exit) {
    if (!g_ptrace_active || !g_self_link) return;
    (void)is_exit;
    pt_stop(c, SIGTRAP, 0, 1 /* syscall stop */, 0, 0);
}

void ptrace_report_exec(CPU *c) {
    if (!g_ptrace_active || !g_self_link) return;
    int event = (g_self_link->options & G_PTRACE_O_TRACEEXEC) ? G_PTRACE_EVENT_EXEC : 0;
    /* After execve a fresh tracee is stopped again and must be re-armed by the
     * tracer, so drop any prior syscall/step arming. */
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    pt_stop(c, SIGTRAP, event, 0, 0, 0);
}

int ptrace_report_signal(CPU *c, int sig) {
    if (!g_ptrace_active || !g_self_link || sig == SIGKILL) return sig;
    /* A SEIZE'd tracee reports a stop signal as a group-stop (PTRACE_EVENT_STOP,
     * WSTOPSIG == the stop signal); a PTRACE_ATTACH'd tracee sees it as a plain
     * signal-delivery-stop (event 0), matching the kernel. */
    int event = (g_self_link->seize && pt_is_stopsig(sig)) ? G_PTRACE_EVENT_STOP : 0;
    return pt_stop(c, sig, event, 0, 0, 0);
}

/* Synchronous-fault stop (software breakpoint BRK, SIGSEGV/SIGBUS/SIGILL/...):
 * report the signal to the tracer with precise siginfo (si_code and, for the
 * fault families, si_addr) before the guest handler/fatal decision. Returns 0
 * if the tracer suppressed it (resume the guest), else the signal to deliver
 * (the original, or one the tracer substituted). SIGKILL is never intercepted. */
int ptrace_report_fault(CPU *c, int sig, int si_code, u64 addr) {
    if (!g_ptrace_active || !g_self_link || sig == SIGKILL) return sig;
    return pt_stop(c, sig, 0, 0, si_code, addr);
}

void ptrace_report_singlestep(CPU *c) {
    if (!g_ptrace_active || !g_self_link) return;
    pt_stop(c, SIGTRAP, 0, 0, 0, 0);
}

void ptrace_report_exit_stop(CPU *c, int wstatus) {
    if (!g_ptrace_active || !g_self_link) return;
    if (!(g_self_link->options & G_PTRACE_O_TRACEEXIT)) return;
    /* PTRACE_EVENT_EXIT: park before actually exiting, exposing the pending
     * wait-status word via PTRACE_GETEVENTMSG so the tracer can read final
     * registers/exit code. On resume the caller proceeds to the real exit. */
    g_self_link->eventmsg = (u64)(u32)wstatus;
    pt_stop(c, SIGTRAP, G_PTRACE_EVENT_EXIT, 0, 0, 0);
}

/* Run-loop boundary: a tracer PTRACE_ATTACH/SEIZE/INTERRUPT'd us via the kick
 * signal. Adopt the pending attach (become a tracee; ATTACH also stops with
 * SIGSTOP, SEIZE just attaches) or service a pending interrupt (EVENT_STOP). */
void ptrace_service_kick(CPU *c) {
    g_ptrace_kick = 0;
    if (!g_tab) return;
    if (!g_ptrace_active) {
        /* The kick was thread-targeted (rt_tgsigqueueinfo), so the pending
         * attach to adopt is the one keyed by this thread's own tid. */
        PtLink *e = pt_find((s32)g_tls.tid);
        if (!e || __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) <= 0 ||
            !__atomic_load_n(&e->attach_pending, __ATOMIC_ACQUIRE))
            return;
        __atomic_store_n(&e->attach_pending, 0, __ATOMIC_RELEASE);
        g_self_link = e;
        g_ptrace_active = 1;
        pt_traced_inc(c->m);   /* catch default-fatal signals to report them */
        if (!e->seize) { pt_stop(c, SIGSTOP, 0, 0, 0, 0); return; }  /* ATTACH */
        /* SEIZE: attached without a stop; fall through in case an INTERRUPT
         * kick coalesced with this attach kick into one g_ptrace_kick. */
    }
    if (g_self_link &&
        __atomic_load_n(&g_self_link->interrupt_pending, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&g_self_link->interrupt_pending, 0, __ATOMIC_RELEASE);
        pt_stop(c, SIGTRAP, G_PTRACE_EVENT_STOP, 0, 0, 0);
    }
    /* A stop signal (SIGSTOP/SIGTSTP/...) another process sent us as a tracee:
     * report it as a cooperative group-stop with that signal as WSTOPSIG. */
    if (g_self_link) {
        u32 ss = __atomic_load_n(&g_self_link->stopsig_pending, __ATOMIC_ACQUIRE);
        if (ss) {
            __atomic_store_n(&g_self_link->stopsig_pending, 0, __ATOMIC_RELEASE);
            /* SEIZE'd: a faithful group-stop (EVENT_STOP); ATTACH'd: a plain
             * signal-delivery-stop, as the kernel reports it. */
            int event = g_self_link->seize ? G_PTRACE_EVENT_STOP : 0;
            pt_stop(c, (int)ss, event, 0, 0, 0);
        }
    }
}

int ptrace_selfstop(int sig) {
    if (!g_ptrace_active) return 0;
    if (!pt_is_stopsig(sig)) return 0;
    /* Queue it for the cooperative signal-delivery stop instead of letting the
     * host job-control-stop this process (which would freeze our service loop
     * so the tracer's next request would deadlock). */
    sig_raise_local(sig);
    return 1;
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

/* Parent side: report the fork/clone event stop, carrying the new child's pid
 * for PTRACE_GETEVENTMSG. */
void ptrace_report_event(CPU *c, int event, u64 msg) {
    if (!g_ptrace_active || !g_self_link) return;
    g_self_link->eventmsg = msg;
    pt_stop(c, SIGTRAP, event, 0, 0, 0);
}

/* Child side of a clone/fork. `event` is nonzero when the parent's tracer is
 * following this creation (PTRACE_O_TRACE{FORK,VFORK,CLONE}); the child then
 * auto-attaches to the same tracer and reports an initial (SIGSTOP) stop.
 * Otherwise it runs untraced. Called in the freshly forked child, which has
 * inherited the parent's g_self_link pointer (valid: the registry is shared at
 * the same address). */
void ptrace_fork_child(CPU *c, int event) {
    PtLink *parent = g_self_link;          /* inherited: the parent's link */
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
    if (!event || !parent) {
        if (inherited) sig_trace_update_all(c->m);
        return;                            /* not followed: a fresh untraced pid */
    }

    s32 tracer = __atomic_load_n(&parent->tracer, __ATOMIC_ACQUIRE);
    u32 opts = __atomic_load_n(&parent->options, __ATOMIC_ACQUIRE);
    u32 seize = parent->seize;             /* the attach flavor is inherited */
    if (tracer <= 0) {
        if (inherited) sig_trace_update_all(c->m);
        return;
    }
    PtLink *e = pt_claim(getpid(), getpid());
    if (!e) {
        if (inherited) sig_trace_update_all(c->m);
        return;                            /* registry full: degrade to untraced */
    }
    __atomic_store_n(&e->options, opts, __ATOMIC_RELAXED);  /* options are inherited */
    e->seize = seize;
    __atomic_store_n(&e->tracer, tracer, __ATOMIC_RELEASE);
    __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);
    g_self_link = e;
    g_ptrace_active = 1;
    pt_traced_inc(c->m);   /* catch default-fatal signals to report them */
    /* Initial attach stop: an auto-attached child of a SEIZE'd tracee stops
     * with PTRACE_EVENT_STOP, of an ATTACH'd one with SIGSTOP (kernel
     * behavior). The tracer sees it, (re)sets options and resumes us. */
    if (seize) pt_stop(c, SIGTRAP, G_PTRACE_EVENT_STOP, 0, 0, 0);
    else       pt_stop(c, SIGSTOP, 0, 0, 0, 0);
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
    if (g_self_link->seize) pt_stop(c, SIGTRAP, G_PTRACE_EVENT_STOP, 0, 0, 0);
    else                    pt_stop(c, SIGSTOP, 0, 0, 0, 0);
}

/* ---- tracee: PTRACE_TRACEME ---- */
static long ptrace_traceme(CPU *c) {
    if (!g_tab) return -EPERM;
    if (g_self_link) return -EPERM;   /* already traced */
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
static void pt_cmd(PtLink *e, u32 cmd, u64 addr, u64 arg) {
    e->cmd = cmd;
    e->addr = addr;
    e->arg = arg;
    u32 d = __atomic_load_n(&e->done_seq, __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&e->cmd_seq, 1, __ATOMIC_RELEASE);
    fx_wake(&e->cmd_seq);
    while (__atomic_load_n(&e->done_seq, __ATOMIC_ACQUIRE) == d) {
        /* Tracee gone while we waited -- its slot freed (killed), or its exit
         * published (a sibling thread's exit_group fan-out flips a parked
         * thread's link to EXITED without it ever answering): bail so ptrace
         * doesn't hang. Checked while done_seq is still unbumped, so an answer
         * that did land is never discarded. */
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) <= 0 ||
            __atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED) {
            e->result = -ESRCH;
            return;
        }
        fx_wait(&e->done_seq, d, 500);
    }
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

/* Thread group of host task `tid` (/proc/<tid>/status Tgid -- guest tids are
 * host tids). -1 if the task does not exist. Used to attach by thread tid. */
static s32 pt_tgid_of(s32 tid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", (int)tid);
    FILE *f = fopen(path, "re");
    if (!f) return -1;
    char line[128];
    s32 tg = -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "Tgid:", 5)) { tg = (s32)strtol(line + 5, NULL, 10); break; }
    fclose(f);
    return tg;
}

/* A stop signal aimed at a task whose thread group has ptrace tracees: route it
 * into cooperative group-stops instead of a real host stop. An uncatchable
 * SIGSTOP delivered to the host would freeze the tracees inside their ptrace
 * service loops, so the follow-up tracer requests (e.g. the DETACH strace
 * issues on ^C after it stops the tracee with SIGSTOP) would deadlock -- and
 * the emulator would never see the signal to report it. The kernel group-stops
 * *all* threads and each traced one reports its own group-stop, so the signal
 * is recorded and kicked on every live link of the group (`id` may be a pid or
 * any thread's tid). In a mixed traced/untraced group only the traced threads
 * stop -- a documented simplification; a full strace -f/-p traces every thread.
 * Returns 1 if routed (the caller must not also host-signal), 0 otherwise. */
int ptrace_signal_stop(s32 id, int sig) {
    if (!g_tab || id <= 0) return 0;
    if (!pt_is_stopsig(sig)) return 0;
    /* Resolve to a thread group: an exact link match maps a tid to its group;
     * otherwise treat `id` as a tgid (its main thread may be untraced). */
    PtLink *hit = pt_find(id);
    s32 tgid = hit ? hit->tgid : id;
    int routed = 0;
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0 || e->tgid != tgid) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) <= 0) continue;
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED) continue;
        __atomic_store_n(&e->stopsig_pending, (u32)sig, __ATOMIC_RELEASE);
        pt_send_kick(e->tgid, t);
        routed = 1;
    }
    return routed;
}

/* SIGCONT aimed at a task whose thread group has tracees a tracer put into a
 * listening group-stop (PTRACE_LISTEN): end the group-stop and notify each
 * tracer with a fresh PTRACE_EVENT_STOP trap. The tracees stay parked in their
 * service loops (their CPUs are intact), so a follow-up GETREGSET/CONT
 * round-trips as usual; we only re-arm the stop fields on the shared links from
 * the sender side and wake the tracer(s). Returns 1 if consumed (the caller
 * must not also host-signal), else 0 -- an ordinary SIGCONT (no listening
 * tracee in the group) falls through to normal delivery. */
int ptrace_signal_cont(s32 id, int sig) {
    if (!g_tab || id <= 0 || sig != SIGCONT) return 0;
    PtLink *hit = pt_find(id);
    s32 tgid = hit ? hit->tgid : id;
    int consumed = 0;
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0 || e->tgid != tgid) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) <= 0) continue;
        if (!__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE)) continue;
        __atomic_store_n(&e->listening, 0, __ATOMIC_RELEASE);
        e->stop_sig = SIGTRAP;
        e->event = G_PTRACE_EVENT_STOP;
        e->syscall_stop = 0;
        e->si_signo = SIGTRAP;
        e->si_code = (G_PTRACE_EVENT_STOP << 8) | SIGTRAP;
        e->si_errno = 0;
        /* state is already PT_ST_STOPPED (the tracee never left its service loop). */
        __atomic_store_n(&e->reported, 0, __ATOMIC_RELEASE);
        __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
        fx_wake(&g_tab->global_gen);
        { s32 tr = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
          if (tr > 0) kill(tr, SIGCHLD); }   /* wake an async tracer's event loop */
        consumed = 1;
    }
    return consumed;
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
        if (write) {
            memcpy(e->data, buf + done, chunk);
            pt_cmd(e, PT_CMD_WRITE, rva + done, chunk);
        } else {
            pt_cmd(e, PT_CMD_READ, rva + done, chunk);
        }
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
            tgid = pt_tgid_of(pid);
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
        pt_send_kick(tgid, pid);
        return 0;
    }

    PtLink *e = pt_find(pid);
    if (!e || __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != (s32)getpid())
        return -ESRCH;

    /* Stop a SEIZE'd (or otherwise running) tracee on demand. */
    if (req == G_PTRACE_INTERRUPT) {
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_STOPPED)
            return 0;                            /* already stopped */
        __atomic_store_n(&e->interrupt_pending, 1, __ATOMIC_RELEASE);
        pt_send_kick(e->tgid, pid);
        return 0;
    }

    /* Requests serviceable without a mailbox round-trip. */
    switch (req) {
    case G_PTRACE_SETOPTIONS:
        __atomic_store_n(&e->options, (u32)data & G_PTRACE_O_MASK, __ATOMIC_RELEASE);
        return 0;
    case G_PTRACE_KILL:
        kill(e->tgid, SIGKILL);   /* pid may be a thread tid: kill its process */
        return 0;
    case G_PTRACE_GETEVENTMSG: {
        u64 msg = e->eventmsg;
        return copy_to_guest(c, data, &msg, 8) < 0 ? -EFAULT : 0;
    }
    case G_PTRACE_GETSIGINFO: {
        u8 si[128];
        memset(si, 0, sizeof si);
        s32 *w = (s32 *)si;
        w[0] = e->si_signo;
        w[1] = e->si_errno;
        w[2] = e->si_code;
        /* Fault signals carry si_addr in the _sigfault union, at byte offset 16
         * on arm64 (after si_signo/si_errno/si_code and pointer alignment pad).
         * gdb reads it for SIGSEGV/SIGBUS; TRAP_BRKPT carries the BRK PC. */
        switch (e->si_signo) {
        case SIGSEGV: case SIGBUS: case SIGILL: case SIGFPE: case SIGTRAP:
            memcpy(si + 16, &e->fault_addr, 8);
            break;
        }
        return copy_to_guest(c, data, si, sizeof si) < 0 ? -EFAULT : 0;
    }
    }

    /* Everything else requires the tracee to be stopped. */
    if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_STOPPED)
        return -ESRCH;

    /* A listening tracee (post-LISTEN, parked in a group-stop awaiting SIGCONT) is
     * stopped but counts as "running" to ptrace data ops: a resume op cancels the
     * listen and proceeds, LISTEN is idempotent, and everything else gets -ESRCH
     * (exactly as the kernel treats a listening tracee). */
    if (__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE)) {
        switch (req) {
        case G_PTRACE_CONT: case G_PTRACE_SYSCALL:
        case G_PTRACE_SINGLESTEP: case G_PTRACE_DETACH:
            __atomic_store_n(&e->listening, 0, __ATOMIC_RELEASE);
            break;                      /* fall through to the resume handling */
        case G_PTRACE_LISTEN:
            return 0;                   /* already listening */
        default:
            return -ESRCH;
        }
    }

    switch (req) {
    case G_PTRACE_PEEKTEXT:
    case G_PTRACE_PEEKDATA:
        pt_cmd(e, PT_CMD_PEEK, addr, 0);
        if (e->result < 0) return -EIO;
        return copy_to_guest(c, data, e->data, 8) < 0 ? -EFAULT : 0;
    case G_PTRACE_PEEKUSR:
        pt_cmd(e, PT_CMD_PEEKUSR, addr, 0);
        if (e->result < 0) return -EIO;
        return copy_to_guest(c, data, e->data, 8) < 0 ? -EFAULT : 0;
    case G_PTRACE_POKETEXT:
    case G_PTRACE_POKEDATA:
        pt_cmd(e, PT_CMD_POKE, addr, data);
        return e->result < 0 ? -EIO : 0;
    case G_PTRACE_POKEUSR:
        return -EIO;   /* user-area writes not modelled (gdb uses SETREGSET) */
    case G_PTRACE_GETREGSET: {
        GIovec iov;
        if (copy_from_guest(c, &iov, data, sizeof iov) < 0) return -EFAULT;
        pt_cmd(e, PT_CMD_GETREGS, addr, 0);
        if (e->result < 0) return -EINVAL;
        u32 n = e->rlen;
        if (iov.iov_len < n) n = (u32)iov.iov_len;
        if (n && copy_to_guest(c, iov.iov_base, e->data, n) < 0) return -EFAULT;
        iov.iov_len = e->rlen;
        return copy_to_guest(c, data, &iov, sizeof iov) < 0 ? -EFAULT : 0;
    }
    case G_PTRACE_SETREGSET: {
        GIovec iov;
        if (copy_from_guest(c, &iov, data, sizeof iov) < 0) return -EFAULT;
        u32 n = (u32)iov.iov_len;
        if (n > PT_MBOX) n = PT_MBOX;
        if (n && copy_from_guest(c, e->data, iov.iov_base, n) < 0) return -EFAULT;
        e->rlen = n;
        pt_cmd(e, PT_CMD_SETREGS, addr, 0);
        return e->result < 0 ? (long)e->result : 0;
    }
    case G_PTRACE_CONT:
        pt_cmd(e, PT_CMD_RESUME, data, PT_RES_CONT);
        return 0;
    case G_PTRACE_SYSCALL:
        pt_cmd(e, PT_CMD_RESUME, data, PT_RES_SYSCALL);
        return 0;
    case G_PTRACE_SINGLESTEP:
        pt_cmd(e, PT_CMD_RESUME, data, PT_RES_SINGLESTEP);
        return 0;
    case G_PTRACE_DETACH:
        pt_cmd(e, PT_CMD_DETACH, data, 0);
        return 0;
    case G_PTRACE_LISTEN:
        /* Only on a SEIZE'd tracee currently in an EVENT_STOP (a group-stop or a
         * PTRACE_INTERRUPT stop). Keep it parked-but-listening: it does not resume;
         * a later SIGCONT (ptrace_signal_cont) ends the group-stop with a fresh
         * EVENT_STOP. No mailbox round-trip -- the tracee stays parked. */
        if (!e->seize) return -EIO;
        if (e->event != G_PTRACE_EVENT_STOP) return -EIO;
        __atomic_store_n(&e->listening, 1, __ATOMIC_RELEASE);
        return 0;
    default:
        return -EIO;
    }
}

/* ---- tracer: wait4/waitid integration ---- */
int ptrace_collect(s32 wpid, int *status, s32 *outpid) {
    if (!g_tab) return 0;
    s32 me = (s32)getpid();
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) <= 0) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me) continue;
        s32 t = e->tracee;
        if (wpid > 0 && wpid != t) continue;   /* -1/0 => any child of ours */
        u32 st_state = __atomic_load_n(&e->state, __ATOMIC_ACQUIRE);
        /* Synthetic exit of an auto-attached tracee we cannot host-reap. */
        if (st_state == PT_ST_EXITED) {
            *status = e->exit_status;
            *outpid = t;
            pt_free(e);
            return 1;
        }
        if (st_state != PT_ST_STOPPED) continue;
        if (__atomic_load_n(&e->reported, __ATOMIC_ACQUIRE)) continue;
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

int ptrace_have_tracee(s32 wpid) {
    if (!g_tab) return 0;
    s32 me = (s32)getpid();
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) <= 0) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me) continue;
        if (wpid > 0 && wpid != e->tracee) continue;
        return 1;
    }
    return 0;
}

/* Is host task `t` dead to a tracer -- its host process gone or a zombie? A tracee
 * killed by an uncatchable SIGKILL runs no guest code, so it publishes no exit and
 * leaves a zombie its real parent has not reaped (kill(t,0) still succeeds); the
 * /proc state distinguishes a zombie from a live one. */
static int pt_task_dead(s32 t) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)t);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;                       /* gone (already reaped) */
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    char *rp = strrchr(buf, ')');               /* comm may hold spaces/parens */
    if (!rp || !rp[1]) return 0;
    char st = (rp[1] == ' ') ? rp[2] : rp[1];   /* "...) S ..." */
    return st == 'Z' || st == 'X' || st == 'x';
}

/* Backstop for a tracee that vanished at the host level without publishing an exit
 * -- an uncatchable SIGKILL (every catchable fatal signal is mediated and reports
 * its real status, so a silent death is a SIGKILL). Report a synthetic
 * WIFSIGNALED(SIGKILL) so a sibling tracer polling in wait4 does not hang. Only
 * fires for a non-child tracee; a host-child's death is reaped via the host wait.
 * Returns 1 and fills status/outpid if such a tracee is found, else 0. */
int ptrace_reap_dead(s32 wpid, int *status, s32 *outpid) {
    if (!g_tab) return 0;
    s32 me = (s32)getpid();
    for (int i = 0; i < PTRACE_MAX; i++) {
        PtLink *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0) continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me) continue;
        if (wpid > 0 && wpid != t) continue;
        /* A stopped/exited tracee is alive-and-parked / handled by ptrace_collect. */
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED) continue;
        if (!pt_task_dead(t)) continue;
        *status = SIGKILL;            /* WIFSIGNALED(SIGKILL) */
        *outpid = t;
        pt_free(e);
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
