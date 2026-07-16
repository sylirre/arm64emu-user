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
 *     holds one PtLink per tracee, keyed by tracee pid (== host pid).
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
#include <limits.h>
#include <linux/futex.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "machine.h"
#include "guest_abi.h"
#include "ptrace.h"

/* ---- process-local tracee-self state (fast gates read by the hot paths) ---- */
int g_ptrace_active;
int g_ptrace_syscall_armed;
int g_ptrace_singlestep;

/* ---- shared registry ---- */
#define PTRACE_MAX  256      /* max concurrent tracees in the session */
#define PT_MBOX     1024     /* mailbox payload cap (>= largest regset, 528) */

/* Link state. */
enum { PT_ST_RUNNING = 0, PT_ST_STOPPED = 1 };

/* Mailbox commands (tracer -> stopped tracee). */
enum {
    PT_CMD_NONE = 0,
    PT_CMD_PEEK,        /* addr -> 8-byte word in data[] */
    PT_CMD_PEEKUSR,     /* addr = user-area offset -> word */
    PT_CMD_POKE,        /* addr, arg = value */
    PT_CMD_GETREGS,     /* addr = NT_* which -> regset in data[] */
    PT_CMD_SETREGS,     /* addr = NT_* which, rlen bytes in data[] */
    PT_CMD_RESUME,      /* addr = inject sig, arg = PT_RES_* submode */
    PT_CMD_DETACH,      /* addr = inject sig */
};

/* Resume submodes. */
enum { PT_RES_CONT = 0, PT_RES_SYSCALL = 1, PT_RES_SINGLESTEP = 2 };

typedef struct {
    s32 tracee;          /* 0 = free (CAS-claimed); guest pid == host pid */
    s32 tracer;          /* tracer pid, 0 once detached */
    u32 options;         /* PTRACE_O_* */
    u32 state;           /* PT_ST_* (release/acquire flag for the stop fields) */
    u32 reported;        /* wait4 has already consumed the current stop */
    u32 stop_sig;        /* WSTOPSIG of the current stop */
    u32 event;           /* PTRACE_EVENT_* of the current stop (0 = none) */
    u32 syscall_stop;    /* current stop is a syscall-entry/exit stop */
    u64 eventmsg;        /* PTRACE_GETEVENTMSG payload */
    s32 si_signo, si_code, si_errno;   /* stored siginfo for GETSIGINFO */
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
static PtLink  *g_self_link;      /* this process's own tracee entry, or NULL */

/* ---- futex helpers (cross-process: no FUTEX_PRIVATE_FLAG) ---- */
static void fx_wake(volatile u32 *a) {
    syscall(SYS_futex, (u32 *)a, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}
static void fx_wait(volatile u32 *a, u32 val, int ms) {
    struct timespec ts;
    if (ms >= 0) { ts.tv_sec = ms / 1000; ts.tv_nsec = (long)(ms % 1000) * 1000000L; }
    syscall(SYS_futex, (u32 *)a, FUTEX_WAIT, val, ms >= 0 ? &ts : NULL, NULL, 0);
}

void ptrace_init(void) {
    void *p = mmap(NULL, sizeof(PtTable), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_tab = (p == MAP_FAILED) ? NULL : p;   /* degrade to "no ptrace" on failure */
}

void ptrace_fork_child(void) {
    /* A plain fork is not a tracee of the parent's tracer (that needs
     * PTRACE_O_TRACEFORK, handled later). Drop inherited self state; the child
     * has a fresh pid and therefore no link of its own. */
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
}

/* ---- registry helpers ---- */
static PtLink *pt_find(s32 tracee) {
    if (!g_tab || tracee <= 0) return NULL;
    for (int i = 0; i < PTRACE_MAX; i++)
        if (__atomic_load_n(&g_tab->links[i].tracee, __ATOMIC_ACQUIRE) == tracee)
            return &g_tab->links[i];
    return NULL;
}

static PtLink *pt_claim(s32 tracee) {
    if (!g_tab) return NULL;
    PtLink *e = pt_find(tracee);
    if (e) return e;
    for (int i = 0; i < PTRACE_MAX; i++) {
        s32 expect = 0;
        if (__atomic_compare_exchange_n(&g_tab->links[i].tracee, &expect, tracee,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            e = &g_tab->links[i];
            e->tracer = 0; e->options = 0; e->state = PT_ST_RUNNING;
            e->reported = 0; e->stop_sig = 0; e->event = 0; e->syscall_stop = 0;
            e->eventmsg = 0; e->si_signo = e->si_code = e->si_errno = 0;
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
    g_self_link = NULL;
    g_ptrace_active = 0;
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    if (e) { __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE); pt_free(e); }
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
            e->result = copy_to_guest(c, e->addr, &e->arg, 8) < 0 ? -EIO : 0;
            break;
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

/* Publish a stop and park until the tracer resumes us. Returns the inject sig. */
static int pt_stop(CPU *c, int stop_sig, int event, int syscall_stop) {
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
    e->si_code = event ? ((event << 8) | 5 /*SIGTRAP*/) : 0;
    e->si_errno = 0;
    __atomic_store_n(&e->reported, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&e->state, PT_ST_STOPPED, __ATOMIC_RELEASE);
    /* Wake the tracer's wait4. */
    __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
    fx_wake(&g_tab->global_gen);
    return pt_service_loop(c, e, seen);
}

void ptrace_report_syscall(CPU *c, int is_exit) {
    if (!g_ptrace_active || !g_self_link) return;
    (void)is_exit;
    pt_stop(c, SIGTRAP, 0, 1 /* syscall stop */);
}

void ptrace_report_exec(CPU *c) {
    if (!g_ptrace_active || !g_self_link) return;
    int event = (g_self_link->options & G_PTRACE_O_TRACEEXEC) ? G_PTRACE_EVENT_EXEC : 0;
    /* After execve a fresh tracee is stopped again and must be re-armed by the
     * tracer, so drop any prior syscall/step arming. */
    g_ptrace_syscall_armed = 0;
    g_ptrace_singlestep = 0;
    pt_stop(c, SIGTRAP, event, 0);
}

int ptrace_report_signal(CPU *c, int sig) {
    if (!g_ptrace_active || !g_self_link || sig == SIGKILL) return sig;
    return pt_stop(c, sig, 0, 0);
}

void ptrace_report_singlestep(CPU *c) {
    if (!g_ptrace_active || !g_self_link) return;
    pt_stop(c, SIGTRAP, 0, 0);
}

void ptrace_report_exit(CPU *c) {
    (void)c;
    if (g_self_link) pt_free(g_self_link);
    g_self_link = NULL;
    g_ptrace_active = 0;
}

/* ---- tracee: PTRACE_TRACEME ---- */
static long ptrace_traceme(void) {
    if (!g_tab) return -EPERM;
    if (g_self_link) return -EPERM;   /* already traced */
    PtLink *e = pt_claim(getpid());
    if (!e) return -ENOMEM;
    __atomic_store_n(&e->tracer, (s32)getppid(), __ATOMIC_RELEASE);
    /* Flip the session-wide "someone is tracing" flag so every wait4 switches to
     * the polling path (a blocked host wait4 can't see a cooperative stop). */
    __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);
    g_self_link = e;
    g_ptrace_active = 1;
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
        fx_wait(&e->done_seq, d, 500);
        /* Tracee gone (killed) while we waited: bail so ptrace doesn't hang. */
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) <= 0) { e->result = -ESRCH; return; }
    }
}

/* ---- tracer: guest ptrace(2) dispatch ---- */
long ptrace_syscall(CPU *c, long req, s32 pid, u64 addr, u64 data) {
    if (req == G_PTRACE_TRACEME)
        return ptrace_traceme();
    if (!g_tab) return -EPERM;

    PtLink *e = pt_find(pid);
    if (!e || __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != (s32)getpid())
        return -ESRCH;

    /* Requests serviceable without a mailbox round-trip. */
    switch (req) {
    case G_PTRACE_SETOPTIONS:
        __atomic_store_n(&e->options, (u32)data & G_PTRACE_O_MASK, __ATOMIC_RELEASE);
        return 0;
    case G_PTRACE_KILL:
        kill(pid, SIGKILL);
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
        return copy_to_guest(c, data, si, sizeof si) < 0 ? -EFAULT : 0;
    }
    }

    /* Everything else requires the tracee to be stopped. */
    if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_STOPPED)
        return -ESRCH;

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
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_STOPPED) continue;
        if (__atomic_load_n(&e->reported, __ATOMIC_ACQUIRE)) continue;
        s32 t = e->tracee;
        if (wpid > 0 && wpid != t) continue;   /* -1/0 => any child of ours */
        int sig = (int)e->stop_sig;
        int st;
        if (e->event) {
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

void ptrace_tracer_wait(int ms) {
    if (!g_tab) return;
    u32 g = __atomic_load_n(&g_tab->global_gen, __ATOMIC_ACQUIRE);
    fx_wait(&g_tab->global_gen, g, ms);
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

void ptrace_wake_waiters(void) {
    if (!g_tab) return;
    __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
    fx_wake(&g_tab->global_gen);
}
