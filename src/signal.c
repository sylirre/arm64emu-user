/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest signal delivery.
 *
 * Host side: one SA_SIGINFO catcher (no SA_RESTART, everything masked while it
 * runs) is installed for each signal whose guest disposition is a handler; it
 * only queues {signo, translated siginfo} and sets a flag. Synchronous guest
 * faults (SIGSEGV/SIGILL/...) never come through the host — they arrive from
 * the interpreter as pending exceptions and are delivered directly.
 *
 * Guest side: an arm64 kernel rt_sigframe is built on the guest stack (or the
 * guest sigaltstack): 128-byte siginfo + ucontext with sigcontext (x0-x30, sp,
 * pc, pstate, fault_address) + fpsimd_context (magic 0x46508001) in
 * __reserved, terminator record, x30 pointed at a trampoline page containing
 * `mov x8, #139; svc #0` (arm64 has no sa_restorer; the kernel uses the vDSO
 * for this). rt_sigreturn restores everything from the frame at SP. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#include "machine.h"
#include "ptrace.h"
#include "guest_abi.h"
#include "jit.h"

#define GSIG_DFL 0
#define GSIG_IGN 1

/* si_code of a SIGSYS raised by a seccomp filter (SYS_SECCOMP). */
#define SIG_SECCOMP_CODE 1

/* guest SA_* flag values (arm64 == asm-generic) */
#define G_SA_NOCLDSTOP 0x00000001
#define G_SA_NOCLDWAIT 0x00000002
#define G_SA_SIGINFO   0x00000004
#define G_SA_ONSTACK   0x08000000
#define G_SA_RESTART   0x10000000
#define G_SA_NODEFER   0x40000000
#define G_SA_RESETHAND 0x80000000

/* ---- host-side capture queue (async-signal-safe: handlers are installed
 * with everything masked, so they never nest) ----
 *
 * Per-thread: the kernel delivers a host signal on one specific thread
 * (tgkill picks it explicitly; process-directed signals go to one thread with
 * it unblocked), host_catcher queues it there, and the same thread consumes
 * it from its run loop — single producer, single consumer, program-ordered.
 * A shared ring would be multi-producer under Go's SIGURG async preemption
 * and tears on weakly-ordered hosts (garbage signo -> bogus handler PC). */
typedef struct {
    int signo;
    int code;
    int err;     /* si_errno; only a seccomp trap's RET_DATA uses it */
    int pid, uid, status;
    u64 addr;
    s64 value;   /* full guest sigval width, even on a 32-bit host */
} PendSig;

#define SIGQ_LEN 32
static __thread PendSig sigq[SIGQ_LEN];
static __thread volatile sig_atomic_t sigq_head, sigq_tail;
__thread volatile sig_atomic_t g_sig_npend;

/* Guest rt-signal remap: guest signals 32/33 are the *guest* libc's internal
 * numbers (its SIGTIMER/SIGCANCEL) but collide with the *host* libc's own
 * internal handlers, so they can never be raised as host signals. A POSIX
 * timer the guest arms with signo 32/33 (glibc/musl SIGEV_THREAD helpers do
 * exactly this) is instead created with a reserved high host RT signal and
 * translated back to the guest number at capture time. Armed on first use so
 * a guest that never touches 32/33 keeps the host numbers for itself. */
#define SIG_REMAP32_HOST (SIGRTMAX - 1)   /* host carrier for guest signal 32 */
#define SIG_REMAP33_HOST (SIGRTMAX - 2)   /* host carrier for guest signal 33 */
static int g_sig_remap_armed[2];          /* [0]: 32, [1]: 33 (atomic flags) */

static int sig_remap_to_guest(int sig) {
    if (sig == SIG_REMAP32_HOST &&
        __atomic_load_n(&g_sig_remap_armed[0], __ATOMIC_ACQUIRE)) return 32;
    if (sig == SIG_REMAP33_HOST &&
        __atomic_load_n(&g_sig_remap_armed[1], __ATOMIC_ACQUIRE)) return 33;
    return sig;
}

static void host_catcher(int sig, siginfo_t *si, void *uctx) {
    (void)uctx;
    int next = (sigq_head + 1) % SIGQ_LEN;
    if (next == sigq_tail) return;   /* queue full: drop (kernel coalesces too) */
    PendSig *p = &sigq[sigq_head];
    p->signo = sig_remap_to_guest(sig);
    p->code = si->si_code;
    p->err = si->si_errno;   /* the ring is reused: never leave this stale */
    p->pid = (int)si->si_pid;
    p->uid = (int)si->si_uid;
    p->status = si->si_status;
    p->addr = (u64)(uintptr_t)si->si_addr;
    p->value = (s64)(uintptr_t)si->si_value.sival_ptr;   /* full width on LP64 */
    if (si->si_code == SI_TIMER) {
        /* A POSIX-timer signal: the host sigval carries only the emulator's
         * timer-slot index (the guest's 8-byte sigval cannot ride a 32-bit
         * host kernel's 4-byte sigval); swap in the slot's stored guest value
         * and make si_timerid the guest timer id (async-signal-safe: plain
         * loads). Every SI_TIMER in this process is one of ours. */
        u64 gv;
        if (ptimer_siginfo(si->si_value.sival_int, &gv)) {
            p->value = (s64)gv;
            p->pid = si->si_value.sival_int;   /* si_timerid slot */
        }
    }
    sigq_head = next;
    g_sig_npend = 1;
    jit_signal_interrupt();   /* make generated code exit at its next entry */
}

/* Arm the carrier for guest signal 32 or 33 and return the host signal number
 * to raise in its place (sys_time.c timer_create). Installs the capture
 * handler on the carrier; sig_host_update leaves an armed carrier alone. */
int sig_arm_rt_remap(int guest_sig) {
    int idx = (guest_sig == 33);
    int host = idx ? SIG_REMAP33_HOST : SIG_REMAP32_HOST;
    if (!__atomic_exchange_n(&g_sig_remap_armed[idx], 1, __ATOMIC_ACQ_REL)) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = host_catcher;
        sa.sa_flags = SA_SIGINFO;             /* deliberately no SA_RESTART */
        sigfillset(&sa.sa_mask);
        sigaction(host, &sa, NULL);
    }
    return host;
}

/* The signals sitting in this thread's capture ring. That ring *is* the guest's
 * pending set: everything the host catches is queued here, and one the guest has
 * blocked stays queued instead of being delivered (sig_deliver_pending). */
u64 sig_pending_set(void) {
    u64 m = 0;
    for (int t = sigq_tail; t != sigq_head; t = (t + 1) % SIGQ_LEN) {
        int sig = sigq[t].signo;
        if (sig >= 1 && sig <= 64) m |= 1ULL << (sig - 1);
    }
    return m;
}

/* The host signal number to raise on the guest's behalf. Guest 32/33 are its
 * libc's own SIGCANCEL/SIGSETXID -- pthread_cancel sends one, and glibc's
 * setuid() broadcasts the other to every thread -- but those numbers are the
 * *host* libc's internals and cannot be raised as themselves: a glibc host
 * takes the stray signal in its own setxid handler and dereferences a NULL
 * command block, and a musl host has no handler at all and dies of the default
 * action. Either way the emulator is killed instead of the guest receiving its
 * signal. Route them onto the reserved carrier, which the capture handler maps
 * back to 32/33 (sig_remap_to_guest) before the guest ever sees it. */
int sig_send_host_nr(int guest_sig) {
    return (guest_sig == 32 || guest_sig == 33) ? sig_arm_rt_remap(guest_sig)
                                                : guest_sig;
}

/* Queue a signal into this thread's own capture ring as if the host had caught
 * it, for cooperative delivery at the next run-loop boundary. Routes a traced
 * process's self-directed stop signal (SIGSTOP/SIGTSTP/...) through ptrace's
 * signal-delivery stop instead of a real host job-control stop, which would
 * freeze the tracee so it could no longer serve its ptrace mailbox. */
void sig_raise_local(int sig) {
    int next = (sigq_head + 1) % SIGQ_LEN;
    if (next == sigq_tail) return;   /* queue full: drop */
    PendSig *p = &sigq[sigq_head];
    memset(p, 0, sizeof *p);
    p->signo = sig;
    p->pid = (int)getpid();
    sigq_head = next;
    g_sig_npend = 1;
    jit_signal_interrupt();
}

/* Is `sp` inside the guest's alternate signal stack? The kernel keeps no "am I
 * on the altstack" flag -- it asks this of the current stack pointer every time
 * (on_sig_stack), and the bounds are exactly its own: open at the low end,
 * closed at the high end.
 *
 * A flag set at delivery and cleared at sigreturn gets stuck set whenever a
 * handler leaves without returning. siglongjmp out of a handler is the normal
 * way to recover from a stack-overflow SIGSEGV, and it was enough to disable
 * the alternate stack for the rest of the thread's life -- every later
 * SA_ONSTACK signal was then delivered onto the stack that had just
 * overflowed, where the frame write faults again. */
int sig_on_altstack(u64 sp) {
    return g_tls.sig_altstack_size && sp > g_tls.sig_altstack_sp &&
           sp - g_tls.sig_altstack_sp <= g_tls.sig_altstack_size;
}

/* Signals delivered synchronously from the interpreter (never host-caught). */
static int is_sync_sig(int sig) {
    return sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE ||
           sig == SIGTRAP;
}

/* Does `sig`'s default action terminate the process? Excludes the default-ignore
 * (SIGCHLD/SIGURG/SIGWINCH), default-continue (SIGCONT) and default-stop signals,
 * plus the uncatchable SIGKILL. Everything else defaults to terminate (with or
 * without a core dump). Used to decide which SIG_DFL signals a tracee must catch
 * (to report the death) and which reaching the delivery path must kill+report. */
static int sig_default_terminates(int sig) {
    switch (sig) {
    case SIGCHLD: case SIGURG: case SIGWINCH:                /* ignore */
    case SIGCONT:                                            /* continue */
    case SIGSTOP: case SIGTSTP: case SIGTTIN: case SIGTTOU:  /* stop */
    case SIGKILL:                                            /* uncatchable */
        return 0;
    default:
        return 1;
    }
}

/* ---- SIGSYS safety net ----
 *
 * Android 8+ filters every app process with a seccomp whitelist whose action
 * is SECCOMP_RET_TRAP: a non-whitelisted host syscall is *not executed* and
 * SIGSYS is raised instead of returning ENOSYS. Convert that back into a
 * plain -ENOSYS: patch the mcontext return register and return, which
 * resumes right after the trapped svc/syscall instruction inside the host
 * libc wrapper — it then sets errno normally and the emulator handler above
 * it takes its ordinary ENOSYS fallback path. Any other SIGSYS (a guest
 * kill()) goes through the normal capture queue.
 *
 * The net owns the host SIGSYS disposition for the process lifetime:
 * sig_host_update skips SIGSYS so a guest sigaction can never replace it,
 * and it is never blocked host-side (sig_sync_host_mask touches only the
 * job-control trio) — a seccomp SIGSYS delivered while blocked force-kills
 * regardless, so the net must stay armed. */
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

static void sigsys_net(int sig, siginfo_t *si, void *uctx) {
    if (si->si_code != SYS_SECCOMP) {   /* guest-directed kill(SIGSYS) etc. */
        host_catcher(sig, si, uctx);
        return;
    }
    /* One-shot notice per host syscall number so gaps surface instead of
     * hiding. Async-signal-safe: composed by hand, write(2) only. */
    int nr = si->si_syscall;
    static char warned[1024];
    if (nr >= 0 && nr < (int)sizeof warned && !warned[nr]) {
        warned[nr] = 1;
        static const char pre[] = "arm64chroot: host syscall ";
        static const char post[] = " blocked by seccomp filter, returning ENOSYS\n";
        char msg[sizeof pre + sizeof post + 12];
        size_t p = sizeof pre - 1;
        memcpy(msg, pre, p);
        char dig[12];
        int nd = 0, v = nr;
        do { dig[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
        while (nd) msg[p++] = dig[--nd];
        memcpy(msg + p, post, sizeof post - 1);
        p += sizeof post - 1;
        ssize_t ignored = write(2, msg, p); (void)ignored;
    }
    ucontext_t *uc = uctx;
#if defined(__aarch64__)
    uc->uc_mcontext.regs[0] = (u64)(s64)-ENOSYS;   /* glibc and Bionic */
#elif defined(__arm__)
    uc->uc_mcontext.arm_r0 = -ENOSYS;
#elif defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RAX] = -ENOSYS;
#elif defined(__i386__)
    uc->uc_mcontext.gregs[REG_EAX] = -ENOSYS;
#else
#error "no SIGSYS return-register accessor for this host arch"
#endif
}

void sig_install_sigsys_net(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigsys_net;
    sa.sa_flags = SA_SIGINFO;
    sigfillset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);
}

/* ---- ptrace attach stop-kick net ----
 * A tracer that PTRACE_ATTACH/SEIZE/INTERRUPTs a running, untraced tracee has no
 * host ptrace to stop it with. It instead sigqueue()s PTRACE_KICKSIG carrying
 * PT_KICK_MAGIC; this handler (no SA_RESTART) interrupts any blocked host syscall
 * and flags g_ptrace_kick, which ptrace_service_kick drains at the run-loop
 * boundary to adopt the attach / enter the stop. g_sig_npend is reused as the
 * fast-path exit lever so no per-instruction check is added. A guest-directed
 * signal of the same number (any other si_code/value) is forwarded to the normal
 * capture queue, so the guest keeps full use of the signal. The net owns
 * PTRACE_KICKSIG for the process lifetime (sig_host_update skips it). */
static void sig_kick_net(int sig, siginfo_t *si, void *uctx) {
    if (si->si_code == SI_QUEUE && si->si_value.sival_int == PT_KICK_MAGIC) {
        g_ptrace_kick = 1;
        g_sig_npend = 1;            /* make the run loop exit its fast path */
        jit_signal_interrupt();
        return;
    }
    if (si->si_code == SI_QUEUE && si->si_value.sival_int == PT_WAKE_MAGIC)
        return;   /* tracee->tracer wake: the EINTR on a blocked host
                     wait4/waitid is the whole effect; no flags, invisible
                     to the guest */
    host_catcher(sig, si, uctx);    /* a guest-directed signal of this number */
}

void sig_install_kick_net(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sig_kick_net;
    sa.sa_flags = SA_SIGINFO;                     /* deliberately no SA_RESTART */
    sigfillset(&sa.sa_mask);
    sigaction(PTRACE_KICKSIG, &sa, NULL);
}

/* Mirror the guest block-state to the host where it has to be observed.
 *
 * Two separate things happen here. First the terminal job-control signals are
 * mirrored onto the host process mask. SIGTTOU/SIGTTIN are generated *synchronously by the host
 * kernel* (tcsetpgrp, background terminal I/O) and would stop our process
 * before the run loop can mediate; SIGTSTP travels with them in bash's
 * give_terminal_to() critical section. When the guest blocks one of these
 * (as bash does around tcsetpgrp), we must block it on the host too — POSIX
 * then suppresses the signal entirely instead of stopping us. The guest
 * blocked set is per-thread (g_tls); the shells that need this mirroring are
 * single-threaded, so mirroring the calling thread's view suffices. */
void sig_sync_host_mask(struct Machine *m) {
    static const int sigs[] = { SIGTTOU, SIGTTIN, SIGTSTP };
    sigset_t block, unblock;
    sigemptyset(&block);
    sigemptyset(&unblock);
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        if (g_tls.sigmask & (1ULL << (sigs[i] - 1))) sigaddset(&block, sigs[i]);
        else sigaddset(&unblock, sigs[i]);
    }
    sigprocmask(SIG_BLOCK, &block, NULL);
    sigprocmask(SIG_UNBLOCK, &unblock, NULL);

    /* Then the dispositions of whatever the guest just blocked or unblocked:
     * at SIG_DFL a *blocked* signal has to be caught rather than left to the
     * host default, which would act on it right now. Only the bits that
     * changed are re-mirrored -- shells call sigprocmask constantly. */
    static __thread u64 mirrored;
    u64 changed = mirrored ^ g_tls.sigmask;
    mirrored = g_tls.sigmask;
    for (int s = 1; changed && s <= 64; s++)
        if (changed & (1ULL << (s - 1))) {
            changed &= ~(1ULL << (s - 1));
            sig_host_update(m, s);
        }
}

void sig_host_update(struct Machine *m, int sig) {
    if (sig < 1 || sig > 64 || sig == SIGKILL || sig == SIGSTOP) return;
    if (sig == 32 || sig == 33) return;          /* host-libc internal rt sigs */
    if (sig == SIGSYS) return;                   /* owned by the SIGSYS net; guest
                                                    dispositions are honored via
                                                    the capture queue */
    if (sig == PTRACE_KICKSIG) return;           /* owned by the ptrace kick net;
                                                    guest dispositions honored via
                                                    the capture queue (sig_kick_net) */
    if ((sig == SIG_REMAP32_HOST &&
         __atomic_load_n(&g_sig_remap_armed[0], __ATOMIC_ACQUIRE)) ||
        (sig == SIG_REMAP33_HOST &&
         __atomic_load_n(&g_sig_remap_armed[1], __ATOMIC_ACQUIRE)))
        return;                                  /* armed 32/33 carrier: keep the
                                                    capture handler installed */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    u64 h = m->sigact[sig].handler;
    if (h == GSIG_DFL) {
        /* A ptrace tracee must *catch* its default-terminate signals rather than
         * let the host default (kill) apply: a bare host SIG_DFL kill runs no
         * guest code, so the tracee never reports the signal-delivery-stop nor the
         * WIFSIGNALED death, and a sibling tracer's wait4 poll would hang forever.
         * Caught, the signal is queued and mediated at the run-loop boundary (the
         * sync fault signals still arrive from the interpreter, so skip those).
         * Dispositions are process-wide, so the catcher stays while *any* thread
         * of this process is traced (ptrace_traced), not just the calling one. */
        /* Likewise when the guest has this signal BLOCKED, or a signalfd
         * covers it. A blocked signal is pending, not delivered: the kernel
         * holds it until the guest unblocks it, and the run loop applies the
         * disposition then (terminating on a default-terminate signal, exactly
         * as the kernel would). Left at the host default it would instead act
         * immediately -- killing us for most signals, and silently discarding
         * the SIGCHLD a signalfd was waiting for, so the fd never became
         * readable. */
        if (((g_tls.sigmask | m->sfd_mask) & (1ULL << (sig - 1))) &&
            !is_sync_sig(sig)) {
            sa.sa_sigaction = host_catcher;
            sa.sa_flags = SA_SIGINFO;
            sigfillset(&sa.sa_mask);
        } else if (ptrace_traced() && !is_sync_sig(sig) && sig_default_terminates(sig)) {
            sa.sa_sigaction = host_catcher;
            sa.sa_flags = SA_SIGINFO;
            sigfillset(&sa.sa_mask);
        } else {
            sa.sa_handler = SIG_DFL;
        }
    } else if (h == GSIG_IGN) {
        sa.sa_handler = SIG_IGN;
    } else if (is_sync_sig(sig)) {
        return;                                   /* delivered from pend_exc */
    } else {
        sa.sa_sigaction = host_catcher;
        sa.sa_flags = SA_SIGINFO;                 /* deliberately no SA_RESTART */
        sigfillset(&sa.sa_mask);
    }
    sigaction(sig, &sa, NULL);
}

/* Re-mirror every disposition. Called when a thread of this process becomes a
 * ptrace tracee (so default-terminate signals gain a host catcher) or the last
 * traced one is detached (so they revert to SIG_DFL); sig_host_update reads
 * ptrace_traced() to pick the right disposition. */
void sig_trace_update_all(struct Machine *m) {
    for (int s = 1; s <= 64; s++)
        sig_host_update(m, s);
}

void sig_reset_for_exec(struct Machine *m) {
    for (int s = 1; s <= 64; s++) {
        if (m->sigact[s].handler > GSIG_IGN) {   /* handlers do not survive exec */
            m->sigact[s].handler = GSIG_DFL;
            m->sigact[s].flags = 0;
            sig_host_update(m, s);
        }
    }
    sigq_head = sigq_tail = 0;   /* this thread's queue; post-exec is single-threaded */
    g_sig_npend = 0;
    g_tls.sig_altstack_sp = g_tls.sig_altstack_size = 0;
}

/* ---- guest frame layout (arm64 kernel ABI) ---- */
#define SI_OFF        0          /* siginfo, 128 bytes */
#define UC_OFF        128
#define UC_FLAGS      (UC_OFF + 0)
#define UC_LINK       (UC_OFF + 8)
#define UC_STACK      (UC_OFF + 16)      /* {sp u64, flags s32, pad, size u64} */
#define UC_SIGMASK    (UC_OFF + 40)
#define MCTX_OFF      (UC_OFF + 176)     /* sigcontext, 16-aligned */
#define MC_FAULTADDR  (MCTX_OFF + 0)
#define MC_REGS       (MCTX_OFF + 8)     /* x0..x30 */
#define MC_SP         (MCTX_OFF + 256)
#define MC_PC         (MCTX_OFF + 264)
#define MC_PSTATE     (MCTX_OFF + 272)
#define MC_RESERVED   (MCTX_OFF + 288)   /* fpsimd_context + terminator */
#ifndef FPSIMD_MAGIC  /* Bionic <asm/sigcontext.h> already defines it (same value) */
#define FPSIMD_MAGIC  0x46508001u
#endif
#define FRAME_SIZE    ((MC_RESERVED + 544 + 15) & ~15)

static void wr64(CPU *c, u64 base, u64 off, u64 v) { copy_to_guest(c, base + off, &v, 8); }
static void wr32(CPU *c, u64 base, u64 off, u32 v) { copy_to_guest(c, base + off, &v, 4); }

/* Deliver `sig` to the guest handler in m->sigact[sig] (caller checked it is
 * a real handler). Builds the frame and redirects the CPU. */
static void deliver_to_handler(CPU *c, int sig, const PendSig *info) {
    struct Machine *m = c->m;
    GSigAction *act = &m->sigact[sig];

    int restart = 0;
    u64 saved_pc = c->pc, saved_x0 = c->x[0];
    if (g_tls.sc_ret_eintr && (act->flags & G_SA_RESTART)) {
        switch (g_tls.sc_nr) {   /* restartable subset (kernel: ERESTARTSYS) */
            case G_NR_read: case G_NR_write: case G_NR_readv: case G_NR_writev:
            case G_NR_pread64: case G_NR_pwrite64: case G_NR_wait4:
            case G_NR_waitid: case G_NR_ioctl: case G_NR_futex:
            case G_NR_accept: case G_NR_connect: case G_NR_recvfrom:
            case G_NR_sendto: case G_NR_recvmsg: case G_NR_sendmsg:
                restart = 1;
                break;
        }
    }
    if (restart) { saved_pc = g_tls.sc_svc_pc; saved_x0 = g_tls.sc_orig_x0; }

    /* Pick the stack: guest sigaltstack if requested and configured. */
    u64 sp = *cpu_cur_sp(c);
    int used_altstack = 0;
    if ((act->flags & G_SA_ONSTACK) && g_tls.sig_altstack_size && !sig_on_altstack(sp)) {
        sp = g_tls.sig_altstack_sp + g_tls.sig_altstack_size;
        used_altstack = 1;
    }
    u64 frame = (sp - FRAME_SIZE) & ~15ULL;

    /* Zero the whole frame, then fill. */
    static const u8 zeros[512];
    for (u64 off = 0; off < FRAME_SIZE; off += sizeof zeros) {
        u64 chunk = FRAME_SIZE - off < sizeof zeros ? FRAME_SIZE - off : sizeof zeros;
        if (copy_to_guest(c, frame + off, zeros, chunk) < 0) {
            /* Unwritable stack: force default SIGSEGV (matches the kernel). */
            fprintf(stderr, "arm64chroot: cannot write sigframe, killing\n");
            proctab_unregister((s32)getpid());
            signal(SIGSEGV, SIG_DFL);
            raise(SIGSEGV);
            _exit(128 + SIGSEGV);
        }
    }

    /* siginfo (LP64 layout: signo, errno, code, pad, fields at +16) */
    wr32(c, frame, SI_OFF + 0, (u32)sig);
    wr32(c, frame, SI_OFF + 4, (u32)info->err);
    wr32(c, frame, SI_OFF + 8, (u32)info->code);
    if (sig == SIGCHLD) {
        wr32(c, frame, SI_OFF + 16, (u32)info->pid);
        wr32(c, frame, SI_OFF + 20, (u32)info->uid);
        wr32(c, frame, SI_OFF + 24, (u32)info->status);
    } else if (is_sync_sig(sig)) {
        wr64(c, frame, SI_OFF + 16, info->addr);
    } else if (sig == SIGSYS && info->code == SIG_SECCOMP_CODE) {
        /* _sigsys: the call address, the syscall number and the architecture
         * -- what a seccomp trap handler reads to decide what was blocked. */
        wr64(c, frame, SI_OFF + 16, info->addr);
        wr32(c, frame, SI_OFF + 24, (u32)info->status);
        wr32(c, frame, SI_OFF + 28, G_AUDIT_ARCH_AARCH64);
    } else {
        wr32(c, frame, SI_OFF + 16, (u32)info->pid);
        wr32(c, frame, SI_OFF + 20, (u32)info->uid);
        /* si_value: carries the rt_sigqueueinfo/sigqueue payload; the kernel
         * zeroes this union region for plain kill (SI_USER), so the captured
         * zero is faithful there too. */
        wr64(c, frame, SI_OFF + 24, (u64)(s64)info->value);
    }

    /* ucontext */
    u64 mask_to_save = g_tls.have_saved_sigmask ? g_tls.saved_sigmask
                                                : g_tls.sigmask;
    g_tls.have_saved_sigmask = 0;
    wr64(c, frame, UC_STACK + 0, g_tls.sig_altstack_sp);
    wr32(c, frame, UC_STACK + 8,
         !g_tls.sig_altstack_size ? 2 /*SS_DISABLE*/
                                  : (used_altstack ? 0 : 1 /*SS_ONSTACK*/));
    wr64(c, frame, UC_STACK + 16, g_tls.sig_altstack_size);
    wr64(c, frame, UC_SIGMASK, mask_to_save);

    /* sigcontext */
    wr64(c, frame, MC_FAULTADDR, is_sync_sig(sig) ? info->addr : 0);
    for (int i = 0; i < 31; i++) wr64(c, frame, MC_REGS + 8u * (unsigned)i,
                                      (i == 0) ? saved_x0 : c->x[i]);
    wr64(c, frame, MC_SP, *cpu_cur_sp(c));
    wr64(c, frame, MC_PC, saved_pc);
    wr64(c, frame, MC_PSTATE, cpu_pack_spsr(c));

    /* fpsimd_context + terminator */
    wr32(c, frame, MC_RESERVED + 0, FPSIMD_MAGIC);
    wr32(c, frame, MC_RESERVED + 4, 528);
    wr32(c, frame, MC_RESERVED + 8, c->fpsr);
    wr32(c, frame, MC_RESERVED + 12, c->fpcr);
    for (int i = 0; i < 32; i++)
        copy_to_guest(c, frame + MC_RESERVED + 16 + 16u * (unsigned)i, &c->v[i], 16);
    /* terminator record is already zero */

    /* Redirect the CPU into the handler. */
    c->x[0] = (u64)sig;
    c->x[1] = frame + SI_OFF;
    c->x[2] = frame + UC_OFF;
    c->x[30] = m->sigtramp_va;
    *cpu_cur_sp(c) = frame;
    c->pc = act->handler;

    /* New blocked set while the handler runs. */
    g_tls.sigmask |= act->mask;
    if (!(act->flags & G_SA_NODEFER)) g_tls.sigmask |= 1ULL << (sig - 1);
    g_tls.sigmask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));

    if (act->flags & G_SA_RESETHAND) {
        act->handler = GSIG_DFL;
        act->flags = 0;
        sig_host_update(m, sig);
    }
    g_tls.sc_ret_eintr = 0;
}

void sig_return(CPU *c) {
    u64 frame = *cpu_cur_sp(c);
    u64 v;
    for (int i = 0; i < 31; i++) {
        if (copy_from_guest(c, &c->x[i], frame + MC_REGS + 8u * (unsigned)i, 8) < 0)
            goto bad;
    }
    if (copy_from_guest(c, &v, frame + MC_SP, 8) < 0) goto bad;
    *cpu_cur_sp(c) = v;
    if (copy_from_guest(c, &v, frame + MC_PC, 8) < 0) goto bad;
    c->pc = v;
    if (copy_from_guest(c, &v, frame + MC_PSTATE, 8) < 0) goto bad;
    c->nzcv = (u32)v & (PS_N | PS_Z | PS_C | PS_V);
    if (copy_from_guest(c, &v, frame + UC_SIGMASK, 8) < 0) goto bad;
    g_tls.sigmask = v & ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    sig_sync_host_mask(c->m);
    /* fpsimd */
    u32 magic = 0;
    copy_from_guest(c, &magic, frame + MC_RESERVED, 4);
    if (magic == FPSIMD_MAGIC) {
        u32 f;
        copy_from_guest(c, &f, frame + MC_RESERVED + 8, 4); c->fpsr = f;
        copy_from_guest(c, &f, frame + MC_RESERVED + 12, 4); c->fpcr = f;
        for (int i = 0; i < 32; i++)
            copy_from_guest(c, &c->v[i], frame + MC_RESERVED + 16 + 16u * (unsigned)i, 16);
    }
    c->excl_valid = false;
    return;
bad:
    fprintf(stderr, "arm64chroot: bad sigreturn frame, killing\n");
    proctab_unregister((s32)getpid());
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
    _exit(128 + SIGSEGV);
}

/* Does this thread's capture queue hold a signal that sig_deliver_pending
 * would act on under the current per-thread mask? rt_sigsuspend polls this:
 * its host sleep only wakes for new arrivals, so a signal queued before the
 * mask swap must short-circuit the sleep. Skips what delivery would discard
 * (ignored, and default-ignore dispositions), matching the kernel, where
 * those never wake sigsuspend. */
int sig_pending_deliverable(struct Machine *m) {
    for (int t = sigq_tail; t != sigq_head; t = (t + 1) % SIGQ_LEN) {
        int sig = sigq[t].signo;
        if (g_tls.sigmask & (1ULL << (sig - 1))) continue;
        u64 h = m->sigact[sig].handler;
        if (h == GSIG_IGN) continue;
        if (h == GSIG_DFL && (sig == SIGCHLD || sig == SIGWINCH ||
                              sig == SIGURG || sig == SIGCONT))
            continue;
        return 1;
    }
    return 0;
}

/* ---- signalfd(2) view of the capture ring (sys_sig.c drives these) ----
 *
 * A signalfd reports signals that are *pending*, i.e. queued and not yet
 * dispositioned -- exactly what the ring holds, since sig_deliver_pending
 * consumes everything the guest mask lets through (including the
 * default-ignore discards). So the ring restricted to the fd's mask is the
 * set a read(2) may return, and no separate bookkeeping is needed. */
int sig_fd_pending(u64 mask) {
    for (int t = sigq_tail; t != sigq_head; t = (t + 1) % SIGQ_LEN)
        if (mask & (1ULL << (sigq[t].signo - 1))) return 1;
    return 0;
}

/* Pop the oldest queued signal covered by `mask` into a signalfd_siginfo.
 * Returns 0 when the ring holds no match. Only the fields the kernel fills for
 * the signal's si_code are set; the rest stay zero, as they do there. */
int sig_fd_take(u64 mask, GSignalfdSiginfo *out) {
    for (int t = sigq_tail; t != sigq_head; t = (t + 1) % SIGQ_LEN) {
        int sig = sigq[t].signo;
        if (!(mask & (1ULL << (sig - 1)))) continue;
        PendSig p = sigq[t];
        for (int u = t; u != sigq_tail; ) {   /* remove by shifting, as above */
            int prev = (u + SIGQ_LEN - 1) % SIGQ_LEN;
            sigq[u] = sigq[prev];
            u = prev;
        }
        sigq_tail = (sigq_tail + 1) % SIGQ_LEN;
        if (sigq_tail == sigq_head) g_sig_npend = 0;
        memset(out, 0, sizeof *out);
        out->ssi_signo = (u32)p.signo;
        out->ssi_code = p.code;
        out->ssi_pid = (u32)p.pid;
        out->ssi_uid = (u32)p.uid;
        out->ssi_status = p.status;
        out->ssi_addr = p.addr;
        out->ssi_int = (s32)p.value;
        out->ssi_ptr = (u64)p.value;
        return 1;
    }
    return 0;
}

/* rt_sigtimedwait: synchronously consume one pending signal from `set` off
 * this thread's capture ring -- without invoking its handler -- as sigwait/
 * sigwaitinfo do. The caller keeps these signals *blocked* (the POSIX
 * contract), and blocked host-caught signals accumulate in the ring, so the
 * ring is exactly the pending set to take from; the guest block mask is
 * deliberately ignored (sigwait consumes blocked signals). Polls in short
 * naps like rt_sigsuspend: a matching signal can land on this thread at any
 * moment -- e.g. a SIGEV_THREAD_ID timer aimed at a libc timer helper thread
 * sigwaitinfo()ing its SIGTIMER. timeout_ns < 0 waits forever. Returns the
 * signal number, -EAGAIN on timeout, or -EINTR when a different deliverable
 * signal pends (the run loop delivers it once the syscall returns). */
s64 sig_timedwait(CPU *c, u64 set, u64 info_va, s64 timeout_ns) {
    struct Machine *m = c->m;
    struct timespec dl;
    if (timeout_ns > 0) {
        clock_gettime(CLOCK_MONOTONIC, &dl);
        dl.tv_sec += (time_t)(timeout_ns / 1000000000);
        dl.tv_nsec += (long)(timeout_ns % 1000000000);
        if (dl.tv_nsec >= 1000000000) { dl.tv_sec++; dl.tv_nsec -= 1000000000; }
    }
    for (;;) {
        for (int t = sigq_tail; t != sigq_head; t = (t + 1) % SIGQ_LEN) {
            int sig = sigq[t].signo;
            if (!(set & (1ULL << (sig - 1)))) continue;
            PendSig p = sigq[t];
            for (int u = t; u != sigq_tail; ) {   /* remove by shifting */
                int prev = (u + SIGQ_LEN - 1) % SIGQ_LEN;
                sigq[u] = sigq[prev];
                u = prev;
            }
            sigq_tail = (sigq_tail + 1) % SIGQ_LEN;
            if (sigq_tail == sigq_head) g_sig_npend = 0;
            if (info_va) {
                u8 si[128];
                memset(si, 0, sizeof si);
                s32 *w = (s32 *)si;
                w[0] = p.signo;
                w[2] = p.code;
                /* Union fields as the frame writer lays them out: pid/uid --
                 * which SI_TIMER's timerid/overrun alias -- at +16/+20, the
                 * sigval payload at +24. */
                memcpy(si + 16, &p.pid, 4);
                memcpy(si + 20, &p.uid, 4);
                s64 v = (s64)p.value;
                memcpy(si + 24, &v, 8);
                if (copy_to_guest(c, info_va, si, sizeof si) < 0)
                    return -EFAULT;
            }
            return p.signo;
        }
        /* Nothing from `set`: a caught signal arriving during the wait makes
         * the kernel return EINTR -- mirror that when the ring holds another
         * deliverable signal, so the run loop can deliver it. */
        if (g_sig_npend && sig_pending_deliverable(m)) return -EINTR;
        if (timeout_ns == 0) return -EAGAIN;   /* pure poll */
        if (timeout_ns > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > dl.tv_sec ||
                (now.tv_sec == dl.tv_sec && now.tv_nsec >= dl.tv_nsec))
                return -EAGAIN;
        }
        struct timespec nap = { 0, 2 * 1000 * 1000 };
        nanosleep(&nap, NULL);
    }
}

void guest_terminate_by_signal(CPU *c, int sig) {
    /* Report the WIFSIGNALED death to the tracer(s) (a no-op when untraced):
     * the pre-exit PTRACE_EVENT_EXIT under TRACEEXIT, then the terminal status
     * word -- for every traced thread of this process, since the signal kills
     * them all without their own exit paths running. Without this a tracer
     * that is not our host parent (strace -p / a followed child) never learns
     * we died and its wait4 poll hangs. */
    ptrace_report_exit_stop(c, sig & 0x7f);
    ptrace_report_exit_group(sig & 0x7f);
    proctab_unregister((s32)getpid());   /* drop the guest-PID registry slot */
    sembroker_exit(c->m);                /* apply SEM_UNDO now, not at the
                                          * broker's reclaim tick */
    tmpfs_session_cleanup(c->m);         /* session root only: emulated tmpfs */
    ptrace_wake_waiters();               /* wake a parent polling in wait4 */
    /* Restore the host default and re-raise so the real parent also sees the same
     * WIFSIGNALED status (the guest default action really is terminate). */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigaction(sig, &sa, NULL);
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, sig);
    sigprocmask(SIG_UNBLOCK, &ss, NULL);
    raise(sig);
    _exit(128 + sig);
}

void sig_deliver_pending(CPU *c) {
    struct Machine *m = c->m;
    while (sigq_tail != sigq_head) {
        PendSig p = sigq[sigq_tail];
        int sig = p.signo;
        if (g_tls.sigmask & (1ULL << (sig - 1))) {
            /* Blocked: leave it queued. Scan the rest for an unblocked one. */
            int t = sigq_tail;
            int found = -1;
            for (t = (t + 1) % SIGQ_LEN; t != sigq_head; t = (t + 1) % SIGQ_LEN)
                if (!(g_tls.sigmask & (1ULL << (sigq[t].signo - 1)))) { found = t; break; }
            if (found < 0) return;
            p = sigq[found];
            sig = p.signo;
            /* remove `found` by shifting */
            for (int u = found; u != sigq_tail; ) {
                int prev = (u + SIGQ_LEN - 1) % SIGQ_LEN;
                sigq[u] = sigq[prev];
                u = prev;
            }
            sigq_tail = (sigq_tail + 1) % SIGQ_LEN;
        } else {
            sigq_tail = (sigq_tail + 1) % SIGQ_LEN;
        }
        if (sigq_tail == sigq_head) g_sig_npend = 0;

        /* ptrace signal-delivery stop: the tracer sees WSTOPSIG==sig and may
         * suppress it (return 0) or substitute another signal before it is
         * dispositioned. SIGKILL is never interceptable. */
        if (UNLIKELY(g_ptrace_active)) {
            int ns = ptrace_report_signal(c, sig);
            if (ns == 0) continue;              /* suppressed by the tracer */
            if (ns != sig) { sig = ns; p.signo = ns; }
        }

        u64 h = m->sigact[sig].handler;
        if (h == GSIG_IGN) continue;
        if (h == GSIG_DFL) {
            /* A default-terminate signal: kill the process and report the
             * WIFSIGNALED death to our tracer first (does not return). A tracee
             * reaches here after the tracer let the signal through the delivery
             * stop above; an untraced process reaches it only in a rare race (a
             * handler dropped to SIG_DFL after the signal was queued). */
            if (sig_default_terminates(sig))
                guest_terminate_by_signal(c, sig);
            /* Default-ignore/continue disposition: let the host default apply. */
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_handler = SIG_DFL;
            sigaction(sig, &sa, NULL);
            raise(sig);
            sig_host_update(m, sig);   /* stopped+continued: re-mirror */
            continue;
        }
        deliver_to_handler(c, sig, &p);
        return;   /* one at a time; the next check happens after sigreturn */
    }
    g_sig_npend = 0;
}

/* SECCOMP_RET_TRAP: SIGSYS to the guest, carrying the blocked syscall. It is
 * synchronous like a fault -- the guest is at the syscall it just attempted --
 * so it takes the same path, but with the _sigsys siginfo fields. The `data`
 * bits of the filter's return travel in si_errno, as the kernel puts them. */
void sig_deliver_seccomp_trap(CPU *c, int data, s32 nr) {
    struct Machine *m = c->m;
    int sig = SIGSYS;
    if (UNLIKELY(g_ptrace_active)) {
        int ns = ptrace_report_fault(c, sig, SIG_SECCOMP_CODE, c->pc);
        if (ns == 0) return;
        sig = ns;
    }
    u64 h = m->sigact[sig].handler;
    if (h > GSIG_IGN && !(g_tls.sigmask & (1ULL << (sig - 1)))) {
        PendSig p;
        memset(&p, 0, sizeof p);
        p.signo = sig;
        p.code = SIG_SECCOMP_CODE;
        p.addr = c->pc;
        p.status = nr;
        p.err = data;   /* SECCOMP_RET_DATA -> si_errno, as the kernel does */
        g_tls.sc_ret_eintr = 0;
        deliver_to_handler(c, sig, &p);
        return;
    }
    /* No handler: the default action for SIGSYS is to terminate, and a filter
     * that traps a call the guest cannot survive means exactly that. */
    guest_terminate_by_signal(c, sig);
}

void sig_deliver_fault(CPU *c, int sig, int code, u64 addr) {
    struct Machine *m = c->m;
    /* Under ptrace, a synchronous fault is a signal-delivery stop first: the
     * tracer (gdb hitting a BRK software breakpoint, or catching a SIGSEGV) sees
     * it before any guest handler or the fatal default action, and may suppress
     * it (return 0 -> resume, e.g. after gdb steps over a breakpoint) or
     * substitute another signal. The caller's `code` already equals the intended
     * siginfo si_code (BRK->TRAP_BRKPT, SEGV perm->SEGV_ACCERR / else MAPERR,
     * align->1, undef->1). */
    if (UNLIKELY(g_ptrace_active)) {
        int ns = ptrace_report_fault(c, sig, code, addr);
        if (ns == 0) return;              /* tracer suppressed: resume the guest */
        sig = ns;                         /* tracer may have substituted it */
    }
    u64 h = m->sigact[sig].handler;
    if (h > GSIG_IGN && !(g_tls.sigmask & (1ULL << (sig - 1)))) {
        PendSig p;
        memset(&p, 0, sizeof p);
        p.signo = sig;
        p.code = code;
        p.addr = addr;
        g_tls.sc_ret_eintr = 0;
        deliver_to_handler(c, sig, &p);
        return;
    }
    force_sig_fault(c, sig, code, addr);
}
