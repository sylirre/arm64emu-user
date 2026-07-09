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
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#include "machine.h"
#include "guest_abi.h"

#define GSIG_DFL 0
#define GSIG_IGN 1

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
    int pid, uid, status;
    u64 addr;
    long value;
} PendSig;

#define SIGQ_LEN 32
static __thread PendSig sigq[SIGQ_LEN];
static __thread volatile sig_atomic_t sigq_head, sigq_tail;
__thread volatile sig_atomic_t g_sig_npend;

static void host_catcher(int sig, siginfo_t *si, void *uctx) {
    (void)uctx;
    int next = (sigq_head + 1) % SIGQ_LEN;
    if (next == sigq_tail) return;   /* queue full: drop (kernel coalesces too) */
    PendSig *p = &sigq[sigq_head];
    p->signo = sig;
    p->code = si->si_code;
    p->pid = (int)si->si_pid;
    p->uid = (int)si->si_uid;
    p->status = si->si_status;
    p->addr = (u64)(uintptr_t)si->si_addr;
    p->value = (long)(uintptr_t)si->si_value.sival_ptr;   /* full width on LP64 */
    sigq_head = next;
    g_sig_npend = 1;
}

/* Signals delivered synchronously from the interpreter (never host-caught). */
static int is_sync_sig(int sig) {
    return sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE ||
           sig == SIGTRAP;
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

/* Mirror the guest block-state of the terminal job-control signals to the host
 * process mask. SIGTTOU/SIGTTIN are generated *synchronously by the host
 * kernel* (tcsetpgrp, background terminal I/O) and would stop our process
 * before the run loop can mediate; SIGTSTP travels with them in bash's
 * give_terminal_to() critical section. When the guest blocks one of these
 * (as bash does around tcsetpgrp), we must block it on the host too — POSIX
 * then suppresses the signal entirely instead of stopping us. */
void sig_sync_host_mask(struct Machine *m) {
    static const int sigs[] = { SIGTTOU, SIGTTIN, SIGTSTP };
    sigset_t block, unblock;
    sigemptyset(&block);
    sigemptyset(&unblock);
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        if (m->sigmask & (1ULL << (sigs[i] - 1))) sigaddset(&block, sigs[i]);
        else sigaddset(&unblock, sigs[i]);
    }
    sigprocmask(SIG_BLOCK, &block, NULL);
    sigprocmask(SIG_UNBLOCK, &unblock, NULL);
}

void sig_host_update(struct Machine *m, int sig) {
    if (sig < 1 || sig > 64 || sig == SIGKILL || sig == SIGSTOP) return;
    if (sig == 32 || sig == 33) return;          /* host-libc internal rt sigs */
    if (sig == SIGSYS) return;                   /* owned by the SIGSYS net; guest
                                                    dispositions are honored via
                                                    the capture queue */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    u64 h = m->sigact[sig].handler;
    if (h == GSIG_DFL) {
        sa.sa_handler = SIG_DFL;
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
    m->sig_altstack_sp = m->sig_altstack_size = 0;
    g_tls.on_altstack = 0;
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
    if ((act->flags & G_SA_ONSTACK) && m->sig_altstack_size && !g_tls.on_altstack) {
        sp = m->sig_altstack_sp + m->sig_altstack_size;
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
            signal(SIGSEGV, SIG_DFL);
            raise(SIGSEGV);
            _exit(128 + SIGSEGV);
        }
    }

    /* siginfo (LP64 layout: signo, errno, code, pad, fields at +16) */
    wr32(c, frame, SI_OFF + 0, (u32)sig);
    wr32(c, frame, SI_OFF + 8, (u32)info->code);
    if (sig == SIGCHLD) {
        wr32(c, frame, SI_OFF + 16, (u32)info->pid);
        wr32(c, frame, SI_OFF + 20, (u32)info->uid);
        wr32(c, frame, SI_OFF + 24, (u32)info->status);
    } else if (is_sync_sig(sig)) {
        wr64(c, frame, SI_OFF + 16, info->addr);
    } else {
        wr32(c, frame, SI_OFF + 16, (u32)info->pid);
        wr32(c, frame, SI_OFF + 20, (u32)info->uid);
        /* si_value: carries the rt_sigqueueinfo/sigqueue payload; the kernel
         * zeroes this union region for plain kill (SI_USER), so the captured
         * zero is faithful there too. */
        wr64(c, frame, SI_OFF + 24, (u64)(s64)info->value);
    }

    /* ucontext */
    u64 mask_to_save = m->have_saved_sigmask ? m->saved_sigmask : m->sigmask;
    m->have_saved_sigmask = 0;
    wr64(c, frame, UC_STACK + 0, m->sig_altstack_sp);
    wr32(c, frame, UC_STACK + 8,
         m->sig_altstack_size ? (g_tls.on_altstack ? 1 /*SS_ONSTACK*/ : 0)
                              : 2 /*SS_DISABLE*/);
    wr64(c, frame, UC_STACK + 16, m->sig_altstack_size);
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
    if (used_altstack) g_tls.on_altstack = 1;

    /* New blocked set while the handler runs. */
    m->sigmask |= act->mask;
    if (!(act->flags & G_SA_NODEFER)) m->sigmask |= 1ULL << (sig - 1);
    m->sigmask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));

    if (act->flags & G_SA_RESETHAND) {
        act->handler = GSIG_DFL;
        act->flags = 0;
        sig_host_update(m, sig);
    }
    g_tls.sc_ret_eintr = 0;
}

void sig_return(CPU *c) {
    struct Machine *m = c->m;
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
    m->sigmask = v & ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    sig_sync_host_mask(m);
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
    g_tls.on_altstack = 0;
    c->excl_valid = false;
    return;
bad:
    fprintf(stderr, "arm64chroot: bad sigreturn frame, killing\n");
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
    _exit(128 + SIGSEGV);
}

void sig_deliver_pending(CPU *c) {
    struct Machine *m = c->m;
    while (sigq_tail != sigq_head) {
        PendSig p = sigq[sigq_tail];
        int sig = p.signo;
        if (m->sigmask & (1ULL << (sig - 1))) {
            /* Blocked: leave it queued. Scan the rest for an unblocked one. */
            int t = sigq_tail;
            int found = -1;
            for (t = (t + 1) % SIGQ_LEN; t != sigq_head; t = (t + 1) % SIGQ_LEN)
                if (!(m->sigmask & (1ULL << (sigq[t].signo - 1)))) { found = t; break; }
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

        u64 h = m->sigact[sig].handler;
        if (h == GSIG_IGN) continue;
        if (h == GSIG_DFL) {
            /* Host default disposition applies; only reachable in races
             * (disposition changed after queueing). Re-raise. */
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

void sig_deliver_fault(CPU *c, int sig, int code, u64 addr) {
    struct Machine *m = c->m;
    u64 h = m->sigact[sig].handler;
    if (h > GSIG_IGN && !(m->sigmask & (1ULL << (sig - 1)))) {
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
