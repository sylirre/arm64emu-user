/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* seccomp(2): guest syscall filtering, evaluated here rather than delegated.
 *
 * A guest filter is a classic-BPF program over struct seccomp_data, and it is
 * meant to constrain *guest* syscalls -- guest numbers, guest arguments, the
 * guest architecture. Installing it on the host would apply it to something
 * else entirely: the emulator's own host syscalls, on the host's ISA, issued to
 * serve syscalls the guest never made. That is not a filter the guest asked for,
 * and its first mismatch would kill the emulator rather than the guest process.
 *
 * The emulator already sees every guest syscall at one choke point, so the
 * honest implementation is to run the program there (seccomp_gate, called from
 * the dispatcher) and act on what it returns. Sandbox helpers get real
 * enforcement instead of a lie: bubblewrap --seccomp, flatpak's syscall
 * blacklists and libseccomp-generated filters all behave.
 *
 * The accepted instruction set is exactly the kernel's (seccomp_check_filter):
 * 32-bit aligned absolute loads inside seccomp_data, the ALU/JMP/RET/MISC
 * subset, no packet-relative addressing. Anything else is rejected at install
 * time with EINVAL, as there. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sys.h"

/* One installed program. The chain is newest-first: the kernel evaluates every
 * filter and keeps the most severe answer, so order only matters for ties. */
struct SeccompProg {
    struct SeccompProg *prev;
    u32 len;
    GSockFilter insns[];
};

/* Classic-BPF encoding (linux/bpf_common.h), spelled out so no host header is
 * needed -- these are guest-facing constants like every other G_* value. */
#define BPF_CLASS(c) ((c) & 0x07)
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_RET   0x06
#define BPF_MISC  0x07
#define BPF_SIZE(c) ((c) & 0x18)
#define BPF_W     0x00
#define BPF_MODE(c) ((c) & 0xe0)
#define BPF_IMM   0x00
#define BPF_ABS   0x20
#define BPF_MEM   0x60
#define BPF_LEN   0x80
#define BPF_OP(c) ((c) & 0xf0)
#define BPF_ADD   0x00
#define BPF_SUB   0x10
#define BPF_MUL   0x20
#define BPF_DIV   0x30
#define BPF_OR    0x40
#define BPF_AND   0x50
#define BPF_LSH   0x60
#define BPF_RSH   0x70
#define BPF_NEG   0x80
#define BPF_MOD   0x90
#define BPF_XOR   0xa0
#define BPF_JA    0x00
#define BPF_JEQ   0x10
#define BPF_JGT   0x20
#define BPF_JGE   0x30
#define BPF_JSET  0x40
#define BPF_SRC(c) ((c) & 0x08)
#define BPF_K     0x00
#define BPF_X     0x08
#define BPF_A     0x10
#define BPF_TAX   0x00
#define BPF_TXA   0x80

#define BPF_MEMWORDS 16

/* The kernel's own accept-list (seccomp_check_filter) plus its jump checks
 * (bpf_check_classic): every jump forward and in range, and a RET last, so the
 * program provably terminates. Returns 0 or -errno. */
static int bpf_validate(const GSockFilter *f, u32 len) {
    if (len == 0 || len > G_BPF_MAXINSNS) return -EINVAL;
    for (u32 pc = 0; pc < len; pc++) {
        u16 code = f[pc].code;
        u32 k = f[pc].k;
        switch (code) {
        case BPF_LD | BPF_W | BPF_ABS:
            /* Loads may only reach seccomp_data, 32-bit aligned. */
            if (k >= sizeof(GSeccompData) || (k & 3)) return -EINVAL;
            break;
        case BPF_LD | BPF_W | BPF_LEN:
        case BPF_LDX | BPF_W | BPF_LEN:
        case BPF_LD | BPF_IMM:
        case BPF_LDX | BPF_IMM:
        case BPF_MISC | BPF_TAX:
        case BPF_MISC | BPF_TXA:
        case BPF_RET | BPF_K:
        case BPF_RET | BPF_A:
            break;
        case BPF_LD | BPF_MEM:
        case BPF_LDX | BPF_MEM:
        case BPF_ST:
        case BPF_STX:
            if (k >= BPF_MEMWORDS) return -EINVAL;
            break;
        case BPF_ALU | BPF_ADD | BPF_K: case BPF_ALU | BPF_ADD | BPF_X:
        case BPF_ALU | BPF_SUB | BPF_K: case BPF_ALU | BPF_SUB | BPF_X:
        case BPF_ALU | BPF_MUL | BPF_K: case BPF_ALU | BPF_MUL | BPF_X:
        case BPF_ALU | BPF_DIV | BPF_K: case BPF_ALU | BPF_DIV | BPF_X:
        case BPF_ALU | BPF_MOD | BPF_K: case BPF_ALU | BPF_MOD | BPF_X:
        case BPF_ALU | BPF_AND | BPF_K: case BPF_ALU | BPF_AND | BPF_X:
        case BPF_ALU | BPF_OR  | BPF_K: case BPF_ALU | BPF_OR  | BPF_X:
        case BPF_ALU | BPF_XOR | BPF_K: case BPF_ALU | BPF_XOR | BPF_X:
        case BPF_ALU | BPF_LSH | BPF_K: case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_K: case BPF_ALU | BPF_RSH | BPF_X:
        case BPF_ALU | BPF_NEG:
            /* A constant shift past the word width is rejected, as there. */
            if ((code == (BPF_ALU | BPF_LSH | BPF_K) ||
                 code == (BPF_ALU | BPF_RSH | BPF_K)) && k >= 32) return -EINVAL;
            break;
        case BPF_JMP | BPF_JA:
            if (k >= len - pc - 1) return -EINVAL;   /* forward, in range */
            break;
        case BPF_JMP | BPF_JEQ  | BPF_K: case BPF_JMP | BPF_JEQ  | BPF_X:
        case BPF_JMP | BPF_JGT  | BPF_K: case BPF_JMP | BPF_JGT  | BPF_X:
        case BPF_JMP | BPF_JGE  | BPF_K: case BPF_JMP | BPF_JGE  | BPF_X:
        case BPF_JMP | BPF_JSET | BPF_K: case BPF_JMP | BPF_JSET | BPF_X:
            if (f[pc].jt >= len - pc - 1 || f[pc].jf >= len - pc - 1)
                return -EINVAL;
            break;
        default:
            return -EINVAL;
        }
    }
    return BPF_CLASS(f[len - 1].code) == BPF_RET ? 0 : -EINVAL;
}

/* Run one validated program. Division or modulo by zero aborts the program
 * with 0, matching the kernel's interpreter (0 is SECCOMP_RET_KILL_THREAD --
 * severe, but that is the kernel's answer to a broken filter too). */
static u32 bpf_run(const GSockFilter *f, u32 len, const GSeccompData *d) {
    const u8 *data = (const u8 *)d;
    u32 A = 0, X = 0, mem[BPF_MEMWORDS] = { 0 };
    for (u32 pc = 0; pc < len; pc++) {
        u16 code = f[pc].code;
        u32 k = f[pc].k;
        switch (BPF_CLASS(code)) {
        case BPF_LD:
            if (BPF_MODE(code) == BPF_ABS)      memcpy(&A, data + k, 4);
            else if (BPF_MODE(code) == BPF_IMM) A = k;
            else if (BPF_MODE(code) == BPF_MEM) A = mem[k];
            else                                A = (u32)sizeof(GSeccompData);
            break;
        case BPF_LDX:
            if (BPF_MODE(code) == BPF_IMM)      X = k;
            else if (BPF_MODE(code) == BPF_MEM) X = mem[k];
            else                                X = (u32)sizeof(GSeccompData);
            break;
        case BPF_ST:  mem[k] = A; break;
        case BPF_STX: mem[k] = X; break;
        case BPF_ALU: {
            u32 v = BPF_SRC(code) == BPF_X ? X : k;
            switch (BPF_OP(code)) {
            case BPF_ADD: A += v; break;
            case BPF_SUB: A -= v; break;
            case BPF_MUL: A *= v; break;
            case BPF_DIV: if (!v) return 0; A /= v; break;
            case BPF_MOD: if (!v) return 0; A %= v; break;
            case BPF_AND: A &= v; break;
            case BPF_OR:  A |= v; break;
            case BPF_XOR: A ^= v; break;
            case BPF_LSH: if (v >= 32) return 0; A <<= v; break;
            case BPF_RSH: if (v >= 32) return 0; A >>= v; break;
            case BPF_NEG: A = (u32)(-(s32)A); break;
            }
            break;
        }
        case BPF_JMP: {
            if (BPF_OP(code) == BPF_JA) { pc += k; break; }
            u32 v = BPF_SRC(code) == BPF_X ? X : k;
            int t = 0;
            switch (BPF_OP(code)) {
            case BPF_JEQ:  t = (A == v); break;
            case BPF_JGT:  t = (A >  v); break;
            case BPF_JGE:  t = (A >= v); break;
            case BPF_JSET: t = ((A & v) != 0); break;
            }
            pc += t ? f[pc].jt : f[pc].jf;
            break;
        }
        case BPF_RET:
            return (code & BPF_A) ? A : k;
        case BPF_MISC:
            if ((code & 0xf8) == BPF_TAX) X = A; else A = X;
            break;
        }
    }
    return 0;   /* validated to end in RET, so unreachable */
}

/* Evaluate the whole chain: every filter runs, and the most severe answer wins
 * (lowest value under G_SECCOMP_RET_ACTION). Ties keep the newest filter's
 * data, which is the order the kernel walks in. */
static u32 seccomp_run_chain(struct Machine *m, const GSeccompData *d) {
    u32 ret = G_SECCOMP_RET_ALLOW;
    for (struct SeccompProg *p = m->seccomp_filters; p; p = p->prev) {
        u32 cur = bpf_run(p->insns, p->len, d);
        if ((cur & G_SECCOMP_RET_ACTION) < (ret & G_SECCOMP_RET_ACTION)) ret = cur;
    }
    return ret;
}

/* Strict mode's fixed policy: read, write, exit and rt_sigreturn only, and
 * SIGKILL -- not SIGSYS -- for anything else, as the kernel does. */
static int strict_allows(u64 nr) {
    return nr == G_NR_read || nr == G_NR_write ||
           nr == G_NR_exit || nr == G_NR_rt_sigreturn;
}

/* Called by the dispatcher for every guest syscall once a filter exists (the
 * m->seccomp_mode check keeps the unfiltered path free). Returns 1 when the
 * syscall must NOT run, with *ret holding what the guest sees; 0 to proceed.
 * Killing actions do not return at all. */
int seccomp_gate(CPU *c, u64 nr, const u64 *args, s64 *ret) {
    struct Machine *m = c->m;
    if (m->seccomp_mode == G_SECCOMP_MODE_STRICT) {
        if (strict_allows(nr)) return 0;
        guest_terminate_by_signal(c, SIGKILL);
    }
    GSeccompData d;
    memset(&d, 0, sizeof d);
    d.nr = (s32)nr;
    d.arch = G_AUDIT_ARCH_AARCH64;
    d.instruction_pointer = c->pc;
    for (int i = 0; i < 6; i++) d.args[i] = args[i];

    u32 action = seccomp_run_chain(m, &d);
    switch (action & G_SECCOMP_RET_ACTION_FULL) {
    case G_SECCOMP_RET_ALLOW:
    case G_SECCOMP_RET_LOG:      /* logging is the kernel's audit trail, not ours */
        return 0;
    case G_SECCOMP_RET_ERRNO: {
        u32 e = action & G_SECCOMP_RET_DATA;
        if (e > 4095) e = 4095;   /* MAX_ERRNO clamp */
        *ret = -(s64)e;
        return 1;
    }
    case G_SECCOMP_RET_TRAP:
        /* SIGSYS to the guest, syscall skipped, -ENOSYS left behind as the
         * result like the kernel. A handler that inspects si_syscall/si_arch
         * sees them; that is how a libseccomp-style trap handler identifies
         * the call. Delivery is deferred to the dispatcher (return 2): the
         * signal frame has to capture the *result* in x0, and the handler's
         * own arguments go into x0..x2 after that -- doing it here would have
         * both overwritten. */
        *ret = -ENOSYS;
        return 2;
    case G_SECCOMP_RET_TRACE:
        /* No tracer is listening for seccomp events here, and the kernel's
         * answer to that is to skip the call and return ENOSYS. */
        *ret = -ENOSYS;
        return 1;
    case G_SECCOMP_RET_KILL_THREAD:
    case G_SECCOMP_RET_KILL_PROCESS:
    default:
        /* Unknown actions are killing actions, as in the kernel. A thread kill
         * takes the whole process here (guest threads are host threads sharing
         * one Machine), which differs only for a filtered multithreaded guest. */
        guest_terminate_by_signal(c, SIGSYS);
    }
    return 0;   /* not reached */
}

/* A process cannot switch modes: strict after a filter (or the other way) is
 * EINVAL, while stacking another filter onto filter mode is the normal path
 * (seccomp_may_assign_mode). */
static int may_assign_mode(struct Machine *m, u8 mode) {
    return m->seccomp_mode == 0 || m->seccomp_mode == mode;
}

/* Install a filter: copy the program in, validate it, push it on the chain. */
static s64 seccomp_install(CPU *c, u64 flags, u64 prog_va) {
    struct Machine *m = c->m;
    /* The kernel requires no_new_privs (or CAP_SYS_ADMIN) so a filtered
     * process cannot gain privilege through a setuid exec it can no longer
     * see. Our fake-root is that capability. */
    if (!m->no_new_privs && !(m->fake_id && m->cred.euid == 0)) return -EACCES;
    if (!may_assign_mode(m, G_SECCOMP_MODE_FILTER)) return -EINVAL;
    /* TSYNC is implicit here (one filter chain per process); LOG and
     * SPEC_ALLOW are advisory. A listener fd is something we cannot service. */
    if (flags & ~(u64)(G_SECCOMP_FILTER_FLAG_TSYNC | G_SECCOMP_FILTER_FLAG_LOG |
                       G_SECCOMP_FILTER_FLAG_SPEC_ALLOW |
                       G_SECCOMP_FILTER_FLAG_TSYNC_ESRCH))
        return (flags & G_SECCOMP_FILTER_FLAG_NEW_LISTENER) ? -EOPNOTSUPP : -EINVAL;

    GSockFprog fprog;
    if (copy_from_guest(c, &fprog, prog_va, sizeof fprog) < 0) return -EFAULT;
    u32 len = fprog.len;
    if (len == 0 || len > G_BPF_MAXINSNS) return -EINVAL;

    struct SeccompProg *p = malloc(sizeof *p + (size_t)len * sizeof(GSockFilter));
    if (!p) return -ENOMEM;
    if (copy_from_guest(c, p->insns, fprog.filter,
                        (size_t)len * sizeof(GSockFilter)) < 0) {
        free(p);
        return -EFAULT;
    }
    int r = bpf_validate(p->insns, len);
    if (r < 0) { free(p); return r; }
    p->len = len;
    p->prev = m->seccomp_filters;
    m->seccomp_filters = p;
    m->seccomp_mode = G_SECCOMP_MODE_FILTER;
    return 0;
}

/* prctl(PR_SET_SECCOMP) -- the older way in, still what bubblewrap uses. */
s64 seccomp_prctl_set(CPU *c, u64 mode, u64 prog_va) {
    if (mode == G_SECCOMP_MODE_STRICT) {
        if (!may_assign_mode(c->m, G_SECCOMP_MODE_STRICT)) return -EINVAL;
        c->m->seccomp_mode = G_SECCOMP_MODE_STRICT;
        return 0;
    }
    if (mode == G_SECCOMP_MODE_FILTER) return seccomp_install(c, 0, prog_va);
    return -EINVAL;
}

SYSDEF(seccomp) {
    (void)a3; (void)a4; (void)a5;
    switch (a0) {
    case G_SECCOMP_SET_MODE_STRICT:
        if (a1 != 0 || a2 != 0) return (u64)(s64)-EINVAL;
        if (!may_assign_mode(c->m, G_SECCOMP_MODE_STRICT)) return (u64)(s64)-EINVAL;
        c->m->seccomp_mode = G_SECCOMP_MODE_STRICT;
        return 0;
    case G_SECCOMP_SET_MODE_FILTER:
        return (u64)seccomp_install(c, a1, a2);
    case G_SECCOMP_GET_ACTION_AVAIL: {
        /* "Is this action supported?" -- probed by libseccomp before it emits
         * a program using one. USER_NOTIF is the one we have to decline. */
        u32 act;
        if (a1 != 0) return (u64)(s64)-EINVAL;
        if (copy_from_guest(c, &act, a2, 4) < 0) return (u64)(s64)-EFAULT;
        switch (act & G_SECCOMP_RET_ACTION_FULL) {
        case G_SECCOMP_RET_KILL_PROCESS:
        case G_SECCOMP_RET_KILL_THREAD:
        case G_SECCOMP_RET_TRAP:
        case G_SECCOMP_RET_ERRNO:
        case G_SECCOMP_RET_TRACE:
        case G_SECCOMP_RET_LOG:
        case G_SECCOMP_RET_ALLOW:
            return 0;
        default:
            return (u64)(s64)-EOPNOTSUPP;
        }
    }
    case G_SECCOMP_GET_NOTIF_SIZES:
        return (u64)(s64)-EOPNOTSUPP;   /* no user-notification listener here */
    default:
        return (u64)(s64)-EINVAL;
    }
}
