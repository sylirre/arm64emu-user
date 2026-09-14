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
 * filter and keeps the most severe answer, so order only matters for ties.
 *
 * A node is immutable once published and is never freed (the chain is kept
 * across execve and copied by fork, as the kernel keeps filters), so the
 * dispatcher walks it without a lock: the head is stored with release
 * semantics under the task lock, which serializes installers, and loaded with
 * acquire semantics by every reader -- so a reader that sees a node sees its
 * length, its instructions and its `prev`, on a weakly ordered host as well
 * as on x86. It used to be a plain pointer written by whoever got there:
 * two threads installing at once read the same head and one filter of the
 * two was lost, and an arm64 reader could take the new head before the
 * node's contents had reached it. */
struct SeccompProg {
    struct SeccompProg *prev;
    u32 len;
    u32 elen;   /* the kernel's converted length, for the chain budget */
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
        /* Every ALU form the kernel's list has -- which is not every form
         * classic BPF has: BPF_MOD (a 3.7 addition to the packet filter) was
         * never added to seccomp_check_filter, so a filter using it is EINVAL
         * on every kernel, and was accepted here. */
        case BPF_ALU | BPF_ADD | BPF_K: case BPF_ALU | BPF_ADD | BPF_X:
        case BPF_ALU | BPF_SUB | BPF_K: case BPF_ALU | BPF_SUB | BPF_X:
        case BPF_ALU | BPF_MUL | BPF_K: case BPF_ALU | BPF_MUL | BPF_X:
        case BPF_ALU | BPF_DIV | BPF_K: case BPF_ALU | BPF_DIV | BPF_X:
        case BPF_ALU | BPF_AND | BPF_K: case BPF_ALU | BPF_AND | BPF_X:
        case BPF_ALU | BPF_OR  | BPF_K: case BPF_ALU | BPF_OR  | BPF_X:
        case BPF_ALU | BPF_XOR | BPF_K: case BPF_ALU | BPF_XOR | BPF_X:
        case BPF_ALU | BPF_LSH | BPF_K: case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_K: case BPF_ALU | BPF_RSH | BPF_X:
        case BPF_ALU | BPF_NEG:
            /* A constant shift past the word width is rejected, as there. */
            if ((code == (BPF_ALU | BPF_LSH | BPF_K) ||
                 code == (BPF_ALU | BPF_RSH | BPF_K)) && k >= 32) return -EINVAL;
            /* And so is a constant division by zero: it is knowable at load
             * time, so bpf_check_classic refuses the program rather than let
             * the interpreter meet it. Accepting it here installed a filter
             * that looked valid and then killed the thread the first time that
             * instruction was reached -- the guest heard about its own broken
             * filter as a death rather than as an EINVAL from seccomp(2). The
             * BPF_X form stays a runtime check, as there: whether X is zero is
             * not knowable until the filter runs. */
            if (code == (BPF_ALU | BPF_DIV | BPF_K) && k == 0) return -EINVAL;
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

/* The installed chain, as every reader takes it (see struct SeccompProg). */
static struct SeccompProg *chain_head(struct Machine *m) {
    return __atomic_load_n((struct SeccompProg **)&m->seccomp_filters,
                           __ATOMIC_ACQUIRE);
}

/* The kernel does not run the classic program: it converts it to eBPF
 * (bpf_convert_filter) and runs that, and the length of the conversion is
 * what its chain budget counts (seccomp_attach_filter, MAX_INSNS_PER_PATH).
 * This is that length, for a program bpf_validate has accepted: a prologue of
 * three (A and X cleared, the context register set), one instruction for
 * almost everything, two for a RET K (a move and the exit), five for a
 * division by X (the zero check that exits with 0), and for a conditional
 * jump one when its false branch falls through, one when its true branch does
 * and the test has an inverse (JEQ, JGT, JGE), two otherwise (the test and a
 * JA) -- plus one when the constant compared against is negative as an s32,
 * which eBPF's sign-extended immediate cannot hold and goes through a
 * register instead. Measured against a 6.x kernel for every shape
 * (tests/fixtures/seccomp_threads.c holds the one-instruction case: 3641
 * filters before ENOMEM). */
static u32 ebpf_len(const GSockFilter *f, u32 len) {
    u32 n = 3;
    for (u32 pc = 0; pc < len; pc++) {
        u16 code = f[pc].code;
        switch (BPF_CLASS(code)) {
        case BPF_ALU:
            n += code == (BPF_ALU | BPF_DIV | BPF_X) ? 5 : 1;
            break;
        case BPF_JMP:
            if (BPF_OP(code) == BPF_JA) { n += 1; break; }
            if (BPF_SRC(code) == BPF_K && (s32)f[pc].k < 0) n += 1;
            if (f[pc].jf == 0) n += 1;
            else if (f[pc].jt == 0 && BPF_OP(code) != BPF_JSET) n += 1;
            else n += 2;
            break;
        case BPF_RET:
            n += (code & 0x18) == BPF_K ? 2 : 1;
            break;
        default:   /* LD, LDX, ST, STX, MISC: one each */
            n += 1;
            break;
        }
    }
    return n;
}

/* The chain budget: the new program's converted length plus, for every filter
 * already installed, its length and a four-instruction penalty, must fit in
 * MAX_INSNS_PER_PATH or the install is ENOMEM (seccomp_attach_filter). It
 * bounds what a guest can make every one of its syscalls run through -- and
 * what it can make the emulator malloc. Caller holds the task lock. */
#define MAX_INSNS_PER_PATH 32768
static int chain_has_room(struct Machine *m, u32 elen) {
    u64 total = elen;
    for (struct SeccompProg *w = chain_head(m); w; w = w->prev)
        total += (u64)w->elen + 4;
    return total <= MAX_INSNS_PER_PATH;
}

/* Run one validated program. Division by zero aborts the program with 0,
 * matching the kernel's interpreter (0 is SECCOMP_RET_KILL_THREAD -- severe,
 * but that is the kernel's answer to a broken filter too). */
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
            case BPF_AND: A &= v; break;
            case BPF_OR:  A |= v; break;
            case BPF_XOR: A ^= v; break;
            /* A shift by X of 32 or more is masked to five bits -- the eBPF
             * interpreter's `DST << (SRC & 31)` since the undefined-behaviour
             * fix, and what the x86/arm64 JITs' shift instructions do by
             * themselves. (A shift by K of 32 or more never loads: the classic
             * checker refuses it, above.) It used to end the program with 0,
             * a kill. */
            case BPF_LSH: A <<= (v & 31); break;
            case BPF_RSH: A >>= (v & 31); break;
            /* Classic BPF is unsigned 32-bit throughout, and the kernel's
             * NEG is the wraparound (its eBPF form is DST = (u32) -DST): the
             * negation of 0x80000000 is 0x80000000. Negating it as a signed
             * int is overflow -- undefined behaviour, which UBSan flags and a
             * compiler is free to act on -- for an answer the arithmetic has
             * to give anyway. */
            case BPF_NEG: A = 0u - A; break;
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
    for (struct SeccompProg *p = chain_head(m); p; p = p->prev) {
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
 * syscall must NOT run, with *ret holding what the guest sees; 2 when a SIGSYS
 * is owed as well, with *trap_data holding the filter's SECCOMP_RET_DATA for
 * si_errno; 0 to proceed. Killing actions do not return at all. */
int seccomp_gate(CPU *c, u64 nr, const u64 *args, s64 *ret, u16 *trap_data) {
    struct Machine *m = c->m;
    if (__atomic_load_n(&m->seccomp_mode, __ATOMIC_RELAXED) == G_SECCOMP_MODE_STRICT) {
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
         * the call. The filter's low 16 bits ride along in si_errno, which is
         * how one filter distinguishes several traps it installed. Delivery is
         * deferred to the dispatcher (return 2): the signal frame has to
         * capture the *result* in x0, and the handler's own arguments go into
         * x0..x2 after that -- doing it here would have both overwritten. */
        *ret = -ENOSYS;
        *trap_data = (u16)(action & G_SECCOMP_RET_DATA);
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
 * (seccomp_may_assign_mode). Caller holds the task lock: the check and the
 * mode store it guards are one step, as they are under the kernel's siglock. */
static int may_assign_mode(struct Machine *m, u8 mode) {
    u8 cur = __atomic_load_n(&m->seccomp_mode, __ATOMIC_RELAXED);
    return cur == 0 || cur == mode;
}

/* Enter a mode, publishing the chain first: a dispatcher that sees the mode
 * byte set and then loads the head must find the filter that set it there.
 * Caller holds the task lock. */
static void assign_mode(struct Machine *m, u8 mode) {
    __atomic_store_n(&m->seccomp_mode, mode, __ATOMIC_RELEASE);
}

/* /proc/<pid>/status Seccomp: / Seccomp_filters: (sys_procfs.c).
 *
 * The host file cannot answer this. A guest filter is never installed on the
 * host -- that is the whole point of evaluating it here -- so a filtered guest
 * reads 0 there; and where the emulator itself runs under a filter it never
 * asked for (Android, and `make test-seccomp`), an unfiltered guest reads 2.
 * Both directions are wrong, so the guest's numbers come from its own chain.
 *
 * Publishing to the shared registry on every install keeps the answer available
 * to another process reading /proc/<pid>/status, the way the id maps are. */
static int seccomp_status_locked(struct Machine *m, u32 *nfilters) {
    u32 n = 0;
    for (struct SeccompProg *p = chain_head(m); p; p = p->prev) n++;
    if (nfilters) *nfilters = n;
    return __atomic_load_n(&m->seccomp_mode, __ATOMIC_RELAXED);
}

/* Under the task lock, so the mode and the count are one install's pair. */
int seccomp_status(struct Machine *m, u32 *nfilters) {
    task_lock();
    int mode = seccomp_status_locked(m, nfilters);
    task_unlock();
    return mode;
}

/* Publishes are serialized by the lock like the installs they follow: two
 * racing installs could otherwise publish their counts in the other order,
 * and the registry would hold 1 after 2. Caller holds the task lock. */
static void seccomp_publish_locked(struct Machine *m) {
    u32 n = 0;
    u8 mode = (u8)seccomp_status_locked(m, &n);
    proctab_seccomp_set(mode, n);
}

void seccomp_publish(struct Machine *m) {
    task_lock();
    seccomp_publish_locked(m);
    task_unlock();
}

/* Install a filter: copy the program in, validate it, push it on the chain.
 *
 * The refusals come in the kernel's order (seccomp_set_mode_filter, then
 * seccomp_prepare_user_filter): the flags first, then the program header
 * (EFAULT), its length (EINVAL), the privilege check (EACCES), the
 * instructions (EFAULT) and their validity (EINVAL), and the mode last. The
 * order is observable, and observed: libseccomp asks whether a flag exists by
 * passing it with a NULL program and expecting EFAULT -- before it has set
 * no_new_privs -- so a check that put EACCES first told it that no flag
 * exists, TSYNC included, and seccomp_attr_set(SCMP_FLTATR_CTL_TSYNC) failed
 * with EOPNOTSUPP on every guest that was not fake root. */
static s64 seccomp_install(CPU *c, u64 flags, u64 prog_va) {
    struct Machine *m = c->m;
    /* TSYNC is implicit here (one filter chain per process); LOG and
     * SPEC_ALLOW are advisory; TSYNC_ESRCH only changes how a TSYNC failure
     * is reported, and TSYNC cannot fail here. NEW_LISTENER is not a flag this
     * kernel has: a user-notification fd would park guest syscalls on an
     * external agent, and a kernel without the feature -- any before 5.0 --
     * answers the flag as it answers every bit it does not know, which is what
     * libseccomp's probe wants to hear before it emits SECCOMP_RET_USER_NOTIF
     * (WAIT_KILLABLE_RECV, which needs a listener, is unknown for the same
     * reason). An unknown bit is EINVAL whatever it is combined with. */
    if (flags & ~(u64)(G_SECCOMP_FILTER_FLAG_TSYNC | G_SECCOMP_FILTER_FLAG_LOG |
                       G_SECCOMP_FILTER_FLAG_SPEC_ALLOW |
                       G_SECCOMP_FILTER_FLAG_TSYNC_ESRCH))
        return -EINVAL;

    GSockFprog fprog;
    if (copy_from_guest(c, &fprog, prog_va, sizeof fprog) < 0) return -EFAULT;
    u32 len = fprog.len;
    if (len == 0 || len > G_BPF_MAXINSNS) return -EINVAL;
    /* The kernel requires no_new_privs (or CAP_SYS_ADMIN) so a filtered
     * process cannot gain privilege through a setuid exec it can no longer
     * see. Our fake-root is that capability. */
    if (!m->no_new_privs && !fake_root(m)) return -EACCES;

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
    p->elen = ebpf_len(p->insns, len);
    /* The push: head read, node linked, head stored, all under the lock that
     * every other installer takes, so no two of them link to the same head;
     * the release store is what a lock-free reader's acquire load pairs with.
     * The mode check and the budget are judged under it too, against the
     * chain this push joins rather than one a sibling may still be growing. */
    task_lock();
    if (!may_assign_mode(m, G_SECCOMP_MODE_FILTER)) {
        task_unlock();
        free(p);
        return -EINVAL;
    }
    if (!chain_has_room(m, p->elen)) {
        task_unlock();
        free(p);
        return -ENOMEM;
    }
    p->prev = chain_head(m);
    __atomic_store_n((struct SeccompProg **)&m->seccomp_filters, p,
                     __ATOMIC_RELEASE);
    assign_mode(m, G_SECCOMP_MODE_FILTER);
    seccomp_publish_locked(m);
    task_unlock();
    return 0;
}

/* prctl(PR_SET_SECCOMP) -- the older way in, still what bubblewrap uses. */
/* Strict mode. Enforcement is local to this process, but the Seccomp: line
 * of its /proc/<pid>/status is read by OTHER processes, which can only see
 * what the shared registry says, so the transition is published like a
 * filter install is. */
static s64 seccomp_set_strict(struct Machine *m) {
    task_lock();
    if (!may_assign_mode(m, G_SECCOMP_MODE_STRICT)) {
        task_unlock();
        return -EINVAL;
    }
    assign_mode(m, G_SECCOMP_MODE_STRICT);
    seccomp_publish_locked(m);
    task_unlock();
    return 0;
}

s64 seccomp_prctl_set(CPU *c, u64 mode, u64 prog_va) {
    if (mode == G_SECCOMP_MODE_STRICT) return seccomp_set_strict(c->m);
    if (mode == G_SECCOMP_MODE_FILTER) return seccomp_install(c, 0, prog_va);
    return -EINVAL;
}

SYSDEF(seccomp) {
    (void)a3; (void)a4; (void)a5;
    switch (a0) {
    case G_SECCOMP_SET_MODE_STRICT:
        if (a1 != 0 || a2 != 0) return (u64)(s64)-EINVAL;
        return (u64)seccomp_set_strict(c->m);
    case G_SECCOMP_SET_MODE_FILTER:
        return (u64)seccomp_install(c, a1, a2);
    case G_SECCOMP_GET_ACTION_AVAIL: {
        /* "Is this action supported?" -- probed by libseccomp before it emits
         * a program using one. USER_NOTIF is the one this kernel has not got
         * (seccomp_install). The whole word is compared, as the kernel
         * compares it (seccomp_get_action_avail): an action with data bits
         * set is not an action it knows. */
        u32 act;
        if (a1 != 0) return (u64)(s64)-EINVAL;
        if (copy_from_guest(c, &act, a2, 4) < 0) return (u64)(s64)-EFAULT;
        switch (act) {
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
    /* GET_NOTIF_SIZES is the user-notification operation, which this kernel
     * does not have (seccomp_install): an operation it does not know is
     * EINVAL, like every other. */
    case G_SECCOMP_GET_NOTIF_SIZES:
    default:
        return (u64)(s64)-EINVAL;
    }
}
