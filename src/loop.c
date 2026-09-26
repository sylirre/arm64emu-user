/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* The interpreter run loop: step the CPU, dispatch pending exceptions
 * (recorded by exception.c) to the syscall layer or to signal delivery. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "machine.h"
#include "esr.h"
#include "guest_abi.h"
#include "predecode.h"
#include "jit.h"
#include "ptrace.h"
#include "sysreg.h"

/* Generic-timer count for CNTVCT_EL0/CNTPCT_EL0 reads (sysreg.c hook):
 * host monotonic clock scaled to the advertised 24 MHz counter frequency. */
u64 gt_count(CPU *c, bool virt) {
    (void)c; (void)virt;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    u64 ns = (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
    return ns * 3 / 125;   /* ns -> 24 MHz ticks */
}

/* EL0's view of the ID registers, as an arm64 kernel presents it. An MRS of
 * the op0 3, op1 0, CRn 0 space is UNDEFINED at EL0, and instead of the
 * SIGILL the kernel answers it itself (cpufeature.c, emulate_sys_reg): CRm 0
 * for MIDR_EL1 (the CPU's), MPIDR_EL1 (0x80000000, whatever the CPU) and
 * REVIDR_EL1 (0); CRm 2..7 for the feature registers, each field the kernel
 * shows userspace passed through and every other one read as its safe value
 * -- a CPU's EL2/EL3, its debug and memory-system details and its AArch32
 * support are nothing a program is told. The table is the kernel's
 * (FTR_VISIBLE fields; safe_val of each FTR_HIDDEN one) for every AArch64
 * register it tracks; an untracked slot reads 0, and so does an AArch32
 * register (CRm 2 and 3) of a CPU with no AArch32 at EL0, which the kernel
 * never reads. The rest of the space, CRm 1 included, stays SIGILL. */
static const struct { u8 crm, op2; u64 visible, hidden; } id_el0_view[] = {
    { 4, 0, 0x000f000f00ff0000ULL, 0x0000000000000011ULL },  /* ID_AA64PFR0: EL1, EL0 AArch64 only */
    { 4, 1, 0x0000f0000f000fffULL, 0 },                      /* ID_AA64PFR1 */
    { 4, 2, 0x0000000f00000ff0ULL, 0 },                      /* ID_AA64PFR2 */
    { 4, 4, 0x0fffff0f0ffff0ffULL, 0 },                      /* ID_AA64ZFR0 */
    { 4, 5, 0xbff1ffff73810001ULL, 0 },                      /* ID_AA64SMFR0 */
    { 4, 7, 0x00000000fc008003ULL, 0 },                      /* ID_AA64FPFR0 */
    { 5, 0, 0,                     0x0000000000000006ULL },  /* ID_AA64DFR0: DebugVer v8.0 */
    { 6, 0, 0xf0fffffff0fffff0ULL, 0 },                      /* ID_AA64ISAR0 */
    { 6, 1, 0xf0fff0ffffffffffULL, 0 },                      /* ID_AA64ISAR1 */
    { 6, 2, 0x0fff000000ffffffULL, 0 },                      /* ID_AA64ISAR2 */
    { 6, 3, 0x00000000f00f00f0ULL, 0 },                      /* ID_AA64ISAR3 */
    { 7, 0, 0xf000000000000000ULL, 0x00000111ff000000ULL },  /* ID_AA64MMFR0: TGran4/64 "none", TGran*_2 "as stage 1" */
    { 7, 1, 0x0000f00000000000ULL, 0 },                      /* ID_AA64MMFR1 */
    { 7, 2, 0x0000000f00000000ULL, 0 },                      /* ID_AA64MMFR2 */
    { 7, 3, 0x00000000000f0000ULL, 0 },                      /* ID_AA64MMFR3 */
};

/* do_el0_undef's try_emulate_mrs: whether the UNDEFINED instruction at pc is
 * such an MRS, answered (Rt written, pc past it) if so. */
static bool emulate_id_mrs(CPU *c) {
    u32 insn;
    if (!mem_ifetch(c, c->pc, &insn) || (insn & 0xfff00000u) != 0xd5300000u)
        return false;                                  /* not an MRS of op0 2/3 */
    unsigned op0 = 2 | ((insn >> 19) & 1), op1 = (insn >> 16) & 7;
    unsigned crn = (insn >> 12) & 15, crm = (insn >> 8) & 15, op2 = (insn >> 5) & 7;
    if (op0 != 3 || op1 != 0 || crn != 0 || crm == 1 || crm > 7) return false;
    u64 v = 0;
    if (crm == 0) {
        if (op2 == 0) v = sysreg_id_read(c, 0, 0);     /* MIDR_EL1 */
        else if (op2 == 5) v = 1ULL << 31;             /* MPIDR_EL1 */
        else if (op2 != 6) return false;               /* REVIDR_EL1 reads 0 */
    } else {
        for (size_t i = 0; i < sizeof id_el0_view / sizeof *id_el0_view; i++)
            if (id_el0_view[i].crm == crm && id_el0_view[i].op2 == op2) {
                v = (sysreg_id_read(c, crm, op2) & id_el0_view[i].visible) |
                    id_el0_view[i].hidden;
                break;
            }
    }
    set_x(c, insn & 31, v);
    c->pc += 4;
    return true;
}

/* Fatal guest fault with no guest handler (M1..M4): report, restore the host
 * default disposition and re-raise so the parent sees the real termination
 * status (guest handler delivery arrives in M5). */
void force_sig_fault(CPU *c, int sig, int code, u64 addr) {
    (void)code;
    /* Include the faulting instruction word when the PC is still fetchable
     * (always true for SIGILL/undefined, where it names the missing opcode).
     * mem_ifetch is non-faulting: it reports failure instead of aborting. */
    u32 insn = 0;
    if (mem_ifetch(c, c->pc, &insn))
        fprintf(stderr,
                "arm64chroot: guest fatal signal %d at pc=0x%llx addr=0x%llx insn=0x%08x\n",
                sig, (unsigned long long)c->pc, (unsigned long long)addr, insn);
    else
        fprintf(stderr,
                "arm64chroot: guest fatal signal %d at pc=0x%llx addr=0x%llx\n",
                sig, (unsigned long long)c->pc, (unsigned long long)addr);
    if (c->m->strace) cpu_dump(c);
    /* Report the WIFSIGNALED death to our tracer, drop the /proc slot, restore the
     * host default and re-raise so the real parent sees the status. Shared with
     * the async default-fatal delivery path (sig_deliver_pending). */
    guest_terminate_by_signal(c, sig);
}

/* Does the run loop have to act for this thread before any more guest code
 * runs: a signal to deliver, a tracer's kick to serve (ptrace_service_kick),
 * an execve's call-out to answer (stop_gen)? All three raise g_sig_npend, the
 * engines' way out of guest code; this is the question behind it. The
 * interpreter asks the flag before every instruction and cannot miss one. The
 * JIT asks a flag of its own at block entries -- the one the capture handler
 * raises beside g_sig_npend -- and clears it before each block it enters, so
 * one raised while the thread was out here, after the loop's delivery point
 * had looked, was gone by the time a block could see it: a thread spinning in
 * a block chained to itself went on spinning, its signal undelivered until
 * another arrived. jit_run asks this before entering a block.
 *
 * `at` is where a frame for the signal would say the thread was: none is
 * delivered on the rt_sigreturn trampoline (sig_deliver_pending), so a
 * signal is not due there, and the trampoline gets to run. */
int emu_callout_due(CPU *c, u64 at) {
    if (!g_sig_npend) return 0;
    return g_ptrace_kick ||
           __atomic_load_n(&c->m->stop_gen, __ATOMIC_ACQUIRE) != g_tls.stop_gen ||
           (!sig_on_trampoline(c->m, at) && sig_pending_deliverable(c->m));
}

int emu_loop(CPU *c) {
    for (;;) {
        if (UNLIKELY(c->stop)) return 0;
        /* Called out of guest code: an execve is dismantling this thread group,
         * or has already replaced the image this thread belongs to. One shared
         * load per iteration buys every thread a bounded response time, which
         * is what lets execve tear the address space down knowing nobody is
         * still walking it (guest_stop_point, sys_proc.c). */
        if (UNLIKELY(__atomic_load_n(&c->m->stop_gen, __ATOMIC_ACQUIRE) !=
                     g_tls.stop_gen)) {
            guest_stop_point(c);
            continue;   /* re-test c->stop, and the counter it just synced */
        }

        /* volatile: assigned inside the sigsetjmp bracket below, so a recovery
         * unwind must not leave it indeterminate. It stays 0 on that path,
         * which is right — an instruction that faulted did not single-step. */
        volatile int stepped = 0;
        /* Bus-error recovery bracket (mem.c). A file truncated from outside
         * this address space leaves PTEs pointing at host pages the kernel now
         * refuses; the handler records the guest abort and unwinds to here,
         * where the bus_setjmp returns nonzero and the engines are skipped so
         * the pending exception below is delivered. Cheap: once per run-loop
         * round trip, not per instruction, and savemask 0 keeps it a pure
         * register save (the handler unblocks SIGBUS itself before unwinding).
         * On arm32 Bionic bus_setjmp is our own save, not libc sigsetjmp,
         * which parks a mangled value in the live sp -- fatal under this
         * loop's async-signal traffic (mmu.h has the story). Deliberately
         * does NOT cover syscall dispatch further down: a handler may hold
         * locks that an unwind out to here would strand -- the syscall layer
         * brackets its own guest-memory touches instead (BUS_ARM_COPY). */
        if (bus_setjmp(&g_bus_jb) == 0) {
        as_bus_arm(c, BUS_ARM_ENGINE);
        if (UNLIKELY(g_debug_hooks)) {
            /* Full step: keeps every per-instruction debug facility
             * (trace/rtrace/prof/ring/cov/tpc) behaving exactly as before. */
            cpu_step(c);
        } else if (UNLIKELY(g_ptrace_singlestep)) {
            /* PTRACE_SINGLESTEP: exactly one instruction via the interpreter
             * (never a JIT/predecode chunk), then a SIGTRAP stop below. */
            cpu_step(c);
            stepped = 1;
        } else if (UNLIKELY(jit_on())) {
            /* -jit: run translated blocks; same return contract as pd_run. */
            jit_run(c);
        } else if (LIKELY(g_predecode)) {
            /* Threaded fast path: executes instructions back-to-back through
             * the decode cache, returning when this loop must intervene. */
            pd_run(c);
        } else {
            /* -nopd: single-step fast path — cpu_step minus the IRQ/FIQ-line
             * and halted checks (nothing drives the interrupt lines in
             * linux-user; halted is cleared below before the next step). */
            c->cur_insn_pc = c->pc;
            u32 insn;
            if (LIKELY(mem_ifetch(c, c->pc, &insn))) {
                c->pc += 4;
                exec_a64(c, insn);
                c->icount++;
            }
        }
        }
        as_bus_disarm();

        /* WFE/WFI at EL0: treat as yield. */
        if (UNLIKELY(c->halted)) c->halted = false;

        if (UNLIKELY(g_tls.pend_exc.valid)) {
            g_tls.pend_exc.valid = false;
            u64 esr = g_tls.pend_exc.esr;
            u64 far = g_tls.pend_exc.far;
            unsigned ec = (unsigned)(esr >> 26);
            switch (ec) {
                case EC_SVC64:
                    /* A signal that arrived while the engine was in guest code
                     * is delivered BEFORE the syscall runs, as a kernel delivers
                     * one that lands on a task in user mode: before its next
                     * instruction. The engines check the lever at their safe
                     * points -- every instruction for the interpreter, block
                     * entries for the JIT -- so one that landed after the last
                     * check and before the SVC is found here, with the syscall
                     * not yet dispatched. Dispatched first, a blocking syscall
                     * never came back: the host signal that carried the guest's
                     * had been consumed queuing it, and nothing was left to
                     * interrupt the wait -- glibc's setxid broadcast wedged a
                     * thread blocking on the setxid lock a few instructions
                     * after a sibling's SIGSETXID landed (tests/fixtures/
                     * sigsvc.c). So the SVC is stepped back over and left for
                     * after the handler: the frame is built at it, and the
                     * return re-executes it, exactly the kernel's order. Only
                     * for what WILL be delivered -- a blocked or ignored signal
                     * stays queued and the syscall proceeds -- and for the
                     * emulator's own call-outs, which need this thread at the
                     * loop boundary rather than in a wait: a tracer's kick
                     * (ptrace_service_kick) and execve's de_thread (stop_gen).
                     *
                     * A capture that lands after this check and before the
                     * host syscall is entered is the one neither this nor the
                     * EINTR can catch; the flag raised first is what makes
                     * such a capture arm the kick timer that will (signal.c,
                     * "the capture kick"). Raised before the check, so that a
                     * capture between the two is seen by the check or arms
                     * the timer -- never neither.
                     *
                     * A signal is not delivered at the rt_sigreturn
                     * trampoline's SVC: it waits for the context the sigreturn
                     * restores (sig_deliver_pending says why), and the frame
                     * built here would be at that SVC. */
                    g_sig_in_syscall = 1;
                    if (UNLIKELY(g_sig_npend) && emu_callout_due(c, c->pc - 4)) {
                        g_sig_in_syscall = 0;
                        c->pc -= 4;
                        break;
                    }
                    syscall_dispatch(c);
                    g_sig_in_syscall = 0;
                    break;
                case EC_DABORT_LOWER:
                case EC_DABORT_SAME: {
                    unsigned fsc = esr & 0x3f;
                    /* A synchronous external abort is how a file mapping
                     * reports a page past end-of-file: SIGBUS/BUS_ADRERR, not
                     * SIGSEGV (mem.c raise_dabort). */
                    if (fsc == FSC_EXTERNAL)
                        sig_deliver_fault(c, SIGBUS, 2 /*BUS_ADRERR*/, far);
                    else
                        sig_deliver_fault(c, SIGSEGV,
                                          (fsc >= FSC_PERM_L0 && fsc <= FSC_PERM_L3) ? 2 : 1,
                                          far);
                    break;
                }
                case EC_IABORT_LOWER:
                case EC_IABORT_SAME: {
                    /* As a data abort: a permission fault -- the page is
                     * mapped, just not executable -- is SEGV_ACCERR, and only
                     * a page with no mapping at all SEGV_MAPERR (the kernel's
                     * do_page_fault answers VM_FAULT_BADACCESS for the first). */
                    unsigned fsc = esr & 0x3f;
                    if (fsc == FSC_EXTERNAL)
                        sig_deliver_fault(c, SIGBUS, 2 /*BUS_ADRERR*/, far);
                    else
                        sig_deliver_fault(c, SIGSEGV,
                                          (fsc >= FSC_PERM_L0 && fsc <= FSC_PERM_L3) ? 2 : 1,
                                          far);
                    break;
                }
                case EC_PC_ALIGN:
                case EC_SP_ALIGN:
                    sig_deliver_fault(c, SIGBUS, 1, far);
                    break;
                case EC_BRK64:
                    sig_deliver_fault(c, SIGTRAP, 1, c->pc);
                    break;
                case EC_MOP: {
                    /* FEAT_MOPS main/epilogue state mismatch (wrong option, or
                     * an epilogue facing >= a page). Play the kernel's
                     * do_el0_mops: put the registers back in prologue input
                     * format (Arm ARM rules CNTMJ/MWFQH, mirroring Linux
                     * arm64_mops_reset_regs) and restart at the prologue —
                     * P/M/E are architecturally consecutive for this reason.
                     * c->pc still points at the trapping M/E instruction. */
                    bool wrong_option = (esr >> 17) & 1, option_a = (esr >> 16) & 1;
                    unsigned dreg = (esr >> 10) & 0x1f, sreg = (esr >> 5) & 0x1f;
                    unsigned nreg = esr & 0x1f;
                    u64 dst = reg_x(c, dreg), src = reg_x(c, sreg);
                    u64 size = reg_x(c, nreg);
                    if ((esr >> 24) & 1) {                             /* SET* */
                        if (option_a ^ wrong_option) {
                            dst += size; size = 0 - size;
                        }
                    } else {                                           /* CPY* */
                        if (!(option_a ^ wrong_option)) {
                            /* Format is from Option B; N set = backward */
                            if (c->nzcv & PS_N) { dst -= size; src -= size; }
                        } else if (size >> 63) {
                            /* Format is from Option A; negative = forward */
                            dst += size; src += size; size = 0 - size;
                        }
                    }
                    set_x(c, dreg, dst);
                    set_x(c, sreg, src);
                    set_x(c, nreg, size);
                    c->pc -= ((esr >> 18) & 1) ? 8 : 4;
                    break;
                }
                case EC_UNKNOWN:
                    if (emulate_id_mrs(c)) break;
                    sig_deliver_fault(c, SIGILL, 1, c->pc);
                    break;
                default:
                    sig_deliver_fault(c, SIGILL, 1, c->pc);
                    break;
            }
        }

        /* Adopt a pending PTRACE_ATTACH/SEIZE or service a PTRACE_INTERRUPT
         * (the kick signal set g_ptrace_kick and reused g_sig_npend to exit the
         * fast path above). Near-always-zero, like the signal check. Before
         * the signals, as the kernel's get_signal takes a ptrace trap before
         * it dequeues one: a tracer's ptrace(SEIZE) has returned by the time
         * its kill(2) sends the next signal, and a standard signal is taken
         * ahead of the real-time kick, so the two arrive together and the
         * signal must find the thread traced already. */
        /* The boundary has been reached: a kick timer armed inside a syscall
         * handler (by a capture, or by one of the emulator's own call-outs)
         * has done its job, or was never needed. Disarmed before anything is
         * serviced: a stop taken below parks the thread, and a timer still
         * firing through it re-flagged the call it had interrupted as ours
         * to restart -- after the stop had settled that it answers EINTR. */
        sig_kick_timer_disarm();

        /* Something is due, and the thread may be sitting at an SVC we
         * rewound (syscall_restart_internal), not yet dispatched again: that
         * call is still in progress to the guest, and what is due finds it
         * interrupted, as it would inside the host syscall (syscall.c). */
        if (UNLIKELY(g_sig_npend)) syscall_unrewind(c);

        if (UNLIKELY(g_ptrace_kick)) ptrace_service_kick(c);

        /* Deliver any host-caught guest signal at this safe boundary. */
        if (UNLIKELY(g_sig_npend)) sig_deliver_pending(c);

        /* Our own control signal interrupted a host syscall to get this thread
         * here (the attach kick above, a tracee's wake of its tracer, execve's
         * de_thread call-out). The kernel resumes a syscall it stops a task in;
         * so must we, or the guest sees a wait that ended early for no reason it
         * can observe. After the delivery above, so a guest signal's own
         * disposition -- frame, or SA_RESTART rewind -- decides first. */
        if (UNLIKELY(g_sig_selfintr)) syscall_restart_internal(c);

        /* PTRACE_SINGLESTEP: trap after exactly one stepped instruction. Gated
         * on `stepped` so arming single-step from within a stop (which resumes
         * mid-iteration) does not trap before an instruction has run. */
        if (UNLIKELY(stepped) && g_ptrace_singlestep && !c->stop)
            ptrace_report_singlestep(c);
    }
}
