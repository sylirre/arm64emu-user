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

/* Generic-timer count for CNTVCT_EL0/CNTPCT_EL0 reads (sysreg.c hook):
 * host monotonic clock scaled to the advertised 24 MHz counter frequency. */
u64 gt_count(CPU *c, bool virt) {
    (void)c; (void)virt;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    u64 ns = (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
    return ns * 3 / 125;   /* ns -> 24 MHz ticks */
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

int emu_loop(CPU *c) {
    for (;;) {
        if (UNLIKELY(c->stop)) return 0;

        int stepped = 0;
        if (UNLIKELY(g_debug_hooks)) {
            /* Full step: keeps every per-instruction debug facility
             * (trace/rtrace/prof/ring/cov/tpc) behaving exactly as before. */
            cpu_step(c);
        } else if (UNLIKELY(g_ptrace_singlestep)) {
            /* PTRACE_SINGLESTEP: exactly one instruction via the interpreter
             * (never a JIT/predecode chunk), then a SIGTRAP stop below. */
            cpu_step(c);
            stepped = 1;
        } else if (UNLIKELY(g_jit)) {
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

        /* WFE/WFI at EL0: treat as yield. */
        if (UNLIKELY(c->halted)) c->halted = false;

        if (UNLIKELY(g_tls.pend_exc.valid)) {
            g_tls.pend_exc.valid = false;
            u64 esr = g_tls.pend_exc.esr;
            u64 far = g_tls.pend_exc.far;
            unsigned ec = (unsigned)(esr >> 26);
            switch (ec) {
                case EC_SVC64:
                    syscall_dispatch(c);
                    break;
                case EC_DABORT_LOWER:
                case EC_DABORT_SAME: {
                    unsigned fsc = esr & 0x3f;
                    sig_deliver_fault(c, SIGSEGV,
                                      (fsc >= FSC_PERM_L0 && fsc <= FSC_PERM_L3) ? 2 : 1,
                                      far);
                    break;
                }
                case EC_IABORT_LOWER:
                case EC_IABORT_SAME:
                    sig_deliver_fault(c, SIGSEGV, 1, far);
                    break;
                case EC_PC_ALIGN:
                case EC_SP_ALIGN:
                    sig_deliver_fault(c, SIGBUS, 1, far);
                    break;
                case EC_BRK64:
                    sig_deliver_fault(c, SIGTRAP, 1, c->pc);
                    break;
                case EC_UNKNOWN:
                default:
                    sig_deliver_fault(c, SIGILL, 1, c->pc);
                    break;
            }
        }

        /* Deliver any host-caught guest signal at this safe boundary. */
        if (UNLIKELY(g_sig_npend)) sig_deliver_pending(c);

        /* Adopt a pending PTRACE_ATTACH/SEIZE or service a PTRACE_INTERRUPT
         * (the kick signal set g_ptrace_kick and reused g_sig_npend to exit the
         * fast path above). Near-always-zero, like the signal check. */
        if (UNLIKELY(g_ptrace_kick)) ptrace_service_kick(c);

        /* PTRACE_SINGLESTEP: trap after exactly one stepped instruction. Gated
         * on `stepped` so arming single-step from within a stop (which resumes
         * mid-iteration) does not trap before an instruction has run. */
        if (UNLIKELY(stepped) && g_ptrace_singlestep && !c->stop)
            ptrace_report_singlestep(c);
    }
}
