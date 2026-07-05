/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Linux-user exception seam. The copied core calls exception_take() /
 * cpu_raise_sync() exactly as in the system emulator, but here nothing ever
 * vectors to EL1: the exception is recorded and the run loop (loop.c)
 * dispatches it — SVC to the syscall layer, aborts/undef/BRK to guest signal
 * delivery. The CPU stays at EL0 for the lifetime of the process. */
#include "machine.h"

u32 cpu_pack_spsr(CPU *c) {
    u32 s = c->nzcv & (PS_N | PS_Z | PS_C | PS_V);
    s |= c->daif & (PS_D | PS_A | PS_I | PS_F);
    s |= ((u32)c->el << 2) | (c->sp_sel ? 1u : 0u);
    return s;
}

void cpu_unpack_spsr(CPU *c, u32 spsr) {
    c->nzcv = spsr & (PS_N | PS_Z | PS_C | PS_V);
    c->daif = spsr & (PS_D | PS_A | PS_I | PS_F);
    unsigned m = spsr & 0xf;
    c->el = (m >> 2) & 3;
    c->sp_sel = m & 1u;
}

__thread ThreadState g_tls;

void exception_take(CPU *c, ExcKind kind, u64 esr, u64 far, u64 ret_addr) {
    (void)kind;
    g_tls.pend_exc.valid = true;
    g_tls.pend_exc.esr = esr;
    g_tls.pend_exc.far = far;
    /* SVC passes the next-instruction address (continue there after the
     * syscall); faults pass the faulting instruction (Linux re-executes it if
     * a handler repairs the situation). */
    c->pc = ret_addr;
    c->excl_valid = false;
}

void cpu_raise_sync(CPU *c, u64 esr, u64 far) {
    exception_take(c, EXC_SYNC, esr, far, c->cur_insn_pc);
}
