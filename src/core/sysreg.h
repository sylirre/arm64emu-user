/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* System register / SMCCC hooks. sysreg_exec/sysreg_init are implemented in
 * sysreg.c (M2). smccc_conduit's provider (M3, psci.c) was never added, so it
 * stays weak and is called only under a NULL-check. */
#ifndef A64_SYSREG_H
#define A64_SYSREG_H

#include "cpu.h"

/* Execute a System-instruction-group encoding (MSR/MRS/SYS/MSR-imm). */
void sysreg_exec(CPU *c, u32 insn);

/* Initialise ID/feature registers at reset. */
void sysreg_init(CPU *c);

/* The ID register op0 3, op1 0, CRn 0, CRm, op2 as EL1 reads it: what this CPU
 * implements, before a kernel sanitizes EL0's view of it. */
u64 sysreg_id_read(CPU *c, unsigned CRm, unsigned op2);

/* Handle an SMC/HVC conduit call (PSCI / SMCCC). Returns true if handled. */
bool smccc_conduit(CPU *c, bool is_hvc) __attribute__((weak));

#endif /* A64_SYSREG_H */
