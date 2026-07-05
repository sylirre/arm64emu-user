/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Operand pre-decode: a per-PC, per-thread cache of the decoded form of an
 * instruction — a dense opcode id plus pre-extracted operand fields — that
 * lets the run loop skip exec_a64's classification tree and field extraction
 * for hot instruction forms. Entries are a pure function of the instruction
 * word (PC-relative forms add c->cur_insn_pc at execute time), so comparing
 * the cached word against the freshly fetched one fully validates a hit: no
 * flush is needed for mmap/munmap/execve/self-modifying code.
 *
 * Anything the classifier does not recognize with certainty dispatches as
 * PD_GENERIC straight into exec_a64, which stays the source of truth. The
 * specialized handlers (predecode.c) are transcriptions of the corresponding
 * decode.c cases (which is copied from the system emulator and must not be
 * edited); the differential test suite checks their fidelity against qemu.
 *
 * Deliberately NOT a function-pointer table: the sibling emulator measured a
 * handler-pointer cache ~5-6% slower (indirect-call mispredicts + a large
 * table thrashing the data cache). Dense u8 opcode ids instead, dispatched by
 * direct-threaded computed goto (each handler fetches and dispatches its
 * successor, so every handler owns a branch-predictor slot). */
#ifndef A64_PREDECODE_H
#define A64_PREDECODE_H

#include "cpu.h"

/* Direct-mapped by (pc>>2), 16 B entries. Sized by measured miss rate on a
 * busybox-sh workload: 8 K entries missed 12.9%, 16 K 4.6%, 32 K 2.2%, 64 K
 * no better than 32 K. 16 K (256 KB/thread) is the size/benefit knee. */
#define PD_BITS 14
#define PD_SIZE (1u << PD_BITS)
#define PD_MASK (PD_SIZE - 1)

typedef struct {
    u32 insn;      /* validation tag: live word must match; 0 only for UDF #0 */
    u8  op;        /* dense opcode id, PD_GENERIC = 0 */
    u8  rd, rn, rm;/* raw 5-bit register fields (meaning varies per op) */
    u64 imm;       /* immediate/offset/mask/4th operand, pre-computed at fill */
} PDEnt;

extern __thread PDEnt g_pdcache[PD_SIZE];
extern int g_predecode;            /* cleared by -nopd (diagnostic mode) */

enum {
    PD_GENERIC = 0,   /* everything else: dispatch to exec_a64 */
    PD_NOP,           /* NOP/other hints, PRFM */

    /* branches */
    PD_B, PD_BL, PD_BCOND,
    PD_CBZ64, PD_CBZ32, PD_CBNZ64, PD_CBNZ32,
    PD_TBZ, PD_TBNZ,
    PD_BR, PD_BLR,    /* PD_BR also covers RET (identical semantics) */

    /* add/sub immediate (imm pre-shifted; SUBS imm stored pre-inverted) */
    PD_ADD64I, PD_ADD32I, PD_SUB64I, PD_SUB32I,
    PD_ADDS64I, PD_ADDS32I, PD_SUBS64I, PD_SUBS32I,

    /* logical immediate (imm = pre-decoded wmask) */
    PD_AND64I, PD_AND32I, PD_ORR64I, PD_ORR32I,
    PD_EOR64I, PD_EOR32I, PD_ANDS64I, PD_ANDS32I,

    /* move wide / PC-relative (values pre-computed) */
    PD_MOVI, PD_MOVK64, PD_MOVK32, PD_ADR, PD_ADRP,

    /* bitfield aliases (general UBFM/SBFM/BFM stay GENERIC) */
    PD_LSL64I, PD_LSL32I, PD_LSR64I, PD_LSR32I, PD_ASR64I, PD_ASR32I,
    PD_UBFX64, PD_UBFX32, PD_UBFIZ64, PD_UBFIZ32, PD_SBFX64, PD_SBFX32,
    PD_EXTR64, PD_EXTR32,

    /* logical shifted register, LSL #0 specialization */
    PD_AND64, PD_AND32, PD_BIC64, PD_BIC32,
    PD_ORR64, PD_ORR32, PD_ORN64, PD_ORN32,
    PD_EOR64, PD_EOR32, PD_EON64, PD_EON32,
    PD_ANDS64, PD_ANDS32, PD_BICS64, PD_BICS32,
    /* ... with a real shift (imm = N<<8 | type<<6 | amount) */
    PD_AND64S, PD_AND32S, PD_ORR64S, PD_ORR32S,
    PD_EOR64S, PD_EOR32S, PD_ANDS64S, PD_ANDS32S,

    /* add/sub shifted register, LSL #0 specialization */
    PD_ADD64R, PD_ADD32R, PD_SUB64R, PD_SUB32R,
    PD_ADDS64R, PD_ADDS32R, PD_SUBS64R, PD_SUBS32R,
    /* ... with a real shift (imm = type<<6 | amount) */
    PD_ADD64RS, PD_ADD32RS, PD_SUB64RS, PD_SUB32RS,
    PD_ADDS64RS, PD_ADDS32RS, PD_SUBS64RS, PD_SUBS32RS,
    /* add/sub extended register (imm = option<<3 | imm3) */
    PD_ADDX64, PD_ADDX32, PD_SUBX64, PD_SUBX32,
    PD_ADDSX64, PD_ADDSX32, PD_SUBSX64, PD_SUBSX32,

    /* 3-source (imm = Ra) */
    PD_MADD64, PD_MADD32, PD_MSUB64, PD_MSUB32,
    PD_SMADDL, PD_SMSUBL, PD_UMADDL, PD_UMSUBL, PD_SMULH, PD_UMULH,

    /* conditional select (imm = cond) */
    PD_CSEL64, PD_CSEL32, PD_CSINC64, PD_CSINC32,
    PD_CSINV64, PD_CSINV32, PD_CSNEG64, PD_CSNEG32,

    /* conditional compare (imm = cond | imm5<<8 | precomputed-flags<<32) */
    PD_CCMP64I, PD_CCMP32I, PD_CCMP64R, PD_CCMP32R,
    PD_CCMN64I, PD_CCMN32I, PD_CCMN64R, PD_CCMN32R,

    /* 1-source (hot subset) */
    PD_REV64, PD_REVW, PD_CLZ64, PD_CLZ32,

    /* 2-source */
    PD_UDIV64, PD_UDIV32, PD_SDIV64, PD_SDIV32,
    PD_LSLV64, PD_LSLV32, PD_LSRV64, PD_LSRV32,
    PD_ASRV64, PD_ASRV32, PD_RORV64, PD_RORV32,

    /* integer load/store, va = Xn|SP + imm (covers imm-uoff and LDUR/STUR) */
    PD_LDR64U, PD_LDR32U, PD_LDRB, PD_LDRH,
    PD_LDRSB64, PD_LDRSB32, PD_LDRSH64, PD_LDRSH32, PD_LDRSW,
    PD_STR64U, PD_STR32U, PD_STRB, PD_STRH,
    /* pre/post-indexed with writeback (imm = simm9) */
    PD_LDR64PRE, PD_LDR64POST, PD_LDR32PRE, PD_LDR32POST,
    PD_STR64PRE, PD_STR64POST, PD_STR32PRE, PD_STR32POST,
    PD_LDRBPOST, PD_STRBPOST,
    /* register offset (imm = option<<3 | shift) */
    PD_LDR64RO, PD_LDR32RO, PD_LDRBRO, PD_LDRHRO,
    PD_STR64RO, PD_STR32RO, PD_STRBRO, PD_STRHRO,
    /* literal */
    PD_LDRLIT64, PD_LDRLIT32,

    /* integer pairs (rm = Rt2, imm = scaled offset) */
    PD_LDP64, PD_LDP64PRE, PD_LDP64POST,
    PD_LDP32, PD_LDP32PRE, PD_LDP32POST,
    PD_STP64, PD_STP64PRE, PD_STP64POST,
    PD_STP32, PD_STP32PRE, PD_STP32POST,

    /* FP/SIMD register load/store (rd = Vt; PD_LDRV/STRV: rm = byte count) */
    PD_LDRQ, PD_STRQ, PD_LDRV, PD_STRV,
    PD_LDRQPRE, PD_LDRQPOST, PD_STRQPRE, PD_STRQPOST,
    /* FP/SIMD pairs (rm = Vt2, imm = scaled offset) */
    PD_LDPQ, PD_LDPQPRE, PD_LDPQPOST,
    PD_STPQ, PD_STPQPRE, PD_STPQPOST,
    PD_LDPD, PD_LDPDPRE, PD_LDPDPOST,
    PD_STPD, PD_STPDPRE, PD_STPDPOST,

    PD_NOPS_
};

/* Run instructions back-to-back through the decode cache (direct-threaded
 * dispatch). Returns when the loop must intervene: recorded exception,
 * pending signal, stop/halt, or an instruction-fetch fault. */
void pd_run(CPU *c);

#endif /* A64_PREDECODE_H */
