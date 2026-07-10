/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* IR frontend: basic-block discovery and PDEnt -> IR translation. This file
 * is a transcription of the predecode handler semantics (predecode.c) into
 * IR; the differential suite is the fidelity check. Everything guest-shaped
 * is resolved here — XZR vs SP encodings of register 31, 32-bit truncation,
 * pre-decoded immediates (SUBS immediates arrive pre-inverted, logical
 * immediates as wmasks), shifted/extended operand decomposition, and PC
 * folding for ADR/ADRP/branches — so the backends see only simple ops.
 *
 * Anything not translated natively falls back to IRO_CALL1 (exec_a64), the
 * same fallback ladder the interpreter itself uses for PD_GENERIC. */
#include <stdlib.h>

#include "machine.h"
#include "predecode.h"
#include "ir.h"

enum { FE_CONT, FE_END };

/* Debug bisection knob: A64_JIT_PDMAX=N translates only PD ops <= N
 * natively (branches always native); everything else goes through the
 * exec_a64 helper. Used to localize a codegen bug to one handler class. */
static int fe_pdmax(void) {
    static int v = -2;
    if (v == -2) {
        const char *s = getenv("A64_JIT_PDMAX");
        v = s ? atoi(s) : -1;
    }
    return v;
}
static int fe_gated(u8 op) {
    int m = fe_pdmax();
    if (m < 0) return 0;
    if (op >= PD_B && op <= PD_BLR) return 0;   /* keep control flow native */
    return op > m;
}

static IROp *ir_put(IRBlock *ir, u8 op, u8 w, u8 dst, u8 a, u8 b, u8 cc,
                    u64 imm, u32 aux) {
    IROp *o = &ir->ops[ir->n++];
    o->op = op;
    o->w = w;
    o->dst = dst;
    o->a = a;
    o->b = b;
    o->cc = cc;
    o->imm = imm;
    o->aux = aux;
    o->flags_dead = 0;
    o->icnt = ir->ninsns;
    return o;
}

/* Register-31 resolution (which helper predecode.c used for each operand). */
static u8 rx(unsigned r)  { return r == 31 ? VREG_ZERO : (u8)r; }  /* reg_x  */
static u8 rsp(unsigned r) { return (u8)r; }                        /* reg_xsp */

/* Common 3-operand emit where a write to XZR without flags is dead. */
static void put_alu(IRBlock *ir, u8 op, u8 w, u8 dst, u8 a, u8 b) {
    if (dst == VREG_ZERO) {
        switch (op) {                       /* only flag-setters have effect */
            case IRO_ADDS: case IRO_SUBS: case IRO_ANDS: case IRO_BICS:
                break;
            default:
                return;
        }
    }
    ir_put(ir, op, w, dst, a, b, 0, 0, 0);
}

static void put_alui(IRBlock *ir, u8 op, u8 w, u8 dst, u8 a, u64 imm) {
    if (dst == VREG_ZERO) {
        switch (op) {
            case IRO_ADDIS: case IRO_SUBIS: case IRO_ANDIS:
                break;
            default:
                return;
        }
    }
    ir_put(ir, op, w, dst, a, 0, 0, imm, 0);
}

/* Decompose a shifted-register operand (pd_shift_reg) into TMP0.
 * type: 0 LSL, 1 LSR, 2 ASR, 3 ROR; amount already masked per width. */
static u8 fe_shifted(IRBlock *ir, unsigned rm, unsigned type, unsigned amt,
                     u8 w) {
    static const u8 ops[4] = { IRO_LSLI, IRO_LSRI, IRO_ASRI, IRO_RORI };
    u8 m = rx(rm);
    if (m == VREG_ZERO) {
        ir_put(ir, IRO_MOVI, 1, VREG_TMP0, 0, 0, 0, 0, 0);
        return VREG_TMP0;
    }
    if (amt == 0) return m;                 /* LSL #0 etc: pass through */
    ir_put(ir, ops[type], w, VREG_TMP0, m, 0, 0, amt & (w ? 63 : 31), 0);
    return VREG_TMP0;
}

/* Decompose an extended-register operand (pd_extend_reg) into TMP0. */
static u8 fe_extended(IRBlock *ir, unsigned rm, unsigned option,
                      unsigned shift) {
    u8 m = rx(rm);
    u8 t = VREG_TMP0;
    unsigned bits = 8u << (option & 3);
    if (m == VREG_ZERO) {
        ir_put(ir, IRO_MOVI, 1, t, 0, 0, 0, 0, 0);
        return t;
    }
    if (option & 4) {                       /* signed: sext via shift pair */
        if (bits == 64) {
            if (!shift) return m;
            ir_put(ir, IRO_MOV, 1, t, m, 0, 0, 0, 0);
        } else {
            ir_put(ir, IRO_LSLI, 1, t, m, 0, 0, 64 - bits, 0);
            ir_put(ir, IRO_ASRI, 1, t, t, 0, 0, 64 - bits, 0);
        }
    } else {
        if (bits == 64) {
            if (!shift) return m;
            ir_put(ir, IRO_MOV, 1, t, m, 0, 0, 0, 0);
        } else if (bits == 32) {
            ir_put(ir, IRO_MOV, 0, t, m, 0, 0, 0, 0);   /* zext32 */
        } else {
            ir_put(ir, IRO_ANDI, 1, t, m, 0, 0, (1ULL << bits) - 1, 0);
        }
    }
    if (shift) ir_put(ir, IRO_LSLI, 1, t, t, 0, 0, shift, 0);
    return t;
}

static void put_call1(IRBlock *ir, u64 pc, u32 insn) {
    ir_put(ir, IRO_CALL1, 0, 0, 0, 0, 0, pc, insn);
}

/* ---- memory ops ----
 * Address = base(SP-form) + off. dst/val use rx() (reg 31 -> XZR). Loads
 * commit to c->x[rt]; a writeback is a separate IRO_ADDI emitted AFTER the
 * access so a fault (which exits the block) leaves the base unchanged, and a
 * pre-index base-clobbers-rt case resolves rt-then-base like the interpreter.
 * desc packs rt/size/sign/width (MDESC_*); the backend reads it from o->aux. */
static void put_ld(IRBlock *ir, u8 base, s64 off, unsigned rt, unsigned szlog,
                   int sign, int is64, u64 pc) {
    IROp *o = ir_put(ir, IRO_LD, (u8)is64, (u8)(rt == 31 ? VREG_ZERO : rt),
                     base, 0, (u8)szlog, (u64)off,
                     MDESC_MAKE(rt & 31, szlog, sign, is64));
    o->imm2pc = pc;
}
static void put_st(IRBlock *ir, u8 base, s64 off, u8 val, unsigned szlog,
                   u64 pc) {
    IROp *o = ir_put(ir, IRO_ST, 0, 0, base, val, (u8)szlog, (u64)off,
                     MDESC_MAKE(0, szlog, 0, 0));
    o->imm2pc = pc;
}
/* vszl = byte-count log2: 0=1B,1=2B,2=4B,3=8B(D),4=16B(Q). */
static void put_ldv(IRBlock *ir, u8 base, s64 off, unsigned rt, unsigned vszl,
                    u64 pc) {
    IROp *o = ir_put(ir, IRO_LDV, 0, 0, base, 0, (u8)vszl, (u64)off,
                     MDESC_MAKEV(rt, vszl));
    o->imm2pc = pc;
}
static void put_stv(IRBlock *ir, u8 base, s64 off, unsigned rt, unsigned vszl,
                    u64 pc) {
    IROp *o = ir_put(ir, IRO_STV, 0, 0, base, 0, (u8)vszl, (u64)off,
                     MDESC_MAKEV(rt, vszl));
    o->imm2pc = pc;
}
static void put_wb(IRBlock *ir, unsigned rn, s64 imm) {   /* base += imm */
    ir_put(ir, IRO_ADDI, 1, (u8)rn, (u8)rn, 0, 0, (u64)imm, 0);
}
/* Load into IR temp k (dst = VREG_TMP0+k, home = env->tmp_spill[k]): LDP's
 * halves, committed to the guest registers only after both succeed. */
static void put_ld_tmp(IRBlock *ir, u8 base, s64 off, unsigned k,
                       unsigned szlog, int is64, u64 pc) {
    IROp *o = ir_put(ir, IRO_LD, (u8)is64, (u8)(VREG_TMP0 + k), base, 0,
                     (u8)szlog, (u64)off,
                     MDESC_MAKE(k, szlog, 0, is64) | MDESC_TMPBIT);
    o->imm2pc = pc;
}

/* Inline vector / scalar-FP ALU (exec_fpsimd is the reference; the
 * interpreter computes FP in host C float/double, so host FP ops match it
 * bit-for-bit on the same host). Emits one IRO_VOP and returns 1 for
 * whitelisted encodings the host backend accepts (be_vop_ok); 0 = keep the
 * helper. Counted in ninsns (fully native, no faults). */

/* VFPExpandImm / AdvSIMDExpandImm — transcribed from exec_fpsimd.c (spec
 * pseudocode; both must stay in sync with the interpreter's copies). */
static u32 fe_vfp_imm32(unsigned imm8) {
    /* sign:imm8<7>  exp8 = NOT(b6):Rep(b6,5):imm8<5:4>  frac = imm8<3:0> */
    u32 s = (imm8 >> 7) & 1, b6 = (imm8 >> 6) & 1, e = (imm8 >> 4) & 3;
    u32 exp8 = ((!b6) << 7) | ((b6 ? 0x1fu : 0) << 2) | e;
    return (s << 31) | (exp8 << 23) | ((u32)(imm8 & 0xf) << 19);
}
static u64 fe_vfp_imm64(unsigned imm8) {
    u64 s = (imm8 >> 7) & 1, b6 = (imm8 >> 6) & 1, e = (imm8 >> 4) & 3;
    u64 exp11 = ((u64)(!b6) << 10) | ((u64)(b6 ? 0xffu : 0) << 2) | e;
    return (s << 63) | (exp11 << 52) | ((u64)(imm8 & 0xf) << 48);
}
static u64 fe_rep8(u64 b)  { b &= 0xff;       return b * 0x0101010101010101ULL; }
static u64 fe_rep16(u64 h) { h &= 0xffff;     return h * 0x0001000100010001ULL; }
static u64 fe_rep32(u64 w) { w &= 0xffffffff; return w | (w << 32); }
static u64 fe_expand_imm(unsigned op, unsigned cmode, unsigned imm8) {
    unsigned hi = (cmode >> 1) & 7, lo = cmode & 1;
    switch (hi) {
        case 0: return fe_rep32(imm8);
        case 1: return fe_rep32((u64)imm8 << 8);
        case 2: return fe_rep32((u64)imm8 << 16);
        case 3: return fe_rep32((u64)imm8 << 24);
        case 4: return fe_rep16(imm8);
        case 5: return fe_rep16((u64)imm8 << 8);
        case 6: return lo ? fe_rep32(((u64)imm8 << 16) | 0xffff)
                          : fe_rep32(((u64)imm8 << 8) | 0xff);
        default:
            if (lo == 0 && op == 0) return fe_rep8(imm8);
            if (lo == 0 && op == 1) {
                u64 v = 0;
                for (int i = 0; i < 8; i++)
                    if ((imm8 >> i) & 1) v |= 0xffULL << (i * 8);
                return v;
            }
            if (lo == 1 && op == 0) return fe_rep32(fe_vfp_imm32(imm8));
            return fe_vfp_imm64(imm8);
    }
}

static int fe_fpsimd(IRBlock *ir, u32 insn, u64 pc) {
    (void)pc;
    unsigned rd = insn & 31, rn = (insn >> 5) & 31;
    u32 vclass = ~0u;
    u8 gdst = VREG_ZERO, gsrc = VREG_ZERO;   /* guest GPRs involved */
    u32 aux_extra = 0;

    if ((insn & 0x9F200400u) == 0x0E200400u) {
        /* vector three-same (bit31=0, 28:24=01110, 21=1, 10=1) */
        unsigned U = (insn >> 29) & 1;
        unsigned opc = (insn >> 11) & 0x1f;
        if (opc == 0x03) vclass = VC_BITW;
        else if (opc == 0x10) vclass = VC_ADDSUB;
        else if ((opc == 0x11 && U) || opc == 0x06 || opc == 0x07)
            vclass = VC_CM3;
    } else if ((insn & 0x9FF80400u) == 0x0F000400u) {
        /* modified immediate (28:19 = 0111100000, bit10=1) */
        unsigned Q = (insn >> 30) & 1, op = (insn >> 29) & 1;
        unsigned cmode = (insn >> 12) & 0xf;
        unsigned imm8 = (((insn >> 16) & 7) << 5) | ((insn >> 5) & 31);
        unsigned hi = (cmode >> 1) & 7, lo = cmode & 1;
        int orr_bic = (lo == 1) && (hi <= 5);
        u64 v;
        unsigned kind;
        if (orr_bic) {
            v = fe_expand_imm(0, cmode, imm8);
            kind = op ? 2 : 1;                   /* BIC : ORR */
        } else {
            v = fe_expand_imm(op, cmode, imm8);
            if (op == 1 && hi != 7) v = ~v;
            kind = 0;                            /* plain write */
        }
        if (!be_vop_ok(VC_MOVI, insn)) return 0;
        IROp *o = ir_put(ir, IRO_VOP, 0, VREG_ZERO, VREG_ZERO, VREG_ZERO, 0,
                         v, VMOVI_MAKE(rd, Q, kind));
        o->imm2pc = v;                           /* both lanes = v */
        ir->ninsns++;
        return 1;
    } else if ((insn & 0x9F800400u) == 0x0F000400u &&
               ((insn >> 19) & 0xf) != 0) {
        /* shift immediate (28:23 = 011110, bit10 = 1, immh != 0) */
        unsigned U = (insn >> 29) & 1, opc = (insn >> 11) & 0x1f;
        if ((opc == 0x0a && !U) || opc == 0x00) vclass = VC_SHIFTI;
    } else if ((insn & 0x9FE08400u) == 0x0E000400u) {
        /* AdvSIMD copy (28:21 = 01110000, bit15 = 0, bit10 = 1); the
         * interpreter's simd_copy semantics are mirrored exactly, including
         * its permissive treatment of reserved imm5/Q combinations. */
        unsigned op = (insn >> 29) & 1;
        unsigned imm4 = (insn >> 11) & 0xf;
        if (op == 1) {                           /* INS (element) */
            vclass = VC_COPY;
        } else if (imm4 == 0x0) {                /* DUP (element) */
            vclass = VC_COPY;
        } else if (imm4 == 0x1 || imm4 == 0x3) { /* DUP/INS (general) */
            vclass = VC_COPY;
            gsrc = rx(rn);
        } else if (imm4 == 0x5 || imm4 == 0x7) { /* SMOV / UMOV */
            vclass = VC_COPY;
            gdst = rx(rd);
        }
    } else if ((insn & 0x7F000000u) == 0x1E000000u) {
        /* scalar FP */
        unsigned ftype = (insn >> 22) & 3, o2 = (insn >> 10) & 3;
        if (((insn >> 24) & 0x1f) == 0x1e && ((insn >> 21) & 1) == 1 &&
            ((insn >> 10) & 0x3f) == 0) {
            /* FP<->integer: only the FMOV bit-move forms */
            unsigned sf = insn >> 31, rmode = (insn >> 19) & 3;
            unsigned opcode = (insn >> 16) & 7;
            if (sf == 1 && ftype == 2 && rmode == 1 &&
                (opcode == 6 || opcode == 7)) {  /* FMOV Xd,Vn.D[1] / inverse */
                vclass = VC_FMOVG;
                if (opcode == 6) gdst = rx(rd); else gsrc = rx(rn);
            } else if (rmode == 0 && (opcode == 6 || opcode == 7) &&
                       ((ftype == 0 && sf == 0) || (ftype == 1 && sf == 1))) {
                vclass = VC_FMOVG;
                if (opcode == 6) gdst = rx(rd); else gsrc = rx(rn);
            }
        } else if ((ftype == 0 || ftype == 1) && ((insn >> 21) & 1) == 1) {
            if (o2 == 0 && ((insn >> 12) & 1) == 1) {        /* FMOV #imm */
                unsigned imm8 = (insn >> 13) & 0xff;
                if (!be_vop_ok(VC_FMOVI, insn)) return 0;
                IROp *o = ir_put(ir, IRO_VOP, 0, VREG_ZERO, VREG_ZERO,
                                 VREG_ZERO, 0,
                                 ftype ? fe_vfp_imm64(imm8)
                                       : (u64)fe_vfp_imm32(imm8),
                                 VC_FMOVI | ((u32)rd << 8));
                o->imm2pc = 0;
                ir->ninsns++;
                return 1;
            }
            if (o2 == 0 && ((insn >> 13) & 1) == 1 &&
                ((insn >> 12) & 1) == 0) {                   /* FCMP/FCMPE */
                vclass = VC_FCMP;
                aux_extra = VF_SETF;
            } else if (o2 == 0 && ((insn >> 14) & 1) == 1) { /* 1-source */
                unsigned opc = (insn >> 15) & 0x3f;
                if (opc <= 0x3) vclass = VC_F1;  /* FMOV/FABS/FNEG/FSQRT */
            } else if (o2 == 2) {                            /* 2-source */
                unsigned opc = (insn >> 12) & 0xf;
                if (opc <= 0x3 || opc == 0x8) vclass = VC_F2; /* +FNMUL */
            } else if (o2 == 3) {                            /* FCSEL */
                vclass = VC_FCSEL;
                aux_extra = VF_READF;
            }
        }
    }

    if (vclass == ~0u || !be_vop_ok(vclass, insn)) return 0;
    ir_put(ir, IRO_VOP, 0, gdst, gsrc, VREG_ZERO, 0, (u64)insn,
           vclass | aux_extra);
    ir->ninsns++;
    return 1;
}

/* Inline exclusives / LSE atomics / ordered accesses (decode.c
 * ldst_exclusive and ldst_atomic are the reference; predecode classifies
 * them all PD_GENERIC). Emits one IRO_ATOMIC and returns 1 when the word is
 * a form the backends inline; 0 = caller falls back to the helper. These
 * are NOT counted in ninsns — the fast path bumps icount itself and the
 * slow path re-runs the insn through the self-counting jit_exec1. */
static int fe_atomic(IRBlock *ir, u32 insn, u64 pc) {
    unsigned rt = insn & 31, rn = (insn >> 5) & 31, rs = (insn >> 16) & 31;
    IROp *o = NULL;

    if ((insn & 0x3F000000u) == 0x08000000u) {   /* exclusives group */
        unsigned szl = insn >> 30;               /* 00..11 = 1..8B */
        int o2 = (insn >> 23) & 1, L = (insn >> 22) & 1, o1 = (insn >> 21) & 1;
        int o0 = (insn >> 15) & 1;
        if (o2 && o1) {                          /* CAS/CASA/CASL/CASAL */
            o = ir_put(ir, IRO_ATOMIC, 1, rx(rs), rsp(rn), rx(rt),
                       rx(rs), (u64)insn,
                       AT_MAKE(AT_CAS, szl, (insn >> 22) & 1, o0));
        } else if (o2 && !o1) {                  /* LDAR/LDLAR / STLR/STLLR */
            if (L) o = ir_put(ir, IRO_ATOMIC, 1, rx(rt), rsp(rn), VREG_ZERO,
                              VREG_ZERO, (u64)insn, AT_MAKE(AT_LDAR, szl, 1, 0));
            else   o = ir_put(ir, IRO_ATOMIC, 1, VREG_ZERO, rsp(rn), rx(rt),
                              VREG_ZERO, (u64)insn, AT_MAKE(AT_STLR, szl, 0, 1));
        } else if (!o2 && !o1) {                 /* LDXR/LDAXR / STXR/STLXR */
            if (L) o = ir_put(ir, IRO_ATOMIC, 1, rx(rt), rsp(rn), VREG_ZERO,
                              VREG_ZERO, (u64)insn, AT_MAKE(AT_LDX, szl, o0, 0));
            else   o = ir_put(ir, IRO_ATOMIC, 1, rx(rs), rsp(rn), rx(rt),
                              VREG_ZERO, (u64)insn, AT_MAKE(AT_STX, szl, 0, o0));
        }
        /* LDXP/STXP/CASP: helper (128-bit / pair monitor; rare) */
    } else if ((insn & 0x3B200C00u) == 0x38200000u) {   /* LSE atomic memops */
        unsigned szl = insn >> 30;
        int A = (insn >> 23) & 1, R = (insn >> 22) & 1;
        int o3 = (insn >> 15) & 1;
        unsigned opc = (insn >> 12) & 7;
        if (o3 && opc == 0)                      /* SWP */
            o = ir_put(ir, IRO_ATOMIC, 1, rx(rt), rsp(rn), rx(rs), VREG_ZERO,
                       (u64)insn, AT_MAKE(AT_SWP, szl, A, R));
        else if (o3 && opc == 4 && rs == 31)     /* LDAPR */
            o = ir_put(ir, IRO_ATOMIC, 1, rx(rt), rsp(rn), VREG_ZERO,
                       VREG_ZERO, (u64)insn, AT_MAKE(AT_LDAR, szl, 1, 0));
        else if (!o3 && opc < 4)                 /* LDADD/LDCLR/LDEOR/LDSET */
            o = ir_put(ir, IRO_ATOMIC, 1, rx(rt), rsp(rn), rx(rs), VREG_ZERO,
                       (u64)insn, AT_MAKE(AT_LDADD + opc, szl, A, R));
        /* LDSMAX..LDUMIN (opc 4-7): helper */
    }
    if (!o) return 0;
    o->imm2pc = pc;
    return 1;
}

/* Translate one classified instruction. Emits IR; returns FE_END when the
 * block must stop after it (all terminal ops emitted). */
static int fe_insn(IRBlock *ir, const PDEnt *e, u64 pc) {
    const u32 insn = e->insn;
    const u64 next = pc + 4;
    u8 w = 0;

    switch (e->op) {
        case PD_NOP:
            return FE_CONT;                 /* hints/PRFM: no effect */

        /* ---- branches (terminal) ---- */
        case PD_B:
            ir->ninsns++;
            ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, pc + e->imm, 0);
            return FE_END;
        case PD_BL:
            ir->ninsns++;
            ir_put(ir, IRO_MOVI, 1, 30, 0, 0, 0, next, 0);
            ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, pc + e->imm, 0);
            return FE_END;
        case PD_BCOND:
            ir->ninsns++;
            if ((e->rd & 0xe) == 0xe) {     /* AL/NV: unconditional */
                ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, pc + e->imm, 0);
            } else {
                ir_put(ir, IRO_BCOND, 0, 0, 0, 0, e->rd, pc + e->imm, 0);
                ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, next, 0);
            }
            return FE_END;
        case PD_CBZ64: case PD_CBZ32: case PD_CBNZ64: case PD_CBNZ32: {
            ir->ninsns++;
            int nz = (e->op == PD_CBNZ64 || e->op == PD_CBNZ32);
            w = (e->op == PD_CBZ64 || e->op == PD_CBNZ64);
            u8 t = rx(e->rd);
            if (t == VREG_ZERO) {           /* always zero */
                ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0,
                       nz ? next : pc + e->imm, 0);
            } else {
                ir_put(ir, nz ? IRO_CBNZ : IRO_CBZ, w, 0, t, 0, 0,
                       pc + e->imm, 0);
                ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, next, 0);
            }
            return FE_END;
        }
        case PD_TBZ: case PD_TBNZ: {
            ir->ninsns++;
            int nz = (e->op == PD_TBNZ);
            u8 t = rx(e->rd);
            if (t == VREG_ZERO) {
                ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0,
                       nz ? next : pc + e->imm, 0);
            } else {
                ir_put(ir, nz ? IRO_TBNZ : IRO_TBZ, 1, 0, t, 0, e->rm,
                       pc + e->imm, 0);
                ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, next, 0);
            }
            return FE_END;
        }
        case PD_BR: {                       /* BR / RET */
            ir->ninsns++;
            u8 t = rx(e->rn);
            if (t == VREG_ZERO) {
                ir_put(ir, IRO_MOVI, 1, VREG_TMP0, 0, 0, 0, 0, 0);
                t = VREG_TMP0;
            }
            ir_put(ir, IRO_JMPIND, 0, 0, t, 0, 0, 0, 0);
            return FE_END;
        }
        case PD_BLR: {
            ir->ninsns++;
            u8 t = rx(e->rn);               /* read target before writing x30 */
            ir_put(ir, t == VREG_ZERO ? IRO_MOVI : IRO_MOV, 1, VREG_TMP0,
                   t == VREG_ZERO ? 0 : t, 0, 0, 0, 0);
            ir_put(ir, IRO_MOVI, 1, 30, 0, 0, 0, next, 0);
            ir_put(ir, IRO_JMPIND, 0, 0, VREG_TMP0, 0, 0, 0, 0);
            return FE_END;
        }

        /* ---- add/sub immediate (rn/rd use SP; S-forms write XZR-style) ---- */
        case PD_ADD64I: case PD_ADD32I:
            w = (e->op == PD_ADD64I);
            put_alui(ir, IRO_ADDI, w, rsp(e->rd), rsp(e->rn), e->imm);
            break;
        case PD_SUB64I: case PD_SUB32I:
            w = (e->op == PD_SUB64I);
            put_alui(ir, IRO_SUBI, w, rsp(e->rd), rsp(e->rn), e->imm);
            break;
        case PD_ADDS64I: case PD_ADDS32I:
            w = (e->op == PD_ADDS64I);
            put_alui(ir, IRO_ADDIS, w, rx(e->rd), rsp(e->rn), e->imm);
            break;
        case PD_SUBS64I: case PD_SUBS32I:
            /* PDEnt stores ~imm for pd_awc; recover the real immediate. */
            w = (e->op == PD_SUBS64I);
            put_alui(ir, IRO_SUBIS, w, rx(e->rd), rsp(e->rn), ~e->imm);
            break;

        /* ---- logical immediate (imm = wmask; rd uses SP except ANDS) ---- */
        case PD_AND64I: case PD_AND32I:
            w = (e->op == PD_AND64I);
            put_alui(ir, IRO_ANDI, w, rsp(e->rd), rx(e->rn), e->imm);
            break;
        case PD_ORR64I: case PD_ORR32I:
            w = (e->op == PD_ORR64I);
            put_alui(ir, IRO_ORRI, w, rsp(e->rd), rx(e->rn), e->imm);
            break;
        case PD_EOR64I: case PD_EOR32I:
            w = (e->op == PD_EOR64I);
            put_alui(ir, IRO_EORI, w, rsp(e->rd), rx(e->rn), e->imm);
            break;
        case PD_ANDS64I: case PD_ANDS32I:
            w = (e->op == PD_ANDS64I);
            put_alui(ir, IRO_ANDIS, w, rx(e->rd), rx(e->rn), e->imm);
            break;

        /* ---- move wide / PC-relative ---- */
        case PD_MOVI:
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_MOVI, 1, e->rd, 0, 0, 0, e->imm, 0);
            break;
        case PD_MOVK64: case PD_MOVK32:
            w = (e->op == PD_MOVK64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_MOVK, w, e->rd, e->rd, 0, e->rm, e->imm, 0);
            break;
        case PD_ADR:
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_MOVI, 1, e->rd, 0, 0, 0, pc + e->imm, 0);
            break;
        case PD_ADRP:
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_MOVI, 1, e->rd, 0, 0, 0,
                       (pc & ~0xfffULL) + e->imm, 0);
            break;

        /* ---- bitfield aliases ---- */
        case PD_LSL64I: case PD_LSL32I:
            w = (e->op == PD_LSL64I);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_LSLI, w, e->rd, rx(e->rn), 0, 0, e->rm, 0);
            break;
        case PD_LSR64I: case PD_LSR32I:
            w = (e->op == PD_LSR64I);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_LSRI, w, e->rd, rx(e->rn), 0, 0, e->rm, 0);
            break;
        case PD_ASR64I: case PD_ASR32I:
            w = (e->op == PD_ASR64I);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_ASRI, w, e->rd, rx(e->rn), 0, 0, e->rm, 0);
            break;
        case PD_UBFX64: case PD_UBFX32:     /* (rn >> rm) & imm */
            w = (e->op == PD_UBFX64);
            if (rx(e->rd) != VREG_ZERO) {
                /* 64-bit ops: handlers use full-width >> and mask (the mask
                 * already truncates for the 32-bit form) */
                ir_put(ir, IRO_LSRI, 1, VREG_TMP0, rx(e->rn), 0, 0, e->rm, 0);
                ir_put(ir, IRO_ANDI, 1, e->rd, VREG_TMP0, 0, 0, e->imm, 0);
            }
            break;
        case PD_UBFIZ64: case PD_UBFIZ32:   /* (rn & imm) << rm */
            w = (e->op == PD_UBFIZ64);
            if (rx(e->rd) != VREG_ZERO) {
                ir_put(ir, IRO_ANDI, 1, VREG_TMP0, rx(e->rn), 0, 0, e->imm, 0);
                ir_put(ir, IRO_LSLI, w, e->rd, VREG_TMP0, 0, 0, e->rm, 0);
            }
            break;
        case PD_SBFX64: case PD_SBFX32:     /* (rn << rm) asr imm, per width */
            w = (e->op == PD_SBFX64);
            if (rx(e->rd) != VREG_ZERO) {
                ir_put(ir, IRO_LSLI, w, VREG_TMP0, rx(e->rn), 0, 0, e->rm, 0);
                ir_put(ir, IRO_ASRI, w, e->rd, VREG_TMP0, 0, 0,
                       (unsigned)e->imm, 0);
            }
            break;
        case PD_EXTR64: case PD_EXTR32:
            w = (e->op == PD_EXTR64);
            if (rx(e->rd) != VREG_ZERO) {
                if (e->imm == 0) {
                    ir_put(ir, IRO_MOV, w, e->rd, rx(e->rm), 0, 0, 0, 0);
                } else {
                    ir_put(ir, IRO_EXTR, w, e->rd, rx(e->rn), rx(e->rm), 0,
                           e->imm, 0);
                }
            }
            break;

        /* ---- logical register, LSL #0 ---- */
        case PD_AND64:  case PD_AND32:
            w = (e->op == PD_AND64);
            put_alu(ir, IRO_AND, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_BIC64:  case PD_BIC32:
            w = (e->op == PD_BIC64);
            put_alu(ir, IRO_BIC, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_ORR64:  case PD_ORR32:
            w = (e->op == PD_ORR64);
            put_alu(ir, IRO_ORR, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_ORN64:  case PD_ORN32:
            w = (e->op == PD_ORN64);
            put_alu(ir, IRO_ORN, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_EOR64:  case PD_EOR32:
            w = (e->op == PD_EOR64);
            put_alu(ir, IRO_EOR, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_EON64:  case PD_EON32:
            w = (e->op == PD_EON64);
            put_alu(ir, IRO_EON, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_ANDS64: case PD_ANDS32:
            w = (e->op == PD_ANDS64);
            put_alu(ir, IRO_ANDS, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_BICS64: case PD_BICS32:
            w = (e->op == PD_BICS64);
            put_alu(ir, IRO_BICS, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;

        /* ---- logical register with shift (imm = N<<8|type<<6|amt) ---- */
        case PD_AND64S: case PD_AND32S: case PD_ORR64S: case PD_ORR32S:
        case PD_EOR64S: case PD_EOR32S: case PD_ANDS64S: case PD_ANDS32S: {
            w = (e->op == PD_AND64S || e->op == PD_ORR64S ||
                 e->op == PD_EOR64S || e->op == PD_ANDS64S);
            int inv = (e->imm >> 8) & 1;
            u8 m = fe_shifted(ir, e->rm, (unsigned)(e->imm >> 6) & 3,
                              (unsigned)e->imm & 63, w);
            u8 op;
            switch (e->op) {
                case PD_AND64S: case PD_AND32S:
                    op = inv ? IRO_BIC : IRO_AND; break;
                case PD_ORR64S: case PD_ORR32S:
                    op = inv ? IRO_ORN : IRO_ORR; break;
                case PD_EOR64S: case PD_EOR32S:
                    op = inv ? IRO_EON : IRO_EOR; break;
                default:
                    op = inv ? IRO_BICS : IRO_ANDS; break;
            }
            put_alu(ir, op, w, rx(e->rd), rx(e->rn), m);
            break;
        }

        /* ---- add/sub register, LSL #0 ---- */
        case PD_ADD64R:  case PD_ADD32R:
            w = (e->op == PD_ADD64R);
            put_alu(ir, IRO_ADD, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_SUB64R:  case PD_SUB32R:
            w = (e->op == PD_SUB64R);
            put_alu(ir, IRO_SUB, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_ADDS64R: case PD_ADDS32R:
            w = (e->op == PD_ADDS64R);
            put_alu(ir, IRO_ADDS, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;
        case PD_SUBS64R: case PD_SUBS32R:
            w = (e->op == PD_SUBS64R);
            put_alu(ir, IRO_SUBS, w, rx(e->rd), rx(e->rn), rx(e->rm));
            break;

        /* ---- add/sub register with shift (imm = type<<6|amt) ---- */
        case PD_ADD64RS:  case PD_ADD32RS: case PD_SUB64RS:  case PD_SUB32RS:
        case PD_ADDS64RS: case PD_ADDS32RS:
        case PD_SUBS64RS: case PD_SUBS32RS: {
            w = (e->op == PD_ADD64RS || e->op == PD_SUB64RS ||
                 e->op == PD_ADDS64RS || e->op == PD_SUBS64RS);
            int sub = (e->op == PD_SUB64RS || e->op == PD_SUB32RS ||
                       e->op == PD_SUBS64RS || e->op == PD_SUBS32RS);
            int S = (e->op == PD_ADDS64RS || e->op == PD_ADDS32RS ||
                     e->op == PD_SUBS64RS || e->op == PD_SUBS32RS);
            u8 m = fe_shifted(ir, e->rm, (unsigned)(e->imm >> 6) & 3,
                              (unsigned)e->imm & 63, w);
            put_alu(ir, sub ? (S ? IRO_SUBS : IRO_SUB)
                            : (S ? IRO_ADDS : IRO_ADD),
                    w, rx(e->rd), rx(e->rn), m);
            break;
        }

        /* ---- add/sub extended (imm = option<<3|imm3; rn uses SP; rd uses
         * SP unless S) ---- */
        case PD_ADDX64:  case PD_ADDX32: case PD_SUBX64:  case PD_SUBX32:
        case PD_ADDSX64: case PD_ADDSX32:
        case PD_SUBSX64: case PD_SUBSX32: {
            w = (e->op == PD_ADDX64 || e->op == PD_SUBX64 ||
                 e->op == PD_ADDSX64 || e->op == PD_SUBSX64);
            int sub = (e->op == PD_SUBX64 || e->op == PD_SUBX32 ||
                       e->op == PD_SUBSX64 || e->op == PD_SUBSX32);
            int S = (e->op == PD_ADDSX64 || e->op == PD_ADDSX32 ||
                     e->op == PD_SUBSX64 || e->op == PD_SUBSX32);
            u8 m = fe_extended(ir, e->rm, (unsigned)(e->imm >> 3) & 7,
                               (unsigned)e->imm & 7);
            u8 dst = S ? rx(e->rd) : rsp(e->rd);
            put_alu(ir, sub ? (S ? IRO_SUBS : IRO_SUB)
                            : (S ? IRO_ADDS : IRO_ADD),
                    w, dst, rsp(e->rn), m);
            break;
        }

        /* ---- 3-source (imm = Ra) ---- */
        case PD_MADD64: case PD_MADD32:
            w = (e->op == PD_MADD64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_MADD, w, e->rd, rx(e->rn), rx(e->rm),
                       rx((unsigned)e->imm), 0, 0);
            break;
        case PD_MSUB64: case PD_MSUB32:
            w = (e->op == PD_MSUB64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_MSUB, w, e->rd, rx(e->rn), rx(e->rm),
                       rx((unsigned)e->imm), 0, 0);
            break;
        case PD_SMADDL: case PD_SMSUBL: case PD_UMADDL: case PD_UMSUBL: {
            static const u8 map[4] = { IRO_SMADDL, IRO_SMSUBL,
                                       IRO_UMADDL, IRO_UMSUBL };
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, map[e->op - PD_SMADDL], 1, e->rd, rx(e->rn),
                       rx(e->rm), rx((unsigned)e->imm), 0, 0);
            break;
        }
        case PD_SMULH: case PD_UMULH:
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, e->op == PD_SMULH ? IRO_SMULH : IRO_UMULH, 1,
                       e->rd, rx(e->rn), rx(e->rm), 0, 0, 0);
            break;

        /* ---- conditional select (imm = cond) ---- */
        case PD_CSEL64:  case PD_CSEL32:
        case PD_CSINC64: case PD_CSINC32:
        case PD_CSINV64: case PD_CSINV32:
        case PD_CSNEG64: case PD_CSNEG32: {
            w = (e->op == PD_CSEL64 || e->op == PD_CSINC64 ||
                 e->op == PD_CSINV64 || e->op == PD_CSNEG64);
            u8 op = (e->op == PD_CSEL64 || e->op == PD_CSEL32) ? IRO_CSEL
                  : (e->op == PD_CSINC64 || e->op == PD_CSINC32) ? IRO_CSINC
                  : (e->op == PD_CSINV64 || e->op == PD_CSINV32) ? IRO_CSINV
                  : IRO_CSNEG;
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, op, w, e->rd, rx(e->rn), rx(e->rm),
                       (u8)e->imm, 0, 0);
            break;
        }

        /* ---- conditional compare (imm = cond|imm5<<8|flags<<32) ---- */
        case PD_CCMP64I: case PD_CCMP32I: case PD_CCMN64I: case PD_CCMN32I: {
            w = (e->op == PD_CCMP64I || e->op == PD_CCMN64I);
            int cmn = (e->op == PD_CCMN64I || e->op == PD_CCMN32I);
            ir_put(ir, cmn ? IRO_CCMNI : IRO_CCMPI, w, 0, rx(e->rn), 0,
                   (u8)(e->imm & 15), (e->imm >> 8) & 31,
                   (u32)(e->imm >> 32));
            break;
        }
        case PD_CCMP64R: case PD_CCMP32R: case PD_CCMN64R: case PD_CCMN32R: {
            w = (e->op == PD_CCMP64R || e->op == PD_CCMN64R);
            int cmn = (e->op == PD_CCMN64R || e->op == PD_CCMN32R);
            ir_put(ir, cmn ? IRO_CCMNR : IRO_CCMPR, w, 0, rx(e->rn),
                   rx(e->rm), (u8)(e->imm & 15), 0, (u32)(e->imm >> 32));
            break;
        }

        /* ---- 1-source / 2-source ---- */
        case PD_REV64:
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_REV64, 1, e->rd, rx(e->rn), 0, 0, 0, 0);
            break;
        case PD_REVW:
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_REV32, 0, e->rd, rx(e->rn), 0, 0, 0, 0);
            break;
        case PD_CLZ64: case PD_CLZ32:
            w = (e->op == PD_CLZ64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_CLZ, w, e->rd, rx(e->rn), 0, 0, 0, 0);
            break;
        case PD_UDIV64: case PD_UDIV32:
            w = (e->op == PD_UDIV64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_UDIV, w, e->rd, rx(e->rn), rx(e->rm), 0, 0, 0);
            break;
        case PD_SDIV64: case PD_SDIV32:
            w = (e->op == PD_SDIV64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_SDIV, w, e->rd, rx(e->rn), rx(e->rm), 0, 0, 0);
            break;
        case PD_LSLV64: case PD_LSLV32:
            w = (e->op == PD_LSLV64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_LSLV, w, e->rd, rx(e->rn), rx(e->rm), 0, 0, 0);
            break;
        case PD_LSRV64: case PD_LSRV32:
            w = (e->op == PD_LSRV64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_LSRV, w, e->rd, rx(e->rn), rx(e->rm), 0, 0, 0);
            break;
        case PD_ASRV64: case PD_ASRV32:
            w = (e->op == PD_ASRV64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_ASRV, w, e->rd, rx(e->rn), rx(e->rm), 0, 0, 0);
            break;
        case PD_RORV64: case PD_RORV32:
            w = (e->op == PD_RORV64);
            if (rx(e->rd) != VREG_ZERO)
                ir_put(ir, IRO_RORV, w, e->rd, rx(e->rn), rx(e->rm), 0, 0, 0);
            break;

        /* ---- integer loads/stores, va = base(SP) + imm ---- */
        case PD_LDR64U:  put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 3, 0, 1, pc); break;
        case PD_LDR32U:  put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 2, 0, 0, pc); break;
        case PD_LDRB:    put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 0, 0, 1, pc); break;
        case PD_LDRH:    put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 1, 0, 1, pc); break;
        case PD_LDRSB64: put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 0, 1, 1, pc); break;
        case PD_LDRSB32: put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 0, 1, 0, pc); break;
        case PD_LDRSH64: put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 1, 1, 1, pc); break;
        case PD_LDRSH32: put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 1, 1, 0, pc); break;
        case PD_LDRSW:   put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 2, 1, 1, pc); break;
        case PD_STR64U:  put_st(ir, rsp(e->rn), (s64)e->imm, rx(e->rd), 3, pc); break;
        case PD_STR32U:  put_st(ir, rsp(e->rn), (s64)e->imm, rx(e->rd), 2, pc); break;
        case PD_STRB:    put_st(ir, rsp(e->rn), (s64)e->imm, rx(e->rd), 0, pc); break;
        case PD_STRH:    put_st(ir, rsp(e->rn), (s64)e->imm, rx(e->rd), 1, pc); break;

        /* pre/post-indexed (imm = simm9); writeback after the access */
        case PD_LDR64PRE:  put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 3, 0, 1, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_LDR64POST: put_ld(ir, rsp(e->rn), 0,          e->rd, 3, 0, 1, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_LDR32PRE:  put_ld(ir, rsp(e->rn), (s64)e->imm, e->rd, 2, 0, 0, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_LDR32POST: put_ld(ir, rsp(e->rn), 0,          e->rd, 2, 0, 0, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STR64PRE:  put_st(ir, rsp(e->rn), (s64)e->imm, rx(e->rd), 3, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STR64POST: put_st(ir, rsp(e->rn), 0,          rx(e->rd), 3, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STR32PRE:  put_st(ir, rsp(e->rn), (s64)e->imm, rx(e->rd), 2, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STR32POST: put_st(ir, rsp(e->rn), 0,          rx(e->rd), 2, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_LDRBPOST:  put_ld(ir, rsp(e->rn), 0,          e->rd, 0, 0, 1, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STRBPOST:  put_st(ir, rsp(e->rn), 0,          rx(e->rd), 0, pc); put_wb(ir, e->rn, (s64)e->imm); break;

        /* register offset (imm = option<<3 | shift): va = base + extend(rm) */
        case PD_LDR64RO: case PD_LDR32RO: case PD_LDRBRO: case PD_LDRHRO:
        case PD_STR64RO: case PD_STR32RO: case PD_STRBRO: case PD_STRHRO: {
            u8 idx = fe_extended(ir, e->rm, (unsigned)(e->imm >> 3) & 7,
                                 (unsigned)e->imm & 7);
            ir_put(ir, IRO_ADD, 1, VREG_TMP1, rsp(e->rn), idx, 0, 0, 0);
            switch (e->op) {
                case PD_LDR64RO: put_ld(ir, VREG_TMP1, 0, e->rd, 3, 0, 1, pc); break;
                case PD_LDR32RO: put_ld(ir, VREG_TMP1, 0, e->rd, 2, 0, 0, pc); break;
                case PD_LDRBRO:  put_ld(ir, VREG_TMP1, 0, e->rd, 0, 0, 1, pc); break;
                case PD_LDRHRO:  put_ld(ir, VREG_TMP1, 0, e->rd, 1, 0, 1, pc); break;
                case PD_STR64RO: put_st(ir, VREG_TMP1, 0, rx(e->rd), 3, pc); break;
                case PD_STR32RO: put_st(ir, VREG_TMP1, 0, rx(e->rd), 2, pc); break;
                case PD_STRBRO:  put_st(ir, VREG_TMP1, 0, rx(e->rd), 0, pc); break;
                default:         put_st(ir, VREG_TMP1, 0, rx(e->rd), 1, pc); break;
            }
            break;
        }

        /* literal: va = cur_insn_pc + imm (constant) */
        case PD_LDRLIT64:
            ir_put(ir, IRO_MOVI, 1, VREG_TMP0, 0, 0, 0, pc + e->imm, 0);
            put_ld(ir, VREG_TMP0, 0, e->rd, 3, 0, 1, pc);
            break;
        case PD_LDRLIT32:
            ir_put(ir, IRO_MOVI, 1, VREG_TMP0, 0, 0, 0, pc + e->imm, 0);
            put_ld(ir, VREG_TMP0, 0, e->rd, 2, 0, 0, pc);
            break;

        /* integer STP (rm = Rt2, imm = scaled offset): two stores + writeback. */
        case PD_STP64: case PD_STP64PRE: case PD_STP64POST:
        case PD_STP32: case PD_STP32PRE: case PD_STP32POST: {
            int is64 = (e->op == PD_STP64 || e->op == PD_STP64PRE || e->op == PD_STP64POST);
            int post = (e->op == PD_STP64POST || e->op == PD_STP32POST);
            int wb = post || e->op == PD_STP64PRE || e->op == PD_STP32PRE;
            unsigned szl = is64 ? 3 : 2, esz = is64 ? 8 : 4;
            s64 a0 = post ? 0 : (s64)e->imm;
            put_st(ir, rsp(e->rn), a0,            rx(e->rd), szl, pc);
            put_st(ir, rsp(e->rn), a0 + (s64)esz, rx(e->rm), szl, pc);
            if (wb) put_wb(ir, e->rn, (s64)e->imm);
            break;
        }

        /* Integer LDP: both register writes land only after BOTH reads
         * succeed (predecode.c L_LDP64 is all-or-nothing), so read into IR
         * temps and commit with MOVs. The address is computed once into TMP2
         * up front, which also resolves the rd==rn / rm==rn hazards. */
        case PD_LDP64: case PD_LDP64PRE: case PD_LDP64POST:
        case PD_LDP32: case PD_LDP32PRE: case PD_LDP32POST: {
            int is64 = (e->op == PD_LDP64 || e->op == PD_LDP64PRE || e->op == PD_LDP64POST);
            int post = (e->op == PD_LDP64POST || e->op == PD_LDP32POST);
            int wb = post || e->op == PD_LDP64PRE || e->op == PD_LDP32PRE;
            unsigned szl = is64 ? 3 : 2, esz = is64 ? 8 : 4;
            s64 a0 = post ? 0 : (s64)e->imm;
            if (a0) ir_put(ir, IRO_ADDI, 1, VREG_TMP2, rsp(e->rn), 0, 0, (u64)a0, 0);
            else    ir_put(ir, IRO_MOV,  1, VREG_TMP2, rsp(e->rn), 0, 0, 0, 0);
            put_ld_tmp(ir, VREG_TMP2, 0,        0, szl, is64, pc);
            put_ld_tmp(ir, VREG_TMP2, (s64)esz, 1, szl, is64, pc);
            if (e->rd != 31) ir_put(ir, IRO_MOV, (u8)is64, e->rd, VREG_TMP0, 0, 0, 0, 0);
            if (e->rm != 31) ir_put(ir, IRO_MOV, (u8)is64, e->rm, VREG_TMP1, 0, 0, 0, 0);
            if (wb) ir_put(ir, IRO_ADDI, 1, rsp(e->rn), VREG_TMP2, 0, 0,
                           post ? e->imm : 0, 0);
            break;
        }

        /* ---- FP/SIMD single loads/stores (rd = Vt) ---- */
        /* PD_LDRV/PD_STRV: e->rm = byte count (1/2/4/8) -> log2 = ctz. */
        case PD_LDRQ:  put_ldv(ir, rsp(e->rn), (s64)e->imm, e->rd, 4, pc); break;
        case PD_STRQ:  put_stv(ir, rsp(e->rn), (s64)e->imm, e->rd, 4, pc); break;
        case PD_LDRV:  put_ldv(ir, rsp(e->rn), (s64)e->imm, e->rd, (unsigned)__builtin_ctz(e->rm), pc); break;
        case PD_STRV:  put_stv(ir, rsp(e->rn), (s64)e->imm, e->rd, (unsigned)__builtin_ctz(e->rm), pc); break;
        case PD_LDRQPRE:  put_ldv(ir, rsp(e->rn), (s64)e->imm, e->rd, 4, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_LDRQPOST: put_ldv(ir, rsp(e->rn), 0,          e->rd, 4, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STRQPRE:  put_stv(ir, rsp(e->rn), (s64)e->imm, e->rd, 4, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STRQPOST: put_stv(ir, rsp(e->rn), 0,          e->rd, 4, pc); put_wb(ir, e->rn, (s64)e->imm); break;

        /* FP/SIMD pairs commit each element on success -> two element ops. */
        case PD_LDPQ: case PD_LDPQPRE: case PD_LDPQPOST: {
            int post = (e->op == PD_LDPQPOST);
            int wb = post || e->op == PD_LDPQPRE;
            s64 a0 = post ? 0 : (s64)e->imm;
            put_ldv(ir, rsp(e->rn), a0,      e->rd, 4, pc);
            put_ldv(ir, rsp(e->rn), a0 + 16, e->rm, 4, pc);
            if (wb) put_wb(ir, e->rn, (s64)e->imm);
            break;
        }
        case PD_STPQ: case PD_STPQPRE: case PD_STPQPOST: {
            int post = (e->op == PD_STPQPOST);
            int wb = post || e->op == PD_STPQPRE;
            s64 a0 = post ? 0 : (s64)e->imm;
            put_stv(ir, rsp(e->rn), a0,      e->rd, 4, pc);
            put_stv(ir, rsp(e->rn), a0 + 16, e->rm, 4, pc);
            if (wb) put_wb(ir, e->rn, (s64)e->imm);
            break;
        }
        case PD_LDPD: case PD_LDPDPRE: case PD_LDPDPOST: {
            int post = (e->op == PD_LDPDPOST);
            int wb = post || e->op == PD_LDPDPRE;
            s64 a0 = post ? 0 : (s64)e->imm;
            put_ldv(ir, rsp(e->rn), a0,     e->rd, 3, pc);
            put_ldv(ir, rsp(e->rn), a0 + 8, e->rm, 3, pc);
            if (wb) put_wb(ir, e->rn, (s64)e->imm);
            break;
        }
        case PD_STPD: case PD_STPDPRE: case PD_STPDPOST: {
            int post = (e->op == PD_STPDPOST);
            int wb = post || e->op == PD_STPDPRE;
            s64 a0 = post ? 0 : (s64)e->imm;
            put_stv(ir, rsp(e->rn), a0,     e->rd, 3, pc);
            put_stv(ir, rsp(e->rn), a0 + 8, e->rm, 3, pc);
            if (wb) put_wb(ir, e->rn, (s64)e->imm);
            break;
        }

        /* ---- everything else (FP/SIMD arith, system, rare atomics):
         * interpreter helper ---- */
        default: {
            if (e->op == PD_GENERIC && fe_atomic(ir, insn, pc))
                return FE_CONT;      /* inline atomic (not in ninsns) */
            if (e->op == PD_GENERIC && fe_fpsimd(ir, insn, pc))
                return FE_CONT;      /* inline vector/FP (counted inside) */
            if (e->op == PD_GENERIC && (insn >> 24) == 0xD5) {
                /* System family: hints, barriers, sysreg moves, cache ops —
                 * none can branch (IC IVAU is intercepted before pd_fill),
                 * and jit_exec1's return catches faults/halt anyway, so the
                 * block keeps going. The hot TLS/barrier cases are inline. */
                unsigned rt = insn & 31;
                if ((insn & 0xFFFFFFE0u) == 0xD53BD040u) {   /* MRS Xt, TPIDR_EL0 */
                    if (rt != 31)
                        ir_put(ir, IRO_CPULD, 1, (u8)rt, VREG_ZERO, 0, 0,
                               offsetof(CPU, tpidr), 0);     /* tpidr[0] */
                    break;
                }
                if ((insn & 0xFFFFFFE0u) == 0xD53BD060u) {   /* MRS Xt, TPIDRRO_EL0 */
                    if (rt != 31)
                        ir_put(ir, IRO_CPULD, 1, (u8)rt, VREG_ZERO, 0, 0,
                               offsetof(CPU, tpidrro_el0), 0);
                    break;
                }
                if ((insn & 0xFFFFFFE0u) == 0xD51BD040u) {   /* MSR TPIDR_EL0, Xt */
                    ir_put(ir, IRO_CPUST, 1, VREG_ZERO, rx(rt), 0, 0,
                           offsetof(CPU, tpidr), 0);
                    break;
                }
                if ((insn & 0xFFFFF0FFu) == 0xD50330BFu ||   /* DMB */
                    (insn & 0xFFFFF0FFu) == 0xD503309Fu) {   /* DSB */
                    ir_put(ir, IRO_FENCE, 0, VREG_ZERO, VREG_ZERO, 0, 0, 0, 0);
                    break;
                }
                if ((insn & 0xFFFFF0FFu) == 0xD50330DFu)     /* ISB */
                    break;              /* context sync: nothing to do here */
                put_call1(ir, pc, insn);
                return FE_CONT;
            }
            put_call1(ir, pc, insn);         /* jit_exec1 counts this insn */
            if (e->op == PD_GENERIC) {
                unsigned grp = (insn >> 25) & 0xf;
                if (grp == 0xa || grp == 0xb) {
                    /* branch/exception group: possible control transfer;
                     * end the block, fall through to the sequential
                     * successor when the helper didn't branch. */
                    ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, next, 0);
                    return FE_END;
                }
            }
            return FE_CONT;
        }
    }
    ir->ninsns++;
    return FE_CONT;
}

/* ---- liveness / dead-flag pass ---- */

static int op_reads_flags(const IROp *o) {
    switch (o->op) {
        case IRO_CSEL: case IRO_CSINC: case IRO_CSINV: case IRO_CSNEG:
        case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI:
        case IRO_BCOND:
        case IRO_ADC: case IRO_ADCS: case IRO_SBC: case IRO_SBCS:
            return 1;
        case IRO_VOP:
            return (o->aux & VF_READF) != 0;     /* FCSEL */
        default:
            return 0;
    }
}

static int op_writes_flags(const IROp *o) {
    switch (o->op) {
        case IRO_ADDS: case IRO_SUBS: case IRO_ADDIS: case IRO_SUBIS:
        case IRO_ANDS: case IRO_BICS: case IRO_ANDIS:
        case IRO_ADCS: case IRO_SBCS:
        case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI:
            return 1;
        case IRO_VOP:
            return (o->aux & VF_SETF) != 0;      /* FCMP */
        default:
            return 0;
    }
}

static void fe_liveness(IRBlock *ir) {
    /* Guest registers are always live-out (successor blocks read them);
     * temps die inside the block. NZCV is live-out too (conservative). */
    u64 live = ((1ULL << 32) - 1) | (1ULL << VREG_SP);
    int flags_live = 1;
    for (int i = ir->n - 1; i >= 0; i--) {
        IROp *o = &ir->ops[i];
        ir->live_after[i] = live;
        if (o->op == IRO_CALL1) {           /* uses and defines everything */
            live = ((1ULL << 32) - 1) | (1ULL << VREG_SP);
            flags_live = 1;                 /* helper may read/write NZCV */
            continue;
        }
        if (op_writes_flags(o)) {
            if (!flags_live &&
                !(o->op >= IRO_CCMPR && o->op <= IRO_CCMNI)) {
                o->flags_dead = 1;          /* strip the S: no reader */
            }
            flags_live = 0;
        }
        if (op_reads_flags(o)) flags_live = 1;
        /* register liveness: def kills, uses gen */
        switch (o->op) {
            case IRO_JMP: case IRO_NOP:
                break;
            default:
                if (o->dst < VREG_N && o->dst != VREG_ZERO &&
                    !(o->op >= IRO_CCMPR && o->op <= IRO_CCMNI) &&
                    o->op != IRO_ST && o->op != IRO_BCOND &&
                    o->op != IRO_CBZ && o->op != IRO_CBNZ &&
                    o->op != IRO_TBZ && o->op != IRO_TBNZ &&
                    o->op != IRO_JMPIND)
                    live &= ~(1ULL << o->dst);
                if (o->a < VREG_N && o->a != VREG_ZERO &&
                    o->op != IRO_MOVI)
                    live |= 1ULL << o->a;
                if (o->b < VREG_N && o->b != VREG_ZERO) {
                    switch (o->op) {
                        case IRO_ADD: case IRO_ADDS: case IRO_SUB:
                        case IRO_SUBS: case IRO_AND: case IRO_ANDS:
                        case IRO_BIC: case IRO_BICS: case IRO_ORR:
                        case IRO_ORN: case IRO_EOR: case IRO_EON:
                        case IRO_LSLV: case IRO_LSRV: case IRO_ASRV:
                        case IRO_RORV: case IRO_EXTR: case IRO_MADD:
                        case IRO_MSUB: case IRO_SMADDL: case IRO_SMSUBL:
                        case IRO_UMADDL: case IRO_UMSUBL: case IRO_SMULH:
                        case IRO_UMULH: case IRO_UDIV: case IRO_SDIV:
                        case IRO_CSEL: case IRO_CSINC: case IRO_CSINV:
                        case IRO_CSNEG: case IRO_CCMPR: case IRO_CCMNR:
                        case IRO_ST: case IRO_ATOMIC:
                            live |= 1ULL << o->b;
                            break;
                        default:
                            break;
                    }
                }
                if ((o->op == IRO_MADD || o->op == IRO_MSUB ||
                     o->op == IRO_SMADDL || o->op == IRO_SMSUBL ||
                     o->op == IRO_UMADDL || o->op == IRO_UMSUBL ||
                     o->op == IRO_ATOMIC) &&
                    o->cc < VREG_N && o->cc != VREG_ZERO)
                    live |= 1ULL << o->cc;
                break;
        }
    }
}

u32 jit_fe_block(CPU *c, u64 pc, IRBlock *ir, u32 max_insns) {
    ir->n = 0;
    ir->ninsns = 0;
    u32 guest_n = 0;
    u64 p = pc;
    if (max_insns == 0 || max_insns > JIT_MAX_BLOCK_INSNS)
        max_insns = JIT_MAX_BLOCK_INSNS;
    for (;;) {
        u32 insn;
        if (!mem_ifetch(c, p, &insn)) {
            if (guest_n == 0) return 0;     /* entry fetch fault recorded */
            ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, p, 0);
            break;
        }
        if ((insn & 0xffffffe0u) == 0xd50b7520u) {   /* IC IVAU, Xt */
            ir_put(ir, IRO_CALL1, 1 /* IC variant */, 0, 0, 0, 0, p, insn);
            guest_n++;
            ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, p + 4, 0);
            break;
        }
        PDEnt ent;
        pd_fill(&ent, insn);
        if (UNLIKELY(fe_gated(ent.op))) ent.op = PD_GENERIC;
        int r = fe_insn(ir, &ent, p);
        guest_n++;
        p += 4;
        if (r == FE_END) break;
        if (guest_n >= max_insns ||
            (p & (GUEST_PAGE_SIZE - 1)) == 0 ||
            ir->n >= IR_MAX_OPS - 8) {
            ir_put(ir, IRO_JMP, 0, 0, 0, 0, 0, p, 0);
            break;
        }
    }
    fe_liveness(ir);
    return guest_n;
}
