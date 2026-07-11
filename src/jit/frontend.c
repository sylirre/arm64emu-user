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
            case IRO_ADCS: case IRO_SBCS:
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
                       unsigned szlog, int sign, int is64, u64 pc) {
    IROp *o = ir_put(ir, IRO_LD, (u8)is64, (u8)(VREG_TMP0 + k), base, 0,
                     (u8)szlog, (u64)off,
                     MDESC_MAKE(k, szlog, sign, is64) | MDESC_TMPBIT);
    o->imm2pc = pc;
}
/* Pre/post-indexed load: the interpreter computes the writeback value from
 * the OLD base and applies it AFTER the register write (base wins when
 * rt == rn), so a base-clobbering load must stash the base in TMP2 first. */
static void put_ld_wb(IRBlock *ir, unsigned rn, s64 imm, unsigned rt,
                      unsigned szlog, int sign, int is64, int pre, u64 pc) {
    if (rt == rn && rt != 31) {
        ir_put(ir, IRO_MOV, 1, VREG_TMP2, rsp(rn), 0, 0, 0, 0);
        put_ld(ir, VREG_TMP2, pre ? imm : 0, rt, szlog, sign, is64, pc);
        ir_put(ir, IRO_ADDI, 1, (u8)rn, VREG_TMP2, 0, 0, (u64)imm, 0);
    } else {
        put_ld(ir, rsp(rn), pre ? imm : 0, rt, szlog, sign, is64, pc);
        put_wb(ir, rn, imm);
    }
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
    unsigned rd = insn & 31, rn = (insn >> 5) & 31;
    u32 vclass = ~0u;
    u8 gdst = VREG_ZERO, gsrc = VREG_ZERO;   /* guest GPRs involved */
    u32 aux_extra = 0;

    if ((insn & 0x9F200400u) == 0x0E200400u) {
        /* vector three-same (bit31=0, 28:24=01110, 21=1, 10=1) */
        unsigned U = (insn >> 29) & 1, Q = (insn >> 30) & 1;
        unsigned opc = (insn >> 11) & 0x1f;
        unsigned size3 = (insn >> 22) & 3;
        if (opc == 0x03) vclass = VC_BITW;
        else if (opc == 0x10) vclass = VC_ADDSUB;
        else if (opc == 0x11 || opc == 0x06 || opc == 0x07)
            vclass = VC_CM3;                     /* +CMTST (U=0 0x11) */
        else if ((opc == 0x0c || opc == 0x0d) && size3 != 3)
            vclass = VC_MINMAX;
        else if (opc == 0x13 && !U && size3 != 3)
            vclass = VC_MUL3;
        else if ((opc == 0x17 && !U && !(size3 == 3 && !Q)) ||
                 ((opc == 0x14 || opc == 0x15) && size3 != 3))
            vclass = VC_PAIRI;                   /* ADDP, S/U MAXP/MINP */
        else if (opc >= 0x18 && !(((insn >> 22) & 1) && !Q)) {
            /* FP page (sz=bit22; .2d needs Q). Arith is NaN-gated and
             * self-counting; the mask compares are exact as-is. */
            unsigned key = (U << 6) | (((insn >> 23) & 1) << 5) | opc;
            switch (key) {
                case 0x19: case 0x39:            /* FMLA / FMLS */
                case 0x1a: case 0x3a:            /* FADD / FSUB */
                case 0x5b: case 0x5f: case 0x7a: /* FMUL / FDIV / FABD */
                    vclass = VC_VF3S; break;
                case 0x1c: case 0x5c: case 0x7c: /* FCMEQ / FCMGE / FCMGT */
                case 0x5d: case 0x7d:            /* FACGE / FACGT */
                    vclass = VC_VFCM; break;
                default: break;
            }
        }
    } else if ((insn & 0xDF200400u) == 0x5E200400u) {
        /* AdvSIMD scalar three-same (bit28 set): the D-form integer ADD/SUB
         * and compares — size==3 only. The other sizes and opcodes are the
         * saturating/rounding families, which keep the helper (and its
         * undefined-instruction behavior). */
        unsigned opc = (insn >> 11) & 0x1f;
        unsigned size3 = (insn >> 22) & 3;
        if (size3 == 3 &&
            (opc == 0x10 || opc == 0x11 || opc == 0x06 || opc == 0x07))
            vclass = VC_S3S;
    } else if ((insn & 0xDF800400u) == 0x5F000400u &&
               ((insn >> 19) & 0xf) != 0) {
        /* AdvSIMD scalar shift-imm: the D-form same-width shifts (immh<3>
         * set), incl. the S/USRA accumulators — glibc/gcc use `add d,d,d` +
         * `usra` shapes in checksum/hash loops. Narrowing, rounding,
         * saturating and fixed-point-convert forms keep the helper. */
        unsigned U = (insn >> 29) & 1, opc = (insn >> 11) & 0x1f;
        if (((insn >> 22) & 1) &&                /* immh & 8: esize 64 */
            ((opc == 0x0a && !U) || opc == 0x00 || opc == 0x02))
            vclass = VC_SSHIFTI;
    } else if ((insn & 0x9F3E0C00u) == 0x0E200800u) {
        /* two-register misc (21:17 = 10000, 11:10 = 10); the whitelist
         * mirrors simd_two_misc's coverage and the architectural size
         * constraints, so anything else keeps the helper (and its
         * undefined-instruction behavior). */
        unsigned U = (insn >> 29) & 1, Q = (insn >> 30) & 1;
        unsigned size = (insn >> 22) & 3;
        switch ((U << 5) | ((insn >> 12) & 0x1f)) {
            case 0x00:                           /* REV64 */
                if (size <= 2) vclass = VC_2MISC;
                break;
            case 0x20:                           /* REV32 */
                if (size <= 1) vclass = VC_2MISC;
                break;
            case 0x01:                           /* REV16 */
                if (size == 0) vclass = VC_2MISC;
                break;
            case 0x02: case 0x22:                /* SADDLP / UADDLP */
            case 0x04: case 0x24:                /* CLS / CLZ */
                if (size <= 2) vclass = VC_2MISC;
                break;
            case 0x05:                           /* CNT */
                if (size == 0) vclass = VC_2MISC;
                break;
            case 0x25:                           /* NOT (sz 0) / RBIT (sz 1) */
                if (size <= 1) vclass = VC_2MISC;
                break;
            case 0x08: case 0x28:                /* CMGT / CMGE #0 */
            case 0x09: case 0x29:                /* CMEQ / CMLE #0 */
            case 0x0a:                           /* CMLT #0 */
            case 0x0b: case 0x2b:                /* ABS / NEG */
                if (!(size == 3 && !Q)) vclass = VC_2MISC;
                break;
            case 0x12:                           /* XTN / XTN2 */
            case 0x33:                           /* SHLL / SHLL2 */
                if (size <= 2) vclass = VC_2MISC;
                break;
            default:
                break;
        }
    } else if ((insn & 0x9F3E0C00u) == 0x0E300800u) {
        /* across-lanes reductions (21:17 = 11000) */
        unsigned U = (insn >> 29) & 1, Q = (insn >> 30) & 1;
        unsigned size = (insn >> 22) & 3;
        unsigned opc17 = (insn >> 12) & 0x1f;
        if (((opc17 == 0x1b && !U) ||            /* ADDV */
             opc17 == 0x0a || opc17 == 0x1a) &&  /* S/U MAXV / MINV */
            (size <= 1 || (size == 2 && Q)))
            vclass = VC_ACROSS;
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
        unsigned immh = (insn >> 19) & 0xf;
        if ((opc == 0x0a && !U) || opc == 0x00 || opc == 0x02)
            vclass = VC_SHIFTI;                  /* +S/USRA accumulate */
        else if ((opc == 0x10 && !U && immh <= 7) ||   /* SHRN(2): narrow */
                 (opc == 0x14 && immh <= 7))           /* S/USHLL(2): widen */
            vclass = VC_SHIFTI;
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
    } else if ((insn & 0xFF000000u) == 0x1F000000u) {
        /* scalar FP data-processing 3-source: FMADD/FMSUB/FNMADD/FNMSUB.
         * exec_fp_dp3 computes a +- n*m in host C (uncontracted mul+add on
         * SSE2; contracted to fmadd on the a64 cross build — both match the
         * same-host interpreter binary). */
        unsigned ftype = (insn >> 22) & 3;
        if (ftype == 0 || ftype == 1) vclass = VC_F3;
    } else if ((insn & 0x7F000000u) == 0x1E000000u) {
        /* scalar FP */
        unsigned ftype = (insn >> 22) & 3, o2 = (insn >> 10) & 3;
        if (((insn >> 24) & 0x1f) == 0x1e && ((insn >> 21) & 1) == 1 &&
            ((insn >> 10) & 0x3f) == 0) {
            /* FP<->integer: FMOV bit moves, SCVTF/UCVTF, FCVTZS/FCVTZU */
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
            } else if (ftype <= 1 && rmode == 0 &&
                       (opcode == 2 || opcode == 3) && rn != 31) {
                vclass = VC_CVTIF;               /* SCVTF/UCVTF from gpr */
                gsrc = rx(rn);
            } else if (ftype <= 1 && rmode == 3 &&
                       (opcode == 0 || opcode == 1)) {
                vclass = VC_CVTFI;               /* FCVTZS/FCVTZU to gpr;
                                                  * N/P/M/A modes stay helpers
                                                  * (f_round is ties-away) */
                gdst = rx(rd);
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
                else if ((opc == 0x4 && ftype == 1) ||
                         (opc == 0x5 && ftype == 0))
                    vclass = VC_FCVT;            /* FCVT S<->D (plain casts) */
            } else if (o2 == 2) {                            /* 2-source */
                unsigned opc = (insn >> 12) & 0xf;
                if (opc <= 0x8) vclass = VC_F2;  /* +FNMUL, +FMAX..FMINNM */
            } else if (o2 == 3) {                            /* FCSEL */
                vclass = VC_FCSEL;
                aux_extra = VF_READF;
            } else if (o2 == 1) {                            /* FCCMP(E) */
                vclass = VC_FCCMP;
                aux_extra = VF_READF | VF_SETF;
            }
        }
    }

    if (vclass == ~0u || !be_vop_ok(vclass, insn)) return 0;
    IROp *o = ir_put(ir, IRO_VOP, 0, gdst, gsrc, VREG_ZERO, 0, (u64)insn,
                     vclass | aux_extra);
    o->imm2pc = pc;
    /* FP arithmetic results are NaN-gated (a NaN result means the
     * compiler's operand-order-dependent NaN propagation in the interpreter
     * would show — re-run there). Those classes follow the atomics'
     * self-counting discipline: not in ninsns, the fast path bumps icount
     * inline. */
    if (vclass != VC_F2 && vclass != VC_F3 && vclass != VC_VF3S)
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
        else if (!o3)                            /* LDADD..LDSET, LDSMAX..LDUMIN */
            o = ir_put(ir, IRO_ATOMIC, 1, rx(rt), rsp(rn), rx(rs), VREG_ZERO,
                       (u64)insn, AT_MAKE(AT_LDADD + opc, szl, A, R));
    }
    if (!o) return 0;
    o->imm2pc = pc;
    return 1;
}

/* Load/store forms predecode leaves PD_GENERIC (decode.c ldst_register /
 * ldst_pair / ldst_literal are the reference): signed and sub-word pre/post
 * index, signed register-offset, all SIMD register-offset and non-Q
 * writeback forms, LDRSW literal, LDPSW, the non-temporal pairs and S-sized
 * vector pairs. Address math and commit order mirror the interpreter:
 * writeback only after a successful access, computed from the old base.
 * Returns 1 when handled (caller counts the insn); 0 = helper. */
static int fe_ldst_extra(IRBlock *ir, u32 insn, u64 pc) {
    if (((insn >> 25) & 5) != 4) return 0;         /* loads/stores top group */
    unsigned b2927 = (insn >> 27) & 7;
    unsigned rt = insn & 31, rn = (insn >> 5) & 31, rt2 = (insn >> 10) & 31;
    unsigned size = insn >> 30, opc = (insn >> 22) & 3;
    int V = (insn >> 26) & 1;

    if (b2927 == 3 && ((insn >> 24) & 3) == 0) {   /* literal */
        if (V) return 0;
        if (size == 2) {                           /* LDRSW (literal) */
            s64 off = (s64)((s32)(insn << 8) >> 13) << 2;
            ir_put(ir, IRO_MOVI, 1, VREG_TMP0, 0, 0, 0, pc + off, 0);
            put_ld(ir, VREG_TMP0, 0, rt, 2, 1, 1, pc);
            return 1;
        }
        if (size == 3) return 1;                   /* PRFM (literal): nop */
        return 0;
    }

    if (b2927 == 5) {                              /* pairs (opc = size here) */
        unsigned mode = (insn >> 23) & 7;          /* 0 NP, 1 post, 3 pre */
        int L = (insn >> 22) & 1;
        opc = size;
        if (mode > 3) return 0;
        if (V) {
            if (opc > 2) return 0;
            unsigned vszl = opc + 2;
            s64 imm = (s64)((s32)(insn << 10) >> 25) << vszl;
            s64 a0 = (mode == 1) ? 0 : imm;
            if (L) {
                put_ldv(ir, rsp(rn), a0, rt, vszl, pc);
                put_ldv(ir, rsp(rn), a0 + (1 << vszl), rt2, vszl, pc);
            } else {
                put_stv(ir, rsp(rn), a0, rt, vszl, pc);
                put_stv(ir, rsp(rn), a0 + (1 << vszl), rt2, vszl, pc);
            }
            if (mode == 1 || mode == 3) put_wb(ir, rn, imm);
            return 1;
        }
        unsigned szl = (opc == 2) ? 3 : 2, esz = 1u << szl;
        int sign = (opc == 1);                     /* LDPSW */
        s64 imm = (s64)((s32)(insn << 10) >> 25) << szl;
        if (opc == 3 || (sign && (!L || mode == 0))) return 0;
        if (L) {                                   /* all-or-nothing commit */
            int wb = (mode == 1 || mode == 3);
            s64 a0 = (mode == 1) ? 0 : imm;
            if (wb) {                              /* old base survives in TMP2 */
                if (a0) ir_put(ir, IRO_ADDI, 1, VREG_TMP2, rsp(rn), 0, 0, (u64)a0, 0);
                else    ir_put(ir, IRO_MOV,  1, VREG_TMP2, rsp(rn), 0, 0, 0, 0);
                put_ld_tmp(ir, VREG_TMP2, 0,        0, szl, sign, 1, pc);
                put_ld_tmp(ir, VREG_TMP2, (s64)esz, 1, szl, sign, 1, pc);
            } else {
                put_ld_tmp(ir, rsp(rn), a0,             0, szl, sign, 1, pc);
                put_ld_tmp(ir, rsp(rn), a0 + (s64)esz,  1, szl, sign, 1, pc);
            }
            u8 w = (u8)(sign || opc == 2);
            if (rt  != 31) ir_put(ir, IRO_MOV, w, (u8)rt,  VREG_TMP0, 0, 0, 0, 0);
            if (rt2 != 31) ir_put(ir, IRO_MOV, w, (u8)rt2, VREG_TMP1, 0, 0, 0, 0);
            if (wb) ir_put(ir, IRO_ADDI, 1, rsp(rn), VREG_TMP2, 0, 0,
                           (mode == 1) ? (u64)imm : 0, 0);
        } else {
            if (mode != 0) return 0;               /* offset STP: PD covers */
            put_st(ir, rsp(rn), imm,            rx(rt),  szl, pc);
            put_st(ir, rsp(rn), imm + (s64)esz, rx(rt2), szl, pc);
        }
        return 1;
    }

    if (b2927 != 7 || ((insn >> 24) & 1)) return 0;    /* imm12: PD covers */
    unsigned scale = V ? ((opc & 2) ? 4 : size) : size;

    if ((insn >> 21) & 1) {                        /* register offset */
        if (((insn >> 10) & 3) != 2) return 0;     /* LSE atomics: fe_atomic */
        if (V) {
            if ((opc & 2) && size != 0) return 0;
        } else {
            if (opc == 2 && size == 3) return 1;   /* PRFM (register): nop */
            if (opc == 3 && size >= 2) return 0;   /* undefined: helper */
        }
        unsigned option = (insn >> 13) & 7;
        unsigned shift = ((insn >> 12) & 1) ? scale : 0;
        u8 idx = fe_extended(ir, (insn >> 16) & 31, option, shift);
        ir_put(ir, IRO_ADD, 1, VREG_TMP1, rsp(rn), idx, 0, 0, 0);
        if (V) {
            unsigned vszl = (opc & 2) ? 4 : size;
            if (opc & 1) put_ldv(ir, VREG_TMP1, 0, rt, vszl, pc);
            else         put_stv(ir, VREG_TMP1, 0, rt, vszl, pc);
        } else if (opc == 0) {
            put_st(ir, VREG_TMP1, 0, rx(rt), size, pc);
        } else {
            put_ld(ir, VREG_TMP1, 0, rt, size, opc >= 2, opc != 3, pc);
        }
        return 1;
    }

    unsigned mode = (insn >> 10) & 3;              /* 1 post, 3 pre */
    if (mode != 1 && mode != 3) return 0;          /* unscaled: PD covers */
    int pre = (mode == 3);
    s64 imm9 = (s64)((s32)(insn << 11) >> 23);
    if (V) {
        if (opc & 2) return 0;                     /* Q writeback: PD covers */
        if (opc & 1) put_ldv(ir, rsp(rn), pre ? imm9 : 0, rt, size, pc);
        else         put_stv(ir, rsp(rn), pre ? imm9 : 0, rt, size, pc);
        put_wb(ir, rn, imm9);
        return 1;
    }
    if (opc == 0) {                                /* store, any size */
        put_st(ir, rsp(rn), pre ? imm9 : 0, rx(rt), size, pc);
        put_wb(ir, rn, imm9);
        return 1;
    }
    if (opc == 2 && size == 3) return 0;           /* PRFM-with-wb: helper */
    if (opc == 3 && size >= 2) return 0;           /* undefined: helper */
    put_ld_wb(ir, rn, imm9, rt, size, opc >= 2, opc != 3, pre, pc);
    return 1;
}

/* LD1/ST1 multiple-structure, contiguous forms only (decode.c
 * ldst_vector_multi): whole-register loads/stores of 1-4 consecutive V
 * registers, committing per register exactly like the interpreter's loop
 * (a mid-sequence fault keeps the earlier registers and skips writeback).
 * The de-interleaved LD2/3/4 and single-lane forms stay helpers. */
static int fe_ld1(IRBlock *ir, u32 insn, u64 pc) {
    int post;
    if      ((insn & 0xBFBF0000u) == 0x0C000000u) post = 0;
    else if ((insn & 0xBFA00000u) == 0x0C800000u) post = 1;
    else return 0;
    unsigned nregs;
    switch ((insn >> 12) & 0xf) {                  /* contiguous opcodes */
        case 0x2: nregs = 4; break;
        case 0x6: nregs = 3; break;
        case 0x7: nregs = 1; break;
        case 0xa: nregs = 2; break;
        default: return 0;                         /* LD2/3/4: helper */
    }
    unsigned Q = (insn >> 30) & 1, L = (insn >> 22) & 1;
    unsigned rm = (insn >> 16) & 31, rn = (insn >> 5) & 31, rt = insn & 31;
    unsigned vszl = Q ? 4 : 3, regbytes = Q ? 16 : 8;
    for (unsigned r = 0; r < nregs; r++) {
        if (L) put_ldv(ir, rsp(rn), (s64)(r * regbytes), (rt + r) & 31, vszl, pc);
        else   put_stv(ir, rsp(rn), (s64)(r * regbytes), (rt + r) & 31, vszl, pc);
    }
    if (post) {
        if (rm == 31) put_wb(ir, rn, (s64)(nregs * regbytes));
        else ir_put(ir, IRO_ADD, 1, rsp(rn), rsp(rn), (u8)rm, 0, 0, 0);
    }
    return 1;
}

/* Bitfield forms predecode leaves PD_GENERIC: SBFIZ (SBFM with imms < immr)
 * and the BFM family (BFI/BFXIL). decode.c:189 is the reference; these are
 * emitted from the ARM alias equivalences using existing shift/mask IR ops.
 * The N/immr/imms validity filter mirrors predecode's — anything invalid
 * stays on the helper, which raises the undefined exception. */
static int fe_bitfield(IRBlock *ir, u32 insn, u64 pc) {
    (void)pc;
    if ((insn & 0x1F800000u) != 0x13000000u) return 0;
    unsigned sf = insn >> 31, opc = (insn >> 29) & 3, N = (insn >> 22) & 1;
    unsigned immr = (insn >> 16) & 0x3f, imms = (insn >> 10) & 0x3f;
    unsigned rd = insn & 31, rn = (insn >> 5) & 31;
    unsigned width = sf ? 64 : 32;
    u8 w = (u8)sf;
    if (sf ? (N != 1) : (N != 0 || immr >= 32 || imms >= 32)) return 0;

    if (opc == 0 && imms < immr) {                 /* SBFIZ */
        if (rd == 31) return 1;                    /* write to XZR: dead */
        ir_put(ir, IRO_LSLI, w, VREG_TMP0, rx(rn), 0, 0, width - 1 - imms, 0);
        ir_put(ir, IRO_ASRI, w, (u8)rd, VREG_TMP0, 0, 0, immr - imms - 1, 0);
        return 1;
    }
    if (opc == 1) {                                /* BFM: BFXIL / BFI */
        if (rd == 31) return 1;
        /* Masks are < 2^width, and 32-bit guest regs are stored
         * zero-extended, so full-width (w=1) mask ops are exact. */
        if (imms >= immr) {                        /* BFXIL */
            u64 mask = (imms - immr + 1 >= 64)
                           ? ~0ULL : (1ULL << (imms - immr + 1)) - 1;
            if (immr)          ir_put(ir, IRO_LSRI, w, VREG_TMP0, rx(rn), 0, 0, immr, 0);
            else if (rn == 31) ir_put(ir, IRO_MOVI, 1, VREG_TMP0, 0, 0, 0, 0, 0);
            else               ir_put(ir, IRO_MOV,  1, VREG_TMP0, (u8)rn, 0, 0, 0, 0);
            ir_put(ir, IRO_ANDI, 1, VREG_TMP0, VREG_TMP0, 0, 0, mask, 0);
            ir_put(ir, IRO_ANDI, 1, VREG_TMP1, rx(rd), 0, 0, ~mask, 0);
            ir_put(ir, IRO_ORR, w, (u8)rd, VREG_TMP0, VREG_TMP1, 0, 0, 0);
        } else {                                   /* BFI */
            unsigned lsb = width - immr;
            u64 mask = (1ULL << (imms + 1)) - 1;   /* imms < immr < width */
            ir_put(ir, IRO_ANDI, 1, VREG_TMP0, rx(rn), 0, 0, mask, 0);
            ir_put(ir, IRO_LSLI, 1, VREG_TMP0, VREG_TMP0, 0, 0, lsb, 0);
            ir_put(ir, IRO_ANDI, 1, VREG_TMP1, rx(rd), 0, 0, ~(mask << lsb), 0);
            ir_put(ir, IRO_ORR, w, (u8)rd, VREG_TMP0, VREG_TMP1, 0, 0, 0);
        }
        return 1;
    }
    return 0;
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

        /* pre/post-indexed (imm = simm9); writeback after the access, from
         * the old base (put_ld_wb handles the rd==rn base-clobber case) */
        case PD_LDR64PRE:  put_ld_wb(ir, e->rn, (s64)e->imm, e->rd, 3, 0, 1, 1, pc); break;
        case PD_LDR64POST: put_ld_wb(ir, e->rn, (s64)e->imm, e->rd, 3, 0, 1, 0, pc); break;
        case PD_LDR32PRE:  put_ld_wb(ir, e->rn, (s64)e->imm, e->rd, 2, 0, 0, 1, pc); break;
        case PD_LDR32POST: put_ld_wb(ir, e->rn, (s64)e->imm, e->rd, 2, 0, 0, 0, pc); break;
        case PD_STR64PRE:  put_st(ir, rsp(e->rn), (s64)e->imm, rx(e->rd), 3, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STR64POST: put_st(ir, rsp(e->rn), 0,          rx(e->rd), 3, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STR32PRE:  put_st(ir, rsp(e->rn), (s64)e->imm, rx(e->rd), 2, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_STR32POST: put_st(ir, rsp(e->rn), 0,          rx(e->rd), 2, pc); put_wb(ir, e->rn, (s64)e->imm); break;
        case PD_LDRBPOST:  put_ld_wb(ir, e->rn, (s64)e->imm, e->rd, 0, 0, 1, 0, pc); break;
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
            put_ld_tmp(ir, VREG_TMP2, 0,        0, szl, 0, is64, pc);
            put_ld_tmp(ir, VREG_TMP2, (s64)esz, 1, szl, 0, is64, pc);
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
            /* The fe_* families decode raw words (no PD id), so each gets a
             * pseudo-id above PD_NOPS_ for A64_JIT_PDMAX bisection:
             *   +0 fe_atomic  +1 fe_fpsimd  +2 fe_ldst_extra  +3 fe_bitfield
             *   +4 fe_ld1     +5 RBIT idiom +6 ADC/SBC family */
            if (e->op == PD_GENERIC && !fe_gated(PD_NOPS_ + 0) &&
                fe_atomic(ir, insn, pc))
                return FE_CONT;      /* inline atomic (not in ninsns) */
            if (e->op == PD_GENERIC && !fe_gated(PD_NOPS_ + 1) &&
                fe_fpsimd(ir, insn, pc))
                return FE_CONT;      /* inline vector/FP (counted inside) */
            if (e->op == PD_GENERIC && !fe_gated(PD_NOPS_ + 2) &&
                fe_ldst_extra(ir, insn, pc)) {
                ir->ninsns++;        /* inline leftover load/store form */
                return FE_CONT;
            }
            if (e->op == PD_GENERIC && !fe_gated(PD_NOPS_ + 3) &&
                fe_bitfield(ir, insn, pc)) {
                ir->ninsns++;        /* SBFIZ / BFM family */
                return FE_CONT;
            }
            if (e->op == PD_GENERIC && !fe_gated(PD_NOPS_ + 4) &&
                fe_ld1(ir, insn, pc)) {
                ir->ninsns++;        /* contiguous LD1/ST1 */
                return FE_CONT;
            }
            if (e->op == PD_GENERIC && !fe_gated(PD_NOPS_ + 5) &&
                (insn & 0x7FFFFC00u) == 0x5AC00000u) {
                /* RBIT (dp 1-source, opcode 0): strlen's rbit+clz idiom */
                if ((insn & 31) != 31)
                    ir_put(ir, IRO_RBIT, (u8)(insn >> 31), (u8)(insn & 31),
                           rx((insn >> 5) & 31), 0, 0, 0, 0);
                ir->ninsns++;
                return FE_CONT;
            }
            if (e->op == PD_GENERIC && !fe_gated(PD_NOPS_ + 6) &&
                (insn & 0x1FE0FC00u) == 0x1A000000u) {
                /* ADC/ADCS/SBC/SBCS (+ NGC(S): Rn == 31). decode.c's
                 * add_with_carry is the reference; the backends consume the
                 * guest C flag natively. A non-S form writing XZR is
                 * architecturally a no-op (put_alu drops it). */
                unsigned sbc = (insn >> 30) & 1, S = (insn >> 29) & 1;
                static const u8 ops[4] = { IRO_ADC, IRO_ADCS,
                                           IRO_SBC, IRO_SBCS };
                put_alu(ir, ops[(sbc << 1) | S], (u8)(insn >> 31),
                        rx(insn & 31), rx((insn >> 5) & 31),
                        rx((insn >> 16) & 31));
                ir->ninsns++;
                return FE_CONT;
            }
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
                if ((insn & 0xFFFFFFE0u) == 0xD50B7420u) {   /* DC ZVA */
                    /* Zero 64 bytes at Xt & ~63 — glibc memset's bulk path.
                     * Eight 8-byte zero stores mirror sysreg.c's mem_write
                     * loop (same order, same first-fault stop), and the
                     * inline write probes keep the SMC coherence rules. */
                    ir_put(ir, IRO_ANDI, 1, VREG_TMP2, rx(rt), 0, 0,
                           ~63ULL, 0);
                    for (int zi = 0; zi < 8; zi++)
                        put_st(ir, VREG_TMP2, 8 * zi, VREG_ZERO, 3, pc);
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
                        case IRO_SUBS: case IRO_ADC: case IRO_ADCS:
                        case IRO_SBC: case IRO_SBCS:
                        case IRO_AND: case IRO_ANDS:
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

int jit_mem_run_len(const IRBlock *ir, int i) {
    const IROp *o = &ir->ops[i];
    if (o->op != IRO_LD && o->op != IRO_ST) return 1;
    s64 lo = (s64)o->imm, hi = lo + (s64)(1u << o->cc);
    u8 seen[6];
    int nseen = 0;
    seen[nseen++] = o->op == IRO_ST ? o->b : o->dst;
    int k = 1;
    for (; i + k < ir->n && k < 8; k++) {
        const IROp *p = &ir->ops[i + k];
        if (p->op != o->op || p->a != o->a) break;
        if (o->op == IRO_LD && ir->ops[i + k - 1].dst == o->a)
            break;                    /* a prior load clobbered the base */
        s64 plo = (s64)p->imm, phi = plo + (s64)(1u << p->cc);
        s64 nlo = plo < lo ? plo : lo, nhi = phi > hi ? phi : hi;
        if (nhi - nlo > 4096) break;  /* span must fit one guest page */
        u8 r = p->op == IRO_ST ? p->b : p->dst;
        int found = 0;
        for (int t = 0; t < nseen; t++)
            if (seen[t] == r) { found = 1; break; }
        if (!found) {
            if (nseen >= 6) break;    /* register budget */
            seen[nseen++] = r;
        }
        lo = nlo;
        hi = nhi;
    }
    return k;
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
