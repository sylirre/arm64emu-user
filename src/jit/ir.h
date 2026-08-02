/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* JIT intermediate representation. One guest instruction becomes 1..
 * IR_MAX_OPS_PER_INSN linear IR ops; the backends emit host code from them
 * with per-block register
 * allocation. The frontend (frontend.c) is a transcription of the predecode
 * handler semantics (predecode.c, itself checked against decode.c by the
 * differential suite) — XZR/SP resolution, width truncation, pre-decoded
 * immediates and writeback ordering are all resolved HERE, never in a
 * backend.
 *
 * Virtual registers: 0..30 = guest x0..x30, 31 = guest SP (sp_el[0]),
 * 32..34 = block-local temps, 35 = the zero register (reads as 0, writes
 * discarded — backends may have a real zero register). Between blocks all
 * guest state lives in the CPU struct; helpers and block exits sync it.
 *
 * NZCV is not a numbered vreg: ops with an S suffix define the guest flags,
 * cc-consumers (BCOND/CSEL/CCMP/ADC/CSET...) use them. The backend keeps
 * flags lazily (host flags right after the producer; the architectural
 * c->nzcv word otherwise) and materializes on the S-producer when the next
 * op is not its consumer. IR_CC_AL never appears on consumers that cannot
 * take it (frontend folds). The liveness pass strips dead S suffixes. */
#ifndef A64_JIT_IR_H
#define A64_JIT_IR_H

#include "jit_priv.h"

enum {
    VREG_SP   = 31,
    VREG_TMP0 = 32,
    VREG_TMP1 = 33,
    VREG_TMP2 = 34,
    VREG_ZERO = 35,
    VREG_N    = 36,
};

/* op semantics (w: 0 = 32-bit — result zero-extended on write, operands read
 * truncated; 1 = 64-bit): */
enum {
    IRO_NOP = 0,
    /* dst = imm / dst = a */
    IRO_MOVI,               /* dst, imm */
    IRO_MOV,                /* dst, a */
    IRO_MOVK,               /* dst, a, imm = imm16<<sh, cc = sh: keep other bits */

    /* dst = a (op) b; S-forms also define NZCV */
    IRO_ADD,  IRO_ADDS,     /* dst, a, b */
    IRO_SUB,  IRO_SUBS,
    IRO_ADC,  IRO_ADCS,     /* + carry-in from guest C */
    IRO_SBC,  IRO_SBCS,     /* a - b - !C */
    IRO_AND,  IRO_ANDS,
    IRO_BIC,  IRO_BICS,
    IRO_ORR,  IRO_ORN,
    IRO_EOR,  IRO_EON,

    /* dst = a (op) imm; S-forms define NZCV */
    IRO_ADDI, IRO_ADDIS,    /* dst, a, imm */
    IRO_SUBI, IRO_SUBIS,
    IRO_ANDI, IRO_ANDIS,
    IRO_ORRI, IRO_EORI,

    /* shifts (immediate amount in imm, 0..width-1; variable amount masked
     * by width-1 like the guest) */
    IRO_LSLI, IRO_LSRI, IRO_ASRI, IRO_RORI,   /* dst, a, imm = amount */
    IRO_LSLV, IRO_LSRV, IRO_ASRV, IRO_RORV,   /* dst, a, b */

    IRO_EXTR,               /* dst, a = hi, b = lo, imm = amount (0 => lo) */

    /* multiply/divide */
    IRO_MADD, IRO_MSUB,     /* dst = x[cc] +- a*b (cc = Ra vreg) */
    IRO_SMADDL, IRO_SMSUBL, /* dst = x[cc] +- sext32(a)*sext32(b), 64-bit */
    IRO_UMADDL, IRO_UMSUBL,
    IRO_SMULH, IRO_UMULH,   /* dst = high 64 of 64x64 */
    IRO_UDIV, IRO_SDIV,     /* guest semantics: /0 = 0, INT_MIN/-1 = INT_MIN */

    IRO_CLZ,                /* dst, a (width per w; 0 input => width) */
    IRO_REV64, IRO_REV32,   /* bswap64 / bswap32-zext */
    IRO_RBIT,               /* dst, a: bit-reverse within width (per w) */

    /* conditional (consume NZCV; cc = guest condition 0..15) */
    IRO_CSEL, IRO_CSINC, IRO_CSINV, IRO_CSNEG,  /* dst = cc ? a : op(b) */
    IRO_CCMPR, IRO_CCMNR,   /* a vs b   if cc else NZCV = aux (defines NZCV) */
    IRO_CCMPI, IRO_CCMNI,   /* a vs imm if cc else NZCV = aux (defines NZCV) */

    /* memory (Phase C: inline D-TLB probe; until then frontend uses CALL1).
     * addr = x[a] + imm. sz in aux low byte (1/2/4/8), sign-extend flag in
     * aux bit 8 (loads; extension width = w). Faults exit the block with
     * cur_insn_pc = the op's baked guest pc (aux bits 32..: insn index). */
    IRO_LD,                 /* dst=rt(or ZERO), a=base, imm=offset, aux=desc,
                             * cc=szlog, mempc=guest pc; commits to c->x[rt] */
    IRO_ST,                 /* a=base, b=value, imm=offset, aux=desc, cc=szlog */
    IRO_LDV,                /* FP/SIMD: aux=desc(rt,vsz), cc=vsz, into c->v[rt] */
    IRO_STV,                /* FP/SIMD: from c->v[rt] */

    /* control flow (terminal ops; a block's IR always ends with one or two
     * of these). Chainable exits carry the successor guest pc in imm. */
    IRO_JMP,                /* imm = target pc (chainable exit) */
    IRO_BCOND,              /* cc, imm = taken pc; must be followed by JMP */
    IRO_CBZ, IRO_CBNZ,      /* a, w, imm = taken pc; followed by JMP */
    IRO_TBZ, IRO_TBNZ,      /* a, cc = bit, imm = taken pc; followed by JMP */
    IRO_JMPIND,             /* a = target reg: c->pc = a, jcache probe */

    /* helper fallback: sync state, c->{cur_insn_pc,pc} = imm/imm+4, call
     * jit_exec1(c, imm, aux); nonzero return exits the block. Defines every
     * guest register and NZCV as far as the allocator is concerned. */
    IRO_CALL1,              /* imm = guest pc, aux = insn word */

    /* CPU-struct scalar access (TPIDR_EL0 and friends): 64-bit load/store at
     * a byte offset into the CPU struct. No flags, no faults. */
    IRO_CPULD,              /* dst, a = VREG_ZERO, imm = offsetof(CPU, ...) */
    IRO_CPUST,              /* dst = VREG_ZERO, a = src, imm = offset */

    IRO_FENCE,              /* guest DMB/DSB: host full memory barrier */

    /* Inline vector / scalar-FP ALU (exec_fpsimd is the reference; the
     * interpreter computes FP with host C float/double, so plain host FP
     * ops match it bit-for-bit on the same host — no NaN or FPCR gating:
     * the only FPCR-sensitive op, FCVT, stays a helper). aux = VC_* class
     * (+ VF_* flags); imm = the raw insn word, which the backend re-decodes
     * for Rd/Rn/Rm/size/Q/shift — except VC_MOVI, where imm/imm2pc hold the
     * pre-expanded 128-bit pattern. dst/a are the guest GPRs involved
     * (UMOV/SMOV/FMOV-to-gpr define dst; DUP/INS/FMOV-from-gpr read a).
     * Guest V registers are block-locally cached in host vector registers
     * (the backends' vop_src/vop_dst); c->v[] is their home between blocks.
     * No faults. */
    IRO_VOP,

    /* Inline exclusives / LSE atomics / ordered accesses, [base] only (the
     * guest encodings carry no offset). aux = AT_MAKE(kind, szlog, acq, rel);
     * a = base, b = store value / RMW operand, cc = extra source vreg (CAS
     * expected), dst = result (loaded / old value / STXR status; ZERO for
     * the ST* forms). Any TLB miss, misalignment, or perm failure re-runs
     * the whole instruction through jit_exec1 (imm2pc = pc, aux2 = insn in
     * imm). NOT counted in ninsns: the fast path bumps icount inline and
     * jit_exec1 counts itself, so both routes retire exactly once. */
    IRO_ATOMIC,             /* imm = raw insn word (slow-path re-execution) */

    IRO_N_
};

/* IRO_ATOMIC kinds (aux bits 0..7) */
enum {
    AT_LDX,                 /* LDXR/LDAXR: load + record monitor */
    AT_STX,                 /* STXR/STLXR: monitor check + host CAS, status */
    AT_LDAR,                /* LDAR/LDLAR/LDAPR: atomic acquire load */
    AT_STLR,                /* STLR/STLLR: atomic release store */
    AT_SWP,                 /* SWP: dst = old, [base] = b */
    AT_LDADD, AT_LDCLR, AT_LDEOR, AT_LDSET,   /* dst = old, [base] op= b */
    AT_LDSMAX, AT_LDSMIN, AT_LDUMAX, AT_LDUMIN,   /* (order = LSE opc 4-7) */
    AT_CAS,                 /* dst/cc = Rs (expected/old), b = Rt (new) */
};
#define AT_MAKE(kind, szlog, acq, rel) \
    ((u32)((kind) | ((szlog) << 8) | ((acq) << 12) | ((rel) << 13)))
#define AT_KIND(a)  ((a) & 0xff)
#define AT_SZL(a)   (((a) >> 8) & 3)
#define AT_ACQ(a)   (((a) >> 12) & 1)
#define AT_REL(a)   (((a) >> 13) & 1)

/* IRO_VOP classes (aux bits 0..5) + flags. The frontend whitelists exact
 * encodings and asks the backend (be_vop_ok) about per-host gaps; anything
 * declined stays an exec_fpsimd helper call. */
enum {
    VC_BITW,                /* 3-same opc 0x03: AND/BIC/ORR/EOR/BSL/BIT/BIF */
    VC_ADDSUB,              /* 3-same opc 0x10: ADD/SUB, all sizes */
    VC_CM3,                 /* 3-same compares: CMEQ(U1 0x11) CMTST(U0 0x11)
                             * CMGT/CMHI(0x06) CMGE/CMHS(0x07) */
    VC_SHIFTI,              /* shift-imm: SHL(0x0a U0) SSHR/USHR(0x00)
                             * SSRA/USRA(0x02) SHRN(0x10 U0)
                             * USHLL/SSHLL(0x14) */
    VC_MINMAX,              /* 3-same 0x0c/0x0d: SMAX/UMAX/SMIN/UMIN b/h/s */
    VC_MUL3,                /* 3-same 0x13 U0: MUL b/h/s */
    VC_PAIRI,               /* 3-same pairwise: ADDP(0x17 U0) S/UMAXP(0x14)
                             * S/UMINP(0x15) */
    VC_2MISC,               /* two-reg misc: CM*-#0, ABS/NEG, NOT, RBIT.v,
                             * CNT, CLZ/CLS, XTN(2), REV*, SHLL, S/UADDLP */
    VC_ACROSS,              /* across lanes: ADDV, S/UMAXV, S/UMINV */
    VC_VF3S,                /* vector FP 3-same arith: FADD/FSUB/FMUL/FDIV/
                             * FABD/FADDP, and FMLA/FMLS where the backend can
                             * fuse (a64 native; x86 FMA3, else declined).
                             * NaN-gated, self-counting. */
    VC_VFCM,                /* vector FP 3-same compares: FCMEQ/FCMGE/FCMGT/
                             * FACGE/FACGT (mask result, no gate) */
    VC_MOVI,                /* modified-imm MOVI/MVNI/FMOV/ORR/BIC: imm is
                             * pre-expanded; aux carries rd/Q/op kind */
    VC_COPY,                /* AdvSIMD copy: DUP/INS/UMOV/SMOV */
    VC_F2,                  /* scalar FMUL/FDIV/FADD/FSUB/FNMUL (S/D), and
                             * FMAX/FMIN/FMAXNM/FMINNM (opc 4-7, per-host) */
    VC_F1,                  /* scalar FMOV/FABS/FNEG/FSQRT (S/D) */
    VC_F3,                  /* scalar FMADD/FMSUB/FNMADD/FNMSUB (S/D), fused
                             * like the interpreter's __builtin_fma: a64
                             * replays fmadd, x86 needs FMA3 (else declined).
                             * NaN-gated, self-counting. */
    VC_FCMP,                /* FCMP/FCMPE (reg or #0.0): writes NZCV */
    VC_FCCMP,               /* FCCMP/FCCMPE: reads AND writes NZCV */
    VC_FCSEL,               /* reads NZCV */
    VC_FMOVI,               /* scalar FMOV #imm (pattern in o->imm low half) */
    VC_FMOVG,               /* FMOV gpr<->fpr incl. Vn.D[1] forms */
    VC_CVTIF,               /* SCVTF/UCVTF gpr -> fp (a = gpr source) */
    VC_CVTFI,               /* FCVTZS/FCVTZU fp -> gpr (dst = gpr) */
    VC_FCVT,                /* FCVT S<->D precision change */
    VC_S3S,                 /* AdvSIMD scalar 3-same integer, D-form only:
                             * ADD/SUB(0x10), CMGT/CMHI(0x06), CMGE/CMHS
                             * (0x07), CMTST/CMEQ(0x11) */
    VC_SSHIFTI,             /* AdvSIMD scalar shift-imm, D-form (immh<3>):
                             * SHL(0x0a U0), S/USHR(0x00), S/USRA(0x02) */
    VC_FCVTH,               /* FP16 precision converts: scalar FCVT h<->s/d,
                             * vector FCVTL/FCVTN h<->s. F16C/FEAT_FP16-gated,
                             * source/result NaN-gated (self-counting). */
    VC_H1,                  /* scalar half 1-source: FMOV/FABS/FNEG/FSQRT.
                             * FMOV is a bit copy; FABS/FNEG/FSQRT round-trip
                             * through half (NaN-gated, self-counting). */
    VC_H2,                  /* scalar half 2-source: FMUL/FDIV/FADD/FSUB/FNMUL
                             * (FMAX/FMIN(NM) declined). NaN-gated, self-counting. */
    VC_H3,                  /* scalar half 3-source: FMADD/FMSUB/FNMADD/FNMSUB.
                             * NaN-gated, self-counting. */
    VC_VH3,                 /* vector half three-same arith: FADD/FSUB/FMUL/
                             * FDIV/FABD (.4h/.8h). NaN-gated, self-counting. */
    VC_VHCM,                /* vector half three-same compares: FCMEQ/GE/GT,
                             * FACGE/GT -> per-lane mask (no gate). */
    VC_VH2M,                /* vector half two-reg misc: FABS/FNEG/FSQRT and
                             * FRINT* (NaN-gated; FRINTX/I also gate on
                             * FPCR.RMode == RN, a64-only) + FCMxx#0 (mask).
                             * Self-counting. */
    VC_VHMULX,              /* vector half FMULX (three-same). a64-only (native
                             * replay + result NaN gate); x86 declines. */
    VC_VHEST,               /* vector half FRECPE/FRSQRTE (two-misc estimate).
                             * a64-only (native replay + NaN gate); x86 declines. */
    VC_VMISCF,              /* vector two-misc FP (S/D page): FABS/FNEG/FSQRT,
                             * FRINT* (X/I gated on FPCR.RMode == RN), FCMxx#0
                             * masks, FRECPE/FRSQRTE (a64-only). NaN-gated
                             * except the compares; self-counting. */
    VC_FRINTS,              /* scalar FRINT N/P/M/Z/A/X/I, S/D/H. X and I gate
                             * on FPCR.RMode == RN (the interpreter honors the
                             * guest mode in software; native runs host-RN).
                             * a64 replays all; x86 does S/D via SSE4.1 roundss
                             * and declines FRINTA (no ties-away) and half.
                             * NaN-gated, self-counting. */
    VC_FX3,                 /* vector FP 3-same extras: FMULX/FRECPS/FRSQRTS
                             * (S/D). a64-only native replay + result NaN gate
                             * (the fused step and its 0*inf special case live
                             * in fop_d/fop_s and match hardware). */
    VC_FS3,                 /* AdvSIMD scalar 3-same FP: FMULX/FRECPS/FRSQRTS/
                             * FABD (gated) + FCMEQ/GE/GT/FACGE/FACGT masks
                             * (no gate). a64-only replay; self-counting. */
    VC_FPAIRS,              /* AdvSIMD scalar pairwise: ADDP.d (integer, exact)
                             * and FADDP Sd/Dd (NaN-gated). Self-counting.
                             * The MAX/MIN-flavored pairwise reductions stay
                             * helpers with the rest of the FMAX family. */
    VC_FELEM,               /* vector FP by-element FMLA/FMLS/FMUL/FMULX
                             * (.h/.s/.d). a64 replays all (half behind
                             * FEAT_FP16); x86 broadcasts + mulps for FMUL and
                             * FMA3 for FMLA/FMLS (S/D), declining FMULX and
                             * half. NaN-gated, self-counting. */
    VC_FSELEM,              /* scalar FP by-element FMLA/FMLS/FMUL/FMULX (S/D).
                             * a64 replays; x86 loads the element by offset and
                             * uses mulss / FMA3, declining FMULX. NaN-gated,
                             * self-counting. */
    VC_FSMISC,              /* AdvSIMD scalar two-misc: FRECPE/FRSQRTE/FRECPX,
                             * S/D and half pages. a64-only replay; FRECPX is
                             * source-NaN-gated (the interpreter raises no IOC
                             * for it, so the native op must not run on NaN),
                             * the estimates result-NaN-gated. Self-counting. */
    VC_VH3X,                /* vector half three-same extras: FMLA/FMLS (native
                             * half fmla matches the interpreter's compute-in-
                             * double: within half's finite range an addend is
                             * never below half-ulp53 of the product, so the
                             * 53->11 double rounding never diverges), FRECPS/
                             * FRSQRTS, FADDP. a64-only + FEAT_FP16; NaN-gated,
                             * self-counting. */
};
#define VF_READF (1u << 6)  /* consumes guest NZCV (FCSEL) */
#define VF_SETF  (1u << 7)  /* defines guest NZCV (FCMP) */
#define VC(a)    ((a) & 0x3f)
/* VC_MOVI packing: aux bits 8..12 = Rd, 13 = Q, 14..15 = kind
 * (0 = write, 1 = ORR, 2 = BIC) */
#define VMOVI_MAKE(rd, q, kind) \
    ((u32)(VC_MOVI | ((rd) << 8) | ((q) << 13) | ((kind) << 14)))
#define VMOVI_RD(a)   (((a) >> 8) & 31)
#define VMOVI_Q(a)    (((a) >> 13) & 1)
#define VMOVI_KIND(a) (((a) >> 14) & 3)

typedef struct IROp {
    u64 imm;
    u64 imm2pc;             /* memory ops: guest pc baked for a precise fault */
    u32 aux;
    u8  op;
    u8  w;                  /* 0 = 32-bit, 1 = 64-bit */
    u8  dst;
    u8  a;
    u8  b;
    u8  cc;                 /* condition / bit index / Ra vreg / MOVK shift */
    u8  flags_dead;         /* liveness: S-op whose NZCV def is never read */
    u8  icnt;               /* natively-retired guest insns if exiting here
                             * (helper-executed insns count themselves) */
} IROp;

/* Number of 8-byte stores DC ZVA expands to (its zeroed block is 64 bytes).
 * Named because it also fixes the worst case below; keep the two together. */
#define DCZVA_STORES 8

/* Worst-case IR ops emitted for ONE guest instruction. DC ZVA is the
 * outlier by a wide margin — an address-mask op plus DCZVA_STORES stores —
 * where the next largest (LDP with writeback) is 6. jit_fe_block must leave
 * this much headroom free before translating another instruction, PLUS one
 * slot for the IRO_JMP it appends when the budget runs out. Under-reserving
 * does not merely truncate a block: the append runs off the end of ops[],
 * and the liveness pass then indexes live_after[] one past its last element,
 * which is 8 bytes past the end of the heap allocation. */
#define IR_MAX_OPS_PER_INSN (DCZVA_STORES + 1)

/* Sized from an ~4-ops-per-instruction average, not from the worst case: a
 * block whose instructions expand more simply ends early on the headroom
 * check above, covering fewer guest instructions. */
#define IR_MAX_OPS (JIT_MAX_BLOCK_INSNS * 4 + 8)
_Static_assert(IR_MAX_OPS > 2 * (IR_MAX_OPS_PER_INSN + 1),
               "IR budget must fit several worst-case instructions");

typedef struct IRBlock {
    IROp ops[IR_MAX_OPS];
    int  n;
    u32  ninsns;            /* NATIVE-retired guest insn count (icount delta
                             * added by exit stubs; CALL1 insns not included
                             * — jit_exec1 counts those itself) */
    /* Per-op vreg liveness (bit v set = vreg v live after this op). Computed
     * by fe_liveness for a free-after-last-use allocator; NO backend reads it
     * yet — both allocate LRU-style and spill on demand. Kept because the
     * same backward walk already has to run for flags_dead, which is used.
     * Anything wiring it up should re-check the def/use tables first. */
    u64  live_after[IR_MAX_OPS];
} IRBlock;

/* Translate the basic block starting at guest pc into ir (fetching via
 * mem_ifetch, classifying via pd_fill), covering at most max_insns guest
 * instructions. Returns the number consumed (0 = entry fetch fault,
 * pend_exc recorded), and runs the liveness/flag-death pass first. */
u32 jit_fe_block(CPU *c, u64 pc, IRBlock *ir, u32 max_insns);

/* Length (>= 1) of the fusable memory-op run starting at op i: consecutive
 * integer LD or ST ops off the same unclobbered base with constant offsets
 * whose whole span fits one guest page (and a small register budget). The
 * backends emit one span-checked D-TLB probe for the run. */
int jit_mem_run_len(const IRBlock *ir, int i);

#endif /* A64_JIT_IR_H */
