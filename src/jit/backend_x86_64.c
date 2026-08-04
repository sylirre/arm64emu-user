/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* x86-64 code generator. Conventions in generated code:
 *   r14 = CPU*, r15 = JitEnv*        (callee-saved, survive helper calls)
 *   rax/rcx/rdx/rsi                  emitter scratch, never allocated
 *                                    (rsi doubles as the mem-op VA/arg1)
 *   rbx rdi r8-r13                   allocatable pool (guest values)
 * Guest registers live in the CPU struct between blocks; inside a block the
 * allocator caches them in pool registers (write-back on demand or at sync
 * points: helper calls and block exits).
 *
 * Guest NZCV: an S-op leaves its result in host EFLAGS only until the next
 * IR op; if that op consumes flags (B.cond/CSEL/CCMP or a terminal branch)
 * it uses the host condition directly (with the ARM->x86 carry sense flip
 * for subtraction handled in the condition tables); otherwise the flags are
 * immediately recomposed into the architectural c->nzcv word. Terminals
 * entered with live host flags snapshot them with pushfq and each exit stub
 * recomposes NZCV before the (patchable) jump, so chained blocks always see
 * architectural state in memory. */
#include "ir.h"

#ifdef __x86_64__

#include <stdlib.h>
#include <string.h>

enum { RAX = 0, RCX, RDX, RBX, RSP_, RBP, RSI, RDI,
       R8, R9, R10, R11, R12, R13, R14, R15, HREG_N };

/* allocatable pool, preference order */
static const u8 pool[] = { RBX, RDI, R8, R9, R10, R11, R12, R13 };
#define POOL_N ((int)sizeof pool)

enum { FL_MEM, FL_SUB, FL_ADD, FL_LOGIC };

/* host condition codes */
enum { CC_O = 0, CC_NO, CC_B, CC_AE, CC_E, CC_NE, CC_BE, CC_A,
       CC_S, CC_NS, CC_P, CC_NP, CC_L, CC_GE, CC_LE, CC_G,
       CC_ALWAYS = 16, CC_NEVER = 17 };

#define OFF_X(n)   ((s32)(offsetof(CPU, x) + 8 * (n)))
#define OFF_SP     ((s32)offsetof(CPU, sp_el))
#define OFF_PC     ((s32)offsetof(CPU, pc))
#define OFF_CIP    ((s32)offsetof(CPU, cur_insn_pc))
#define OFF_NZCV   ((s32)offsetof(CPU, nzcv))
#define OFF_ICOUNT ((s32)offsetof(CPU, icount))

typedef struct BE {
    Emit *e;
    JitEnv *env;
    JBlock *b;
    s8  v2h[VREG_N];
    u8  h2v[HREG_N];
    u8  dirty[VREG_N];
    u32 lru[HREG_N];
    u32 stamp;
    int fl;                     /* FL_* lazy guest-flag location */
    /* guest V-register cache: xmm5-15 (xmm0-4 stay recipe scratch) */
    s8  vv2h[32];
    u8  vh2v[16];               /* 32 = free */
    u8  vdirty[32];
    u32 vlru[16];
} BE;

/* ---- raw emission ---- */

static void e8(Emit *e, u8 b) {
    if (UNLIKELY(e->rw >= e->rw_end)) { e->overflow = 1; return; }
    *e->rw++ = b;
    e->rx++;
}
static void e32(Emit *e, u32 v) {
    if (UNLIKELY(e->rw + 4 > e->rw_end)) { e->overflow = 1; return; }
    memcpy(e->rw, &v, 4);
    e->rw += 4; e->rx += 4;
}
static void e64(Emit *e, u64 v) {
    if (UNLIKELY(e->rw + 8 > e->rw_end)) { e->overflow = 1; return; }
    memcpy(e->rw, &v, 8);
    e->rw += 8; e->rx += 8;
}

static void rex(Emit *e, int w, int reg, int idx, int rm) {
    u8 r = (u8)(0x40 | (w << 3) | ((reg >> 3) << 2) | ((idx >> 3) << 1) |
                (rm >> 3));
    if (r != 0x40 || w) e8(e, r);
    else if (r == 0x40 && 0) e8(e, r);
}

/* reg-reg: opc reg, rm (direction per opcode) */
static void op_rr(Emit *e, int w, u8 opc, int reg, int rm) {
    rex(e, w, reg, 0, rm);
    e8(e, opc);
    e8(e, (u8)(0xC0 | ((reg & 7) << 3) | (rm & 7)));
}
static void op0f_rr(Emit *e, int w, u8 opc, int reg, int rm) {
    rex(e, w, reg, 0, rm);
    e8(e, 0x0F); e8(e, opc);
    e8(e, (u8)(0xC0 | ((reg & 7) << 3) | (rm & 7)));
}
/* [base + disp32] with base in {r14, r15} (low3 6/7: no SIB/RIP cases) */
static void op_rm(Emit *e, int w, u8 opc, int reg, int base, s32 disp) {
    rex(e, w, reg, 0, base);
    e8(e, opc);
    e8(e, (u8)(0x80 | ((reg & 7) << 3) | (base & 7)));
    e32(e, (u32)disp);
}
static void ld64(Emit *e, int reg, int base, s32 disp) { op_rm(e, 1, 0x8B, reg, base, disp); }
static void st64(Emit *e, int reg, int base, s32 disp) { op_rm(e, 1, 0x89, reg, base, disp); }
static void ld32(Emit *e, int reg, int base, s32 disp) { op_rm(e, 0, 0x8B, reg, base, disp); }
static void st32(Emit *e, int reg, int base, s32 disp) { op_rm(e, 0, 0x89, reg, base, disp); }

static void mov_ri(Emit *e, int w, int reg, u64 imm) {
    if (!w || imm <= 0xffffffffu) {              /* B8+r imm32 zero-extends */
        rex(e, 0, 0, 0, reg);
        e8(e, (u8)(0xB8 | (reg & 7)));
        e32(e, (u32)imm);
    } else {
        rex(e, 1, 0, 0, reg);
        e8(e, (u8)(0xB8 | (reg & 7)));
        e64(e, imm);
    }
}
static void mov_rr(Emit *e, int w, int dst, int src) {
    if (dst == src && w) return;
    op_rr(e, w, 0x8B, dst, src);
}

/* 81 /n imm32 group (n: 0 add, 1 or, 4 and, 5 sub, 6 xor, 7 cmp) */
static void alu_ri32(Emit *e, int w, int n, int rm, u32 imm) {
    rex(e, w, 0, 0, rm);
    e8(e, 0x81);
    e8(e, (u8)(0xC0 | (n << 3) | (rm & 7)));
    e32(e, imm);
}
static int imm_is_s32(u64 v) { return (u64)(s64)(s32)v == v; }

/* shifts: C1 /n imm8, D3 /n by cl (n: 4 shl, 5 shr, 7 sar, 1 ror) */
static void shift_ri(Emit *e, int w, int n, int rm, unsigned amt) {
    rex(e, w, 0, 0, rm);
    e8(e, 0xC1);
    e8(e, (u8)(0xC0 | (n << 3) | (rm & 7)));
    e8(e, (u8)amt);
}
static void shift_cl(Emit *e, int w, int n, int rm) {
    rex(e, w, 0, 0, rm);
    e8(e, 0xD3);
    e8(e, (u8)(0xC0 | (n << 3) | (rm & 7)));
}

static void jmp_to(Emit *e, const u8 *target) {
    s64 rel = target - (e->rx + 5);
    e8(e, 0xE9);
    e32(e, (u32)(s32)rel);
}
static u8 *jcc_fwd(Emit *e, int cc) {
    e8(e, 0x0F); e8(e, (u8)(0x80 | cc));
    u8 *pos = e->rw;
    e32(e, 0);
    return pos;
}
static u8 *jmp_fwd(Emit *e) {
    e8(e, 0xE9);
    u8 *pos = e->rw;
    e32(e, 0);
    return pos;
}
static void fwd_here(Emit *e, u8 *pos) {
    if (!pos || e->overflow) return;
    s32 rel = (s32)(e->rw - (pos + 4));
    memcpy(pos, &rel, 4);
}

/* Offset of the emission cursor from the code-cache base, for the bus-fault
 * fixup table (see JFixup): a host SIGBUS inside an inline access resumes at
 * that access's slow path. */
static u32 cache_off(BE *be) {
    return (u32)(be->e->rx - be->env->cache_rx);
}

/* ---- register allocator ---- */

static s32 v_home(int v) {
    if (v < 31) return OFF_X(v);
    if (v == VREG_SP) return OFF_SP;
    return -1;                                   /* temp: env spill slot */
}
static s32 v_spill(int v) { return (s32)(offsetof(JitEnv, tmp_spill) + 8 * (v - VREG_TMP0)); }

static void v_store(BE *be, int v) {
    int h = be->v2h[v];
    s32 off = v_home(v);
    if (off >= 0) st64(be->e, h, R14, off);
    else st64(be->e, h, R15, v_spill(v));
}
static void v_load_into(BE *be, int v, int h) {
    if (v == VREG_ZERO) { mov_ri(be->e, 0, h, 0); return; }   /* flag-safe */
    s32 off = v_home(v);
    if (off >= 0) ld64(be->e, h, R14, off);
    else ld64(be->e, h, R15, v_spill(v));
}

static void ra_unmap(BE *be, int v) {
    int h = be->v2h[v];
    if (h >= 0) { be->h2v[h] = VREG_N; be->v2h[v] = -1; be->dirty[v] = 0; }
}

static int ra_alloc(BE *be) {
    int best = -1;
    u32 best_lru = ~0u;
    for (int i = 0; i < POOL_N; i++) {
        int h = pool[i];
        if (be->h2v[h] == VREG_N) return h;
        if (be->lru[h] < best_lru) { best_lru = be->lru[h]; best = h; }
    }
    int v = be->h2v[best];
    if (be->dirty[v]) v_store(be, v);
    ra_unmap(be, v);
    return best;
}

static int ra_use(BE *be, int v) {
    int h = be->v2h[v];
    if (h < 0) {
        h = ra_alloc(be);
        v_load_into(be, v, h);
        be->v2h[v] = (s8)h;
        be->h2v[h] = (u8)v;
        be->dirty[v] = 0;
    }
    be->lru[h] = ++be->stamp;
    return h;
}

/* Destination register; prior value irrelevant. VREG_ZERO -> rax (discard). */
static int ra_def(BE *be, int v) {
    if (v == VREG_ZERO) return RAX;
    int h = be->v2h[v];
    if (h < 0) {
        h = ra_alloc(be);
        be->v2h[v] = (s8)h;
        be->h2v[h] = (u8)v;
    }
    be->dirty[v] = 1;
    be->lru[h] = ++be->stamp;
    return h;
}

/* V-register cache counterparts (defined after the SSE emitters). */
static void vra_sync_all(BE *be);
static void vra_inval_all(BE *be);
static void vra_slow_store_dirty(BE *be);
static void vra_slow_reload_all(BE *be);
static void vra_spill(BE *be, unsigned vn);
static void vra_flush(BE *be, unsigned vn);

/* Map without defining: the register keeps (or gets) a clean state, so a
 * bail-path slow_store_dirty never stores a not-yet-written value. Used by
 * the fused memory runs to pre-map load destinations outside the branch. */
static int ra_map_clean(BE *be, int v) {
    int h = be->v2h[v];
    if (h < 0) {
        h = ra_alloc(be);
        be->v2h[v] = (s8)h;
        be->h2v[h] = (u8)v;
        be->dirty[v] = 0;
    }
    be->lru[h] = ++be->stamp;
    return h;
}

static void sync_all(BE *be) {                   /* flag-safe (movs only) */
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && be->dirty[v]) { v_store(be, v); be->dirty[v] = 0; }
    vra_sync_all(be);
}
static void invalidate_all(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0) ra_unmap(be, v);
    vra_inval_all(be);
}

/* Caller-saved pool regs (rdi/r8-r11) don't survive a C call. A memory-op
 * slow path stores every dirty mapped vreg before its call (dirty bits kept:
 * the fast path never ran those stores) and reloads the caller-saved-mapped
 * ones after, so both paths converge on the same allocator state.
 * Callee-saved mappings (rbx/r12/r13) stay resident. */
static int is_caller_saved(int h) {
    return h == RDI || h == R8 || h == R9 || h == R10 || h == R11;
}
static void slow_store_dirty(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && be->dirty[v]) v_store(be, v);
    vra_slow_store_dirty(be);
}
static void slow_reload_clobbered(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && is_caller_saved(be->v2h[v]))
            v_load_into(be, v, be->v2h[v]);
    vra_slow_reload_all(be);                     /* xmm: all caller-saved */
}

/* ---- guest flags ---- */

/* Recompose NZCV from a pushfq snapshot in rax into c->nzcv.
 * x86 FLAGS: CF=0, ZF=6, SF=7, OF=11. Guest: N=31 Z=30 C=29 V=28.
 * kind FL_SUB inverts C (ARM C = NOT borrow). Clobbers rax/rcx/rdx. */
static void recompose_from_rax(BE *be, int kind) {
    Emit *e = be->e;
    mov_rr(e, 0, RCX, RAX);
    shift_ri(e, 0, 4, RCX, 24);                  /* SF->31, ZF->30 */
    alu_ri32(e, 0, 4, RCX, 0xC0000000u);         /* and */
    if (kind != FL_LOGIC) {
        mov_rr(e, 0, RDX, RAX);
        shift_ri(e, 0, 4, RDX, 29);              /* CF -> bit29 */
        alu_ri32(e, 0, 4, RDX, 0x20000000u);
        op_rr(e, 0, 0x09, RDX, RCX);             /* or rcx, rdx */
        mov_rr(e, 0, RDX, RAX);
        shift_ri(e, 0, 4, RDX, 17);              /* OF(11) -> bit28 */
        alu_ri32(e, 0, 4, RDX, 0x10000000u);
        op_rr(e, 0, 0x09, RDX, RCX);
        if (kind == FL_SUB)
            alu_ri32(e, 0, 6, RCX, 0x20000000u); /* xor: C = !borrow */
    }
    st32(e, RCX, R14, OFF_NZCV);
}

/* Live host flags -> c->nzcv now. */
static void materialize_flags(BE *be) {
    if (be->fl == FL_MEM) return;
    Emit *e = be->e;
    e8(e, 0x9C);                                 /* pushfq */
    e8(e, 0x58);                                 /* pop rax */
    recompose_from_rax(be, be->fl);
    be->fl = FL_MEM;
}

/* host cc for guest cond given current flag location; may emit setup code
 * (mem path clobbers rax/rcx/rdx). */
static int cond_setup(BE *be, unsigned cond) {
    static const s8 sub_cc[16] = { CC_E, CC_NE, CC_AE, CC_B, CC_S, CC_NS,
                                   CC_O, CC_NO, CC_A, CC_BE, CC_GE, CC_L,
                                   CC_G, CC_LE, CC_ALWAYS, CC_ALWAYS };
    static const s8 add_cc[16] = { CC_E, CC_NE, CC_B, CC_AE, CC_S, CC_NS,
                                   CC_O, CC_NO, -1, -1, CC_GE, CC_L,
                                   CC_G, CC_LE, CC_ALWAYS, CC_ALWAYS };
    static const s8 logic_cc[16] = { CC_E, CC_NE, CC_NEVER, CC_ALWAYS,
                                     CC_S, CC_NS, CC_NEVER, CC_ALWAYS,
                                     CC_NEVER, CC_ALWAYS, CC_NS, CC_S,
                                     CC_G, CC_LE, CC_ALWAYS, CC_ALWAYS };
    cond &= 15;
    if (be->fl == FL_SUB) return sub_cc[cond];
    if (be->fl == FL_LOGIC) return logic_cc[cond];
    if (be->fl == FL_ADD) {
        int cc = add_cc[cond];
        if (cc >= 0) return cc;
        materialize_flags(be);                   /* ADD-kind HI/LS: rare */
    }
    /* FL_MEM: evaluate from c->nzcv. Clobbers rax/rcx/rdx. */
    Emit *e = be->e;
    ld32(e, RAX, R14, OFF_NZCV);
    switch (cond) {
        case 0: case 1:                          /* EQ/NE: Z */
            /* test eax, PS_Z */
            rex(e, 0, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xC0); e32(e, PS_Z);
            return cond == 0 ? CC_NE : CC_E;
        case 2: case 3:                          /* HS/LO: C */
            rex(e, 0, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xC0); e32(e, PS_C);
            return cond == 2 ? CC_NE : CC_E;
        case 4: case 5:                          /* MI/PL: N */
            rex(e, 0, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xC0); e32(e, PS_N);
            return cond == 4 ? CC_NE : CC_E;
        case 6: case 7:                          /* VS/VC: V */
            rex(e, 0, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xC0); e32(e, PS_V);
            return cond == 6 ? CC_NE : CC_E;
        case 8: case 9:                          /* HI/LS: C && !Z */
            mov_rr(e, 0, RCX, RAX);
            alu_ri32(e, 0, 4, RCX, PS_C | PS_Z);
            alu_ri32(e, 0, 7, RCX, PS_C);        /* cmp rcx, C */
            return cond == 8 ? CC_E : CC_NE;
        case 10: case 11:                        /* GE/LT: N == V */
            mov_rr(e, 0, RCX, RAX);
            shift_ri(e, 0, 5, RCX, 3);           /* N (31) -> 28 */
            op_rr(e, 0, 0x31, RAX, RCX);         /* xor rcx, rax */
            rex(e, 0, 0, 0, RCX); e8(e, 0xF7); e8(e, 0xC1); e32(e, PS_V);
            return cond == 10 ? CC_E : CC_NE;
        case 12: case 13: {                      /* GT/LE: !Z && N==V */
            mov_rr(e, 0, RCX, RAX);
            shift_ri(e, 0, 5, RCX, 3);
            op_rr(e, 0, 0x31, RAX, RCX);         /* rcx = nzcv ^ (nzcv>>3) */
            alu_ri32(e, 0, 4, RCX, PS_V);        /* N^V at bit 28 */
            mov_rr(e, 0, RDX, RAX);
            alu_ri32(e, 0, 4, RDX, PS_Z);
            op_rr(e, 0, 0x09, RDX, RCX);         /* or rcx, rdx */
            return cond == 12 ? CC_E : CC_NE;    /* zero => GT */
        }
        default:                                 /* AL/NV */
            return CC_ALWAYS;
    }
}

/* What happens to the guest flags next, looking through flag-transparent
 * ops? FLAGS_CONSUMED: a cc-consumer or an exit's snapshot reads them —
 * keep them live in EFLAGS. FLAGS_DEAD: an S-op redefines them with only
 * transparent ops between — nobody can observe them, skip the NZCV
 * recompose entirely. FLAGS_UNKNOWN: the window is broken by an op that
 * may clobber EFLAGS or needs c->nzcv valid (mem probes, helpers, most
 * VOPs) — materialize now. The plain ADD/SUB/ADDI/SUBI ops count as
 * transparent because they switch to flag-preserving lea recipes inside a
 * CONSUMED window (and may clobber freely inside a DEAD one); the
 * mov-family ops emit no EFLAGS-touching instruction at all. */
enum { FLAGS_UNKNOWN, FLAGS_CONSUMED, FLAGS_DEAD };
static int flags_next_use(const IRBlock *ir, int i) {
    for (int k = i + 1; k < ir->n; k++) {
        const IROp *o = &ir->ops[k];
        switch (o->op) {
            case IRO_BCOND: case IRO_JMP: case IRO_JMPIND:
            case IRO_CSEL: case IRO_CSINC: case IRO_CSINV: case IRO_CSNEG:
            case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI:
            case IRO_ADC: case IRO_ADCS: case IRO_SBC: case IRO_SBCS:
                return FLAGS_CONSUMED;
            case IRO_ADDS: case IRO_SUBS: case IRO_ADDIS: case IRO_SUBIS:
            case IRO_ANDS: case IRO_BICS: case IRO_ANDIS:
                return FLAGS_DEAD;               /* redefined unread */
            case IRO_NOP: case IRO_MOVI: case IRO_MOV:
            case IRO_CPULD: case IRO_CPUST:
            case IRO_ADD: case IRO_SUB: case IRO_ADDI: case IRO_SUBI:
                continue;                        /* flag-transparent */
            case IRO_VOP:
                if (o->aux & VF_READF) return FLAGS_CONSUMED;
                if (o->aux & VF_SETF) return FLAGS_DEAD;    /* FCMP */
                return FLAGS_UNKNOWN;
            default:
                return FLAGS_UNKNOWN;
        }
    }
    return FLAGS_CONSUMED;
}
static void set_flags_state(BE *be, const IRBlock *ir, int i, int kind) {
    be->fl = kind;
    if (flags_next_use(ir, i) == FLAGS_UNKNOWN) materialize_flags(be);
}

/* Host CF = guest C (inverted for the sbb forms: ARM SBC = a + ~b + C =
 * x86 sbb with CF = !C) from the current lazy flag location. Clobbers rax
 * on the FL_MEM path; only flag-transparent movs may follow before the
 * adc/sbb that consumes CF. */
static void carry_to_host(BE *be, int inverted) {
    Emit *e = be->e;
    switch (be->fl) {
        case FL_ADD:                             /* CF == C after addition */
            if (inverted) e8(e, 0xF5);           /* cmc */
            break;
        case FL_SUB:                             /* CF == borrow == !C */
            if (!inverted) e8(e, 0xF5);
            break;
        case FL_LOGIC:                           /* and/test: CF == 0 == C */
            if (inverted) e8(e, 0xF9);           /* stc */
            break;
        default:                                 /* FL_MEM: C is nzcv<29> */
            ld32(e, RAX, R14, OFF_NZCV);
            e8(e, 0x0F); e8(e, 0xBA); e8(e, 0xE0); e8(e, 29);   /* bt eax,29 */
            if (inverted) e8(e, 0xF5);
            break;
    }
}

/* lea dst, [base + idx + disp8]: a flag-free 3-operand add. mod01+SIB
 * uniformly (covers the r12/r13 special cases; the pool has no rsp). */
static void lea_bid(Emit *e, int dst, int base, int idx, int disp) {
    rex(e, 1, dst, idx, base);
    e8(e, 0x8D);
    e8(e, (u8)(0x44 | ((dst & 7) << 3)));
    e8(e, (u8)(((idx & 7) << 3) | (base & 7)));
    e8(e, (u8)disp);
}

/* ---- common op patterns ---- */

/* dst = a; returns host reg of dst primed with a's value. Safe for d == a.
 * (Callers must not read `b` through this reg before using it.) */
static int def_alias(BE *be, int d, int a, int w) {
    if (d == a) {
        int h = ra_use(be, a);
        /* A write to XZR is discarded, so it must never become dirty: the
         * flag would make v_store spill VREG_ZERO, and VREG_ZERO's spill
         * index is tmp_spill[3] — the slot a fused memory run parks its
         * base VA in. Reachable as `tst xzr, #imm` / `cmn xzr, xzr` with
         * dead flags, where ra_def's own VREG_ZERO guard is bypassed
         * because d == a takes this branch. */
        if (d != VREG_ZERO) be->dirty[d] = 1;
        if (!w) mov_rr(be->e, 0, h, h);          /* zext32 in place */
        return h;
    }
    int ha = ra_use(be, a);
    int hd = ra_def(be, d);
    if (hd != ha) mov_rr(be->e, w, hd, ha);
    if (!w && hd == ha) mov_rr(be->e, 0, hd, hd);
    else if (!w) mov_rr(be->e, 0, hd, hd);
    return hd;
}

/* icount += n as one RMW add. Clobbers EFLAGS — every call site (exit
 * stubs after their recompose, fault arms after their jcc, the atomic and
 * NaN-gate fast paths after theirs) has dead host flags here. */
static void icount_add(BE *be, u32 n) {
    if (!n) return;
    Emit *e = be->e;
    op_rm(e, 1, 0x81, 0, R14, OFF_ICOUNT);       /* add qword [r14+d], n */
    e32(e, n);
}

/* Exit stub: [recompose flags][icount][patch site: store pc, return eid].
 * stub_kind: FL_* to recompose from the rax pushfq snapshot, FL_MEM = none. */
static void exit_stub(BE *be, int slot, u64 target_pc, int stub_kind,
                      u32 icnt) {
    Emit *e = be->e;
    JBlock *b = be->b;
    if (stub_kind != FL_MEM) recompose_from_rax(be, stub_kind);
    icount_add(be, icnt);
    b->exit_pc[slot] = target_pc;
    b->exit_off[slot] = (u32)(e->rx - b->code);
    /* movabs rax, pc ; mov [r14+pc], rax  (first 5 bytes are the patch) */
    rex(e, 1, 0, 0, RAX);
    e8(e, 0xB8);
    e64(e, target_pc);
    st64(e, RAX, R14, OFF_PC);
    u32 eid = ((u32)(b - be->env->arena) << 1) | (u32)slot;
    mov_ri(e, 0, RAX, eid);
    jmp_to(e, be->env->epilogue_rx);
}

/* Non-chainable exit: eid = EXIT_NONE (c->pc already correct). */
static void exit_plain(BE *be, u32 icnt) {
    icount_add(be, icnt);
    mov_ri(be->e, 0, RAX, JIT_EXIT_NONE);
    jmp_to(be->e, be->env->epilogue_rx);
}

/* ---- thunks ---- */

int be_available(void) { return 1; }

void be_emit_thunks(Emit *e, JitEnv *env) {
    env->enter = (u32 (*)(JitEnv *, const u8 *))(uintptr_t)e->rx;
    e8(e, 0x55);                                  /* push rbp */
    e8(e, 0x53);                                  /* push rbx */
    e8(e, 0x41); e8(e, 0x54);                     /* push r12 */
    e8(e, 0x41); e8(e, 0x55);                     /* push r13 */
    e8(e, 0x41); e8(e, 0x56);                     /* push r14 */
    e8(e, 0x41); e8(e, 0x57);                     /* push r15 */
    e8(e, 0x48); e8(e, 0x83); e8(e, 0xEC); e8(e, 0x08);   /* sub rsp, 8 */
    e8(e, 0x49); e8(e, 0x89); e8(e, 0xFF);        /* mov r15, rdi */
    op_rm(e, 1, 0x8B, R14, RDI, (s32)offsetof(JitEnv, c)); /* mov r14,[rdi+c] */
    e8(e, 0xFF); e8(e, 0xE6);                     /* jmp rsi */

    env->epilogue_rx = e->rx;
    e8(e, 0x48); e8(e, 0x83); e8(e, 0xC4); e8(e, 0x08);   /* add rsp, 8 */
    e8(e, 0x41); e8(e, 0x5F);                     /* pop r15 */
    e8(e, 0x41); e8(e, 0x5E);                     /* pop r14 */
    e8(e, 0x41); e8(e, 0x5D);                     /* pop r13 */
    e8(e, 0x41); e8(e, 0x5C);                     /* pop r12 */
    e8(e, 0x5B);                                  /* pop rbx */
    e8(e, 0x5D);                                  /* pop rbp */
    e8(e, 0xC3);                                  /* ret */
}

/* mov [rdi + disp] form used above needs RDI base: modrm rm=7 mod10, fine. */

/* ---- block body ---- */

/* ALU op with 3 registers: hd = ha OP hb (n = 81-group /n and rr opcode). */
static void alu_rrr(BE *be, int w, u8 opc_rr, int commut, int d, int a, int b) {
    Emit *e = be->e;
    int ha = ra_use(be, a);
    int hb = ra_use(be, b);
    if (d == b && d != a && !commut) {
        mov_rr(e, 1, RAX, ha);
        op_rr(e, w, opc_rr ^ 0x02, RAX, hb);      /* 8B-direction: reg<-rm */
        int hd = ra_def(be, d);
        mov_rr(e, w, hd, RAX);
        return;
    }
    if (d == b && d != a && commut) {
        int hd = ra_use(be, b);
        be->dirty[d] = 1;
        op_rr(e, w, opc_rr, ha, hd);              /* hd op= ha */
        if (!w) mov_rr(e, 0, hd, hd);
        return;
    }
    int hd = def_alias(be, d, a, 1);
    hb = ra_use(be, b);
    op_rr(e, w, opc_rr, hb, hd);                  /* hd op= hb */
    if (!w) mov_rr(be->e, 0, hd, hd);
}

/* S-variants must leave the flag-setting op LAST; result width w applies to
 * both flags and the zero-extension, so use the w-sized op and rely on the
 * 32-bit form zero-extending its destination. */
static void alu_rrr_S(BE *be, int w, u8 opc_rr, int d, int a, int b) {
    Emit *e = be->e;
    int ha = ra_use(be, a);
    int hb = ra_use(be, b);
    if (d == VREG_ZERO) {
        /* compare/test only */
        if (opc_rr == 0x29) { op_rr(e, w, 0x39, hb, ha); return; } /* cmp */
        if (opc_rr == 0x21) { op_rr(e, w, 0x85, hb, ha); return; } /* test */
        /* adds/adcs/sbcs xzr: no compare form, compute into rax */
        mov_rr(e, 1, RAX, ha);
        op_rr(e, w, opc_rr, hb, RAX);
        return;
    }
    if (d == b && d != a) {
        mov_rr(e, 1, RAX, ha);
        op_rr(e, w, opc_rr ^ 0x02, RAX, hb);
        int hd = ra_def(be, d);
        mov_rr(e, w, hd, RAX);                    /* mov: flags preserved */
        return;
    }
    int hd = def_alias(be, d, a, 1);
    hb = ra_use(be, b);
    op_rr(e, w, opc_rr, hb, hd);
}

/* Load a vreg's memory home into host reg `h` (scratch use around mem ops). */
static void ld_home(BE *be, int h, int v) {
    Emit *e = be->e;
    if (v == VREG_ZERO) { mov_ri(e, 0, h, 0); return; }
    s32 off = v_home(v);
    if (off >= 0) ld64(e, h, R14, off);
    else ld64(e, h, R15, v_spill(v));
}

#define OFF_V(n) ((s32)(offsetof(CPU, v) + 16 * (n)))

/* lea reg, [base + disp32] — general base, incl. the SIB-needing r12. */
static void lea_rbd(Emit *e, int reg, int base, s32 disp) {
    rex(e, 1, reg, 0, base);
    e8(e, 0x8D);
    if ((base & 7) == 4) {                       /* rsp/r12 base: SIB */
        e8(e, (u8)(0x84 | ((reg & 7) << 3)));
        e8(e, 0x24);
    } else {
        e8(e, (u8)(0x80 | ((reg & 7) << 3) | (base & 7)));
    }
    e32(e, (u32)disp);
}

/* mov [rdx], reg of size 1<<szlog, for any pool reg (REX for dil/r8b..). */
static void st_rdx_sized(Emit *e, unsigned szlog, int reg) {
    if (szlog == 1) e8(e, 0x66);
    u8 r = (u8)(0x40 | ((szlog == 3) << 3) | (((reg >> 3) & 1) << 2));
    if (r != 0x40 || (szlog == 0 && reg >= 4)) e8(e, r);
    e8(e, szlog == 0 ? 0x88 : 0x89);
    e8(e, (u8)(((reg & 7) << 3) | 2));           /* [rdx] */
}

/* Inline memory op. Fast path = probe + access only: operands and results
 * live in allocated host registers, and no guest state is written. The slow
 * branch carries the whole cost instead: it stores every dirty mapped vreg
 * (keeping the dirty bits — the fast path never ran those stores), calls the
 * helper, and reloads the caller-saved-mapped vregs so both paths converge
 * on the allocator state that emission continues with. Loads converge with
 * the (zero/sign-extended) value in rax; a single post-merge ra_def commits
 * it to the destination's register. */
static void emit_mem(BE *be, const IRBlock *ir, int i) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    int is_st = (o->op == IRO_ST || o->op == IRO_STV);
    int is_v  = (o->op == IRO_LDV || o->op == IRO_STV);
    unsigned desc = o->aux;
    unsigned szlog = is_v ? MDESC_VSZL(desc) : o->cc;
    unsigned sz = 1u << szlog;                   /* 1..16 bytes */
    int need = is_st ? 2 /*PTE_W*/ : 1 /*PTE_R*/;

    /* Vector mem ops work on c->v[] directly: an LDV overwrites the
     * register (spill first so a fault still sees the old value; the
     * mapping would then be stale — drop it), an STV reads it (make
     * memory current, the mapping stays valid). */
    if (o->op == IRO_LDV) vra_spill(be, MDESC_RT(desc));
    else if (o->op == IRO_STV) vra_flush(be, MDESC_RT(desc));

    materialize_flags(be);                       /* the probe needs EFLAGS */
    int hb = -1;
    if (o->op == IRO_ST) hb = ra_use(be, o->b);  /* store operand */
    int ha = ra_use(be, o->a);                   /* base */

    /* va = base + offset  -> rsi (scratch; also the slow call's arg1) */
    if (o->imm == 0) {
        mov_rr(e, 1, RSI, ha);
    } else if (imm_is_s32(o->imm)) {
        lea_rbd(e, RSI, ha, (s32)o->imm);
    } else {
        mov_ri(e, 1, RSI, o->imm);
        op_rr(e, 1, 0x03, RSI, ha);              /* add rsi, ha */
    }

    u8 *slow0 = NULL, *slow1 = NULL, *slow2 = NULL;
    if (UNLIKELY(be->env->slowmem)) {
        slow0 = jmp_fwd(e);                      /* bisection: helper always */
        goto fast;
    }
    /* cmp-page -> rax ; ent ptr -> rcx. The tag compare uses the LAST byte's
     * page while the index (and the stored tag) come from the first byte's:
     * a page-crossing access mismatches and falls to the slow helper, so no
     * separate cross gate is needed. (TBI-tagged VAs mismatch the stripped
     * stored tag the same way.) */
    if (sz > 1) lea_rbd(e, RAX, RSI, (s32)(sz - 1));
    else        mov_rr(e, 1, RAX, RSI);
    shift_ri(e, 1, 5, RAX, 12);                /* page of the last byte */
    mov_rr(e, 0, RCX, RSI);
    shift_ri(e, 0, 5, RCX, 12);
    alu_ri32(e, 0, 4, RCX, A64_DTLB_ENTRIES - 1);
    shift_ri(e, 0, 4, RCX, 4);
    op_rm(e, 1, 0x03, RCX, R15, (s32)offsetof(JitEnv, dtlb));  /* add rcx,[r15+dtlb] */
    op_rm(e, 1, 0x39, RAX, RCX, 0);            /* cmp [rcx], rax (tag) */
    slow1 = jcc_fwd(e, CC_NE);
    ld64(e, RDX, RCX, 8);                      /* pte -> rdx */
    e8(e, 0xF6); e8(e, 0xC2); e8(e, (u8)need); /* test dl, need */
    slow2 = jcc_fwd(e, CC_E);
    alu_ri32(e, 1, 4, RDX, 0xFFFFFFF8u);       /* and rdx, ~7 : host base */
    mov_rr(e, 0, RAX, RSI);
    alu_ri32(e, 0, 4, RAX, 0xfff);             /* page offset */
    op_rr(e, 1, 0x01, RAX, RDX);               /* add rdx, rax : host ptr */

fast:;
    u32 fix_fast = cache_off(be);
    /* ---- fast access (loads: result -> rax; ptr = rdx) ---- */
    if (!is_v) {
        if (is_st) {
            st_rdx_sized(e, szlog, hb);
        } else {
            int sign = MDESC_SIGN(desc), is64 = MDESC_IS64(desc);
            if (szlog == 3) {                                    /* mov rax,[rdx] */
                e8(e, 0x48); e8(e, 0x8B); e8(e, 0x02);
            } else if (sign && is64) {
                if (szlog == 2) { e8(e, 0x48); e8(e, 0x63); e8(e, 0x02); }   /* movsxd rax */
                else { e8(e, 0x48); e8(e, 0x0F); e8(e, szlog == 0 ? 0xBE : 0xBF); e8(e, 0x02); }
            } else if (sign) {                                   /* movsx eax (zext to 64) */
                e8(e, 0x0F); e8(e, szlog == 0 ? 0xBE : 0xBF); e8(e, 0x02);
            } else if (szlog == 2) {                             /* mov eax,[rdx] (zext) */
                e8(e, 0x8B); e8(e, 0x02);
            } else {                                             /* movzx eax */
                e8(e, 0x0F); e8(e, szlog == 0 ? 0xB6 : 0xB7); e8(e, 0x02);
            }
        }
    } else {
        unsigned vd = MDESC_RT(desc);
        unsigned vszl = MDESC_VSZL(desc);        /* 0..4 = 1..16 bytes */
        if (is_st) {
            ld64(e, RAX, R14, OFF_V(vd));         /* low 8 bytes of Vd */
            switch (vszl) {                       /* store low `bytes` */
                case 0: e8(e, 0x88); e8(e, 0x02); break;              /* mov [rdx],al */
                case 1: e8(e, 0x66); e8(e, 0x89); e8(e, 0x02); break; /* mov [rdx],ax */
                case 2: e8(e, 0x89); e8(e, 0x02); break;             /* mov [rdx],eax */
                default: e8(e, 0x48); e8(e, 0x89); e8(e, 0x02); break;/* mov [rdx],rax */
            }
            if (vszl == 4) {                      /* Q: high 8 bytes */
                ld64(e, RAX, R14, OFF_V(vd) + 8);
                e8(e, 0x48); e8(e, 0x89); e8(e, 0x42); e8(e, 0x08);
            }
        } else {
            switch (vszl) {                       /* zero-extended into rax */
                case 0: e8(e, 0x0F); e8(e, 0xB6); e8(e, 0x02); break; /* movzx eax,byte */
                case 1: e8(e, 0x0F); e8(e, 0xB7); e8(e, 0x02); break; /* movzx eax,word */
                case 2: e8(e, 0x8B); e8(e, 0x02); break;             /* mov eax,[rdx] */
                default: e8(e, 0x48); e8(e, 0x8B); e8(e, 0x02); break;/* mov rax,[rdx] */
            }
            st64(e, RAX, R14, OFF_V(vd));
            if (vszl == 4) {                      /* Q: second half */
                e8(e, 0x48); e8(e, 0x8B); e8(e, 0x42); e8(e, 0x08);
                st64(e, RAX, R14, OFF_V(vd) + 8);
            } else {
                mov_ri(e, 0, RAX, 0);
                st64(e, RAX, R14, OFF_V(vd) + 8); /* clear the high half */
            }
        }
    }
    u8 *done = jmp_fwd(e);

    /* ---- slow path ---- */
    fwd_here(e, slow0);
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    be_fixup_add(be->env, fix_fast, cache_off(be));
    slow_store_dirty(be);                       /* dirty bits kept: see above */
    s32 hoff;
    if (o->op == IRO_ST) {                      /* jit_st(c, va, val, pc, desc) */
        mov_rr(e, 1, RDX, hb);                  /* before rdi is clobbered */
        mov_rr(e, 1, RDI, R14);
        mov_ri(e, 1, RCX, o->imm2pc);
        mov_ri(e, 0, R8, desc);
        hoff = (s32)offsetof(JitEnv, helper_st);
    } else {                                    /* ld/ldv/stv(c, va, pc, desc) */
        mov_rr(e, 1, RDI, R14);
        mov_ri(e, 1, RDX, o->imm2pc);
        mov_ri(e, 0, RCX, desc);
        hoff = o->op == IRO_LD ? (s32)offsetof(JitEnv, helper_ld)
             : o->op == IRO_LDV ? (s32)offsetof(JitEnv, helper_ldv)
                                : (s32)offsetof(JitEnv, helper_stv);
    }
    ld64(e, RAX, R15, hoff);
    e8(e, 0xFF); e8(e, 0xD0);                   /* call rax */
    op_rr(e, 0, 0x85, RAX, RAX);               /* test eax,eax */
    u8 *ok = jcc_fwd(e, CC_E);
    exit_plain(be, o->icnt);                   /* faulted: leave the block
                                                 * (all dirty state stored) */
    fwd_here(e, ok);
    slow_reload_clobbered(be);                  /* helper ate caller-saved */
    if (o->op == IRO_LD && o->dst != VREG_ZERO)
        ld_home(be, RAX, o->dst);               /* helper committed to home */
    fwd_here(e, done);

    /* ---- merge: commit a load to its register ---- */
    if (o->op == IRO_LD && o->dst != VREG_ZERO) {
        int hd = ra_def(be, o->dst);
        mov_rr(e, 1, hd, RAX);
    }
    be->fl = FL_MEM;
}

/* ---- fused memory runs (probe sharing) ---- */

static int fuse_enabled(void) {
    static int v = -1;
    if (v < 0) v = getenv("A64_JIT_NOFUSE") == NULL;
    return v;
}

#define FUSE_VA_SLOT ((s32)(offsetof(JitEnv, tmp_spill) + 24))

/* [rdx + disp] modrm tail (disp8/32) */
static void modrm_rdx_disp(Emit *e, int reg, s32 d) {
    if (d >= -128 && d <= 127) {
        e8(e, (u8)(0x42 | ((reg & 7) << 3)));
        e8(e, (u8)d);
    } else {
        e8(e, (u8)(0x82 | ((reg & 7) << 3)));
        e32(e, (u32)d);
    }
}
static void st_rdx_disp(Emit *e, unsigned szlog, int reg, s32 d) {
    if (szlog == 1) e8(e, 0x66);
    u8 r = (u8)(0x40 | ((szlog == 3) << 3) | (((reg >> 3) & 1) << 2));
    if (r != 0x40 || (szlog == 0 && reg >= 4)) e8(e, r);
    e8(e, szlog == 0 ? 0x88 : 0x89);
    modrm_rdx_disp(e, reg, d);
}
static void ld_rdx_disp(Emit *e, const IROp *p, int reg, s32 d) {
    unsigned szlog = p->cc;
    int sign = MDESC_SIGN(p->aux), is64 = MDESC_IS64(p->aux);
    if (szlog == 3) {
        rex(e, 1, reg, 0, RDX); e8(e, 0x8B);
    } else if (sign && is64) {
        rex(e, 1, reg, 0, RDX);
        if (szlog == 2) e8(e, 0x63);                     /* movsxd */
        else { e8(e, 0x0F); e8(e, szlog == 0 ? 0xBE : 0xBF); }
    } else if (sign) {
        rex(e, 0, reg, 0, RDX);
        e8(e, 0x0F); e8(e, szlog == 0 ? 0xBE : 0xBF);    /* movsx r32 */
    } else if (szlog == 2) {
        rex(e, 0, reg, 0, RDX); e8(e, 0x8B);
    } else {
        rex(e, 0, reg, 0, RDX);
        e8(e, 0x0F); e8(e, szlog == 0 ? 0xB6 : 0xB7);    /* movzx */
    }
    modrm_rdx_disp(e, reg, d);
}

/* k same-base constant-offset accesses behind ONE span-checked probe
 * (LDP/STP shapes, DC ZVA's eight stores, prologue spill runs). The bail
 * path (miss / span page-cross / TBI / perm — or A64_JIT_SLOWMEM) re-runs
 * every access through its helper in program order, each with its own
 * baked pc and fault exit, so a fault at access j leaves accesses < j
 * committed and j's destination unwritten, exactly like the interpreter.
 * va0 survives the helper calls in a JitEnv spill slot. */
static void emit_mem_run(BE *be, const IRBlock *ir, int i, int k) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    int is_st = (o->op == IRO_ST);
    int need = is_st ? 2 : 1;
    int hb[8], hd[8];

    s64 lo = (s64)o->imm, hi = lo + (s64)(1u << o->cc);
    for (int t = 1; t < k; t++) {
        s64 plo = (s64)ir->ops[i + t].imm;
        s64 phi = plo + (s64)(1u << ir->ops[i + t].cc);
        if (plo < lo) lo = plo;
        if (phi > hi) hi = phi;
    }

    materialize_flags(be);                       /* the probe needs EFLAGS */
    int ha = ra_use(be, o->a);
    for (int t = 0; t < k; t++) {
        const IROp *p = &ir->ops[i + t];
        if (is_st) hb[t] = ra_use(be, p->b);
        else hd[t] = (p->dst == VREG_ZERO) ? -1 : ra_map_clean(be, p->dst);
    }

    /* rsi = va0 = base + lo */
    if (lo == 0) mov_rr(e, 1, RSI, ha);
    else if (lo >= INT32_MIN && lo <= INT32_MAX) lea_rbd(e, RSI, ha, (s32)lo);
    else { mov_ri(e, 1, RSI, (u64)lo); op_rr(e, 1, 0x03, RSI, ha); }

    u8 *slow0 = NULL, *slow1 = NULL, *slow2 = NULL;
    if (UNLIKELY(be->env->slowmem)) {
        slow0 = jmp_fwd(e);
        goto fast;
    }
    /* the probe compares the SPAN's last byte's page against the tag
     * stored for va0's page: any crossing of the whole run mismatches */
    lea_rbd(e, RAX, RSI, (s32)(hi - lo - 1));
    shift_ri(e, 1, 5, RAX, 12);
    mov_rr(e, 0, RCX, RSI);
    shift_ri(e, 0, 5, RCX, 12);
    alu_ri32(e, 0, 4, RCX, A64_DTLB_ENTRIES - 1);
    shift_ri(e, 0, 4, RCX, 4);
    op_rm(e, 1, 0x03, RCX, R15, (s32)offsetof(JitEnv, dtlb));
    op_rm(e, 1, 0x39, RAX, RCX, 0);
    slow1 = jcc_fwd(e, CC_NE);
    ld64(e, RDX, RCX, 8);
    e8(e, 0xF6); e8(e, 0xC2); e8(e, (u8)need);
    slow2 = jcc_fwd(e, CC_E);
    alu_ri32(e, 1, 4, RDX, 0xFFFFFFF8u);
    mov_rr(e, 0, RAX, RSI);
    alu_ri32(e, 0, 4, RAX, 0xfff);
    op_rr(e, 1, 0x01, RAX, RDX);                 /* rdx = host ptr of va0 */

fast:;
    u32 fix_fast = cache_off(be);
    for (int t = 0; t < k; t++) {
        const IROp *p = &ir->ops[i + t];
        s32 d = (s32)((s64)p->imm - lo);
        if (is_st) st_rdx_disp(e, (unsigned)p->cc, hb[t], d);
        else       ld_rdx_disp(e, p, hd[t] < 0 ? RAX : hd[t], d);
    }
    u8 *done = jmp_fwd(e);

    /* ---- bail: the helpers, in program order ---- */
    fwd_here(e, slow0);
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    be_fixup_add(be->env, fix_fast, cache_off(be));
    slow_store_dirty(be);
    st64(e, RSI, R15, FUSE_VA_SLOT);
    for (int t = 0; t < k; t++) {
        const IROp *p = &ir->ops[i + t];
        s32 d = (s32)((s64)p->imm - lo);
        ld64(e, RSI, R15, FUSE_VA_SLOT);
        if (d) lea_rbd(e, RSI, RSI, d);
        mov_rr(e, 1, RDI, R14);
        if (is_st) {
            ld_home(be, RDX, p->b);              /* homes are current */
            mov_ri(e, 1, RCX, p->imm2pc);
            mov_ri(e, 0, R8, p->aux);
        } else {
            mov_ri(e, 1, RDX, p->imm2pc);
            mov_ri(e, 0, RCX, p->aux);
        }
        ld64(e, RAX, R15, is_st ? (s32)offsetof(JitEnv, helper_st)
                                : (s32)offsetof(JitEnv, helper_ld));
        e8(e, 0xFF); e8(e, 0xD0);
        op_rr(e, 0, 0x85, RAX, RAX);
        u8 *okk = jcc_fwd(e, CC_E);
        exit_plain(be, p->icnt);
        fwd_here(e, okk);
    }
    slow_reload_clobbered(be);
    if (!is_st)
        for (int t = 0; t < k; t++)              /* helpers committed home */
            if (hd[t] >= 0) v_load_into(be, ir->ops[i + t].dst, hd[t]);
    fwd_here(e, done);

    if (!is_st)
        for (int t = 0; t < k; t++)
            if (hd[t] >= 0) be->dirty[ir->ops[i + t].dst] = 1;
    be->fl = FL_MEM;
}

/* ---- inline vector / scalar FP (IRO_VOP; exec_fpsimd.c is the reference:
 * the interpreter computes FP with host C float/double, i.e. SSE2 on this
 * host, so the same SSE2 ops match it bit-for-bit) ---- */

/* SSE op xmm_dst, [r14+disp] / xmm_dst, xmm_src. pfx: 0, 0x66, 0xF2, 0xF3.
 * xmm8-15 encode via REX (after the mandatory prefix). */
static void sse_mem(Emit *e, u8 pfx, u8 opc, int xreg, s32 disp) {
    if (pfx) e8(e, pfx);
    e8(e, (u8)(0x41 | ((xreg >> 3) << 2)));      /* REX.B r14 (+.R xmm8+) */
    e8(e, 0x0F); e8(e, opc);
    e8(e, (u8)(0x80 | ((xreg & 7) << 3) | (R14 & 7)));
    e32(e, (u32)disp);
}
static void sse_rr(Emit *e, u8 pfx, u8 opc, int xdst, int xsrc) {
    if (pfx) e8(e, pfx);
    u8 r = (u8)(0x40 | ((xdst >> 3) << 2) | (xsrc >> 3));
    if (r != 0x40) e8(e, r);
    e8(e, 0x0F); e8(e, opc);
    e8(e, (u8)(0xC0 | ((xdst & 7) << 3) | (xsrc & 7)));
}
/* SSE4.1 three-byte-opcode form: 66 0F 38 opc /r */
static void sse38_rr(Emit *e, u8 opc, int xdst, int xsrc) {
    e8(e, 0x66);
    u8 r = (u8)(0x40 | ((xdst >> 3) << 2) | (xsrc >> 3));
    if (r != 0x40) e8(e, r);
    e8(e, 0x0F); e8(e, 0x38); e8(e, opc);
    e8(e, (u8)(0xC0 | ((xdst & 7) << 3) | (xsrc & 7)));
}
/* ---- F16C (VEX-encoded half<->single vector converts) ----
 * Only emitted behind cpu_has_f16c(); AVX (hence VEX) is implied by F16C.
 * 3-byte VEX (0xC4): byte1 = R X B m-mmmm (R/X/B are the INVERTED high bits
 * of ModRM.reg / SIB.index / ModRM.rm; map 2=0F38, 3=0F3A). byte2 = 0x79:
 * W0, vvvv=1111 (no third operand), L=0 (128-bit), pp=01 (mandatory 0x66). */
static void vex3(Emit *e, int map, int reg, int rm) {
    e8(e, 0xC4);
    e8(e, (u8)((((reg >> 3) & 1) ? 0 : 0x80) |   /* R = ~reg[3]  */
               0x40 |                             /* X = 1 (unused) */
               (((rm >> 3) & 1) ? 0 : 0x20) |    /* B = ~rm[3]   */
               (u8)map));
    e8(e, 0x79);
}
/* vcvtph2ps xmm_dst, [r14+disp]: widen 4 packed halves (low 64b) -> 4 singles */
static void vcvtph2ps_m(Emit *e, int xdst, s32 disp) {
    vex3(e, 0x02, xdst, R14);
    e8(e, 0x13);
    e8(e, (u8)(0x80 | ((xdst & 7) << 3) | (R14 & 7)));   /* mod=10, disp32 */
    e32(e, (u32)disp);
}
/* vcvtps2ph xmm_dst, xmm_src, imm8: narrow 4 singles -> 4 halves (low 64b of
 * dst). imm bit2=0 selects rounding from imm[1:0]; 0 = round-to-nearest-even.
 * Encoding is store-shaped: ModRM.reg = source, ModRM.rm = dest. */
static void vcvtps2ph_r(Emit *e, int xdst, int xsrc, u8 imm) {
    vex3(e, 0x03, xsrc, xdst);
    e8(e, 0x1D);
    e8(e, (u8)(0xC0 | ((xsrc & 7) << 3) | (xdst & 7)));
    e8(e, imm);
}
/* cvtsi2ss/sd xmm, r32/r64 */
static void cvtsi2f(Emit *e, int dbl, int w64, int xdst, int rsrc) {
    e8(e, dbl ? 0xF2 : 0xF3);
    u8 r = (u8)(0x40 | ((w64 ? 1 : 0) << 3) | (rsrc >> 3));
    if (r != 0x40) e8(e, r);
    e8(e, 0x0F); e8(e, 0x2A);
    e8(e, (u8)(0xC0 | (xdst << 3) | (rsrc & 7)));
}
/* cvttsd2si r32/r64, xmm (truncating; the only fp->int form we emit) */
static void cvttd2si(Emit *e, int w64, int rdst, int xsrc) {
    e8(e, 0xF2);
    u8 r = (u8)(0x40 | ((w64 ? 1 : 0) << 3) | ((rdst >> 3) << 2));
    if (r != 0x40) e8(e, r);
    e8(e, 0x0F); e8(e, 0x2C);
    e8(e, (u8)(0xC0 | ((rdst & 7) << 3) | xsrc));
}
/* movq xmm, r64 */
static void movq_xr(Emit *e, int xdst, int rsrc) {
    e8(e, 0x66);
    e8(e, (u8)(0x48 | (rsrc >> 3)));
    e8(e, 0x0F); e8(e, 0x6E);
    e8(e, (u8)(0xC0 | (xdst << 3) | (rsrc & 7)));
}
/* movq/movd rax, xmm (scalar result extraction; movd zero-extends) */
static void movq_rax_x(Emit *e, int dbl, int xsrc) {
    e8(e, 0x66);
    if (dbl) e8(e, 0x48);
    e8(e, 0x0F); e8(e, 0x7E);
    e8(e, (u8)(0xC0 | (xsrc << 3) | RAX));
}
/* psll/psrl/psra xmm, imm8: opc 71/72/73 per size, /ext selects the op. */
static void sse_shift_i(Emit *e, u8 opc, unsigned ext, int xreg, u8 imm) {
    e8(e, 0x66);
    if (xreg >= 8) e8(e, 0x41);
    e8(e, 0x0F); e8(e, opc);
    e8(e, (u8)(0xC0 | (ext << 3) | (xreg & 7)));
    e8(e, imm);
}

/* mov qword [r14+disp], imm32 (sign-extended; imm is tiny here). */
static void st_imm_r14(Emit *e, s32 disp, u32 imm) {
    e8(e, 0x49); e8(e, 0xC7);
    e8(e, (u8)(0x80 | (R14 & 7)));
    e32(e, (u32)disp); e32(e, imm);
}
static void st_imm8_r14(Emit *e, s32 disp, u8 imm) {   /* mov byte [r14+d],i */
    e8(e, 0x41); e8(e, 0xC6);
    e8(e, (u8)(0x80 | (R14 & 7)));
    e32(e, (u32)disp); e8(e, imm);
}
/* Zero-extending lane load [r14+disp] -> rax, and the sized store back. */
static void ld_lane_rax(Emit *e, unsigned size, s32 disp) {
    switch (size) {
        case 0: e8(e, 0x41); e8(e, 0x0F); e8(e, 0xB6); break;
        case 1: e8(e, 0x41); e8(e, 0x0F); e8(e, 0xB7); break;
        case 2: e8(e, 0x41); e8(e, 0x8B); break;
        default: e8(e, 0x49); e8(e, 0x8B); break;
    }
    e8(e, (u8)(0x80 | (R14 & 7)));
    e32(e, (u32)disp);
}
static void st_lane_rax(Emit *e, unsigned size, s32 disp) {
    switch (size) {
        case 0: e8(e, 0x41); e8(e, 0x88); break;
        case 1: e8(e, 0x66); e8(e, 0x41); e8(e, 0x89); break;
        case 2: e8(e, 0x41); e8(e, 0x89); break;
        default: e8(e, 0x49); e8(e, 0x89); break;
    }
    e8(e, (u8)(0x80 | (R14 & 7)));
    e32(e, (u32)disp);
}

/* Baseline is SSE2 (x86-64); some vector ops need SSSE3/SSE4.1/SSE4.2 (any
 * Intel/AMD core since ~2008) — probed once, helper fallback without them.
 * Debug: A64_JIT_SSE=2 forces the baseline answers, proving every gated
 * recipe's decline/fallback path on a modern host. */
static int sse_forced_baseline(void) {
    static int v = -1;
    if (v < 0) {
        const char *s = getenv("A64_JIT_SSE");
        v = (s && atoi(s) == 2);
    }
    return v;
}
static int cpu_has_sse41(void) {
    static int v = -1;
    if (v < 0) v = __builtin_cpu_supports("sse4.1");
    return v && !sse_forced_baseline();
}
static int cpu_has_ssse3(void) {
    static int v = -1;
    if (v < 0) v = __builtin_cpu_supports("ssse3");
    return v && !sse_forced_baseline();
}
static int cpu_has_sse42(void) {
    static int v = -1;
    if (v < 0) v = __builtin_cpu_supports("sse4.2");
    return v && !sse_forced_baseline();
}
/* F16C: half<->single vector convert (vcvtph2ps / vcvtps2ph). The gate for the
 * whole FP16 surface — without it every half encoding stays an interpreter
 * helper. A64_JIT_SSE=2 forces it off, exercising that fallback. */
static int cpu_has_f16c(void) {
    static int v = -1;
    if (v < 0) v = __builtin_cpu_supports("f16c");
    return v && !sse_forced_baseline();
}
/* FMA3: the gate for inlining the fused-multiply families (scalar FMADD,
 * vector FMLA/FMLS, the by-element forms). The interpreter computes them
 * with __builtin_fma — correctly rounded no matter how libm gets there —
 * and vfmadd* is the same unique answer for finite results; NaNs are gated.
 * Without it those encodings stay interpreter helpers. */
static int cpu_has_fma(void) {
    static int v = -1;
    if (v < 0) v = __builtin_cpu_supports("fma");
    return v && !sse_forced_baseline();
}

/* SSE4.1 three-byte-opcode 0F 3A form (roundss/sd/ps/pd): 66 0F 3A opc /r ib */
static void sse3a_rr(Emit *e, u8 opc, int xdst, int xsrc, u8 imm) {
    e8(e, 0x66);
    u8 r = (u8)(0x40 | ((xdst >> 3) << 2) | (xsrc >> 3));
    if (r != 0x40) e8(e, r);
    e8(e, 0x0F); e8(e, 0x3A); e8(e, opc);
    e8(e, (u8)(0xC0 | ((xdst & 7) << 3) | (xsrc & 7)));
    e8(e, imm);
}

/* FMA3 231-form (VEX.DDS.128.66.0F38): xdst = ±(xsrc1 * xsrc2) ± xdst per
 * the opcode (B8/B9 fmadd, BA/BB fmsub, BC/BD fnmadd, BE/BF fnmsub; even =
 * packed, odd = scalar). W selects double. Only emitted behind
 * cpu_has_fma(); FMA implies AVX, hence VEX. */
static void fma231_rr(Emit *e, u8 opc, int W, int xdst, int xsrc1, int xsrc2) {
    e8(e, 0xC4);
    e8(e, (u8)((((xdst >> 3) & 1) ? 0 : 0x80) |  /* R = ~reg[3]  */
               0x40 |                            /* X = 1 (unused) */
               (((xsrc2 >> 3) & 1) ? 0 : 0x20) | /* B = ~rm[3]   */
               0x02));                           /* map 0F38 */
    e8(e, (u8)(((W & 1) << 7) | ((~xsrc1 & 0xf) << 3) | 0x01)); /* L=0 pp=66 */
    e8(e, opc);
    e8(e, (u8)(0xC0 | ((xdst & 7) << 3) | (xsrc2 & 7)));
}

/* SSE op xmm, [r15+disp] (JitEnv-relative). */
static void sse_mem15(Emit *e, u8 pfx, u8 opc, int xreg, s32 disp) {
    if (pfx) e8(e, pfx);
    e8(e, (u8)(0x41 | ((xreg >> 3) << 2)));      /* REX.B: r15 base */
    e8(e, 0x0F); e8(e, opc);
    e8(e, (u8)(0x80 | ((xreg & 7) << 3) | (R15 & 7)));
    e32(e, (u32)disp);
}

/* xreg = a translate-time 128-bit constant, staged through env->vconst
 * (pshufb LUTs, byte-shift masks; the cache has no data pools). */
static void emit_const128(BE *be, u64 lo, u64 hi, int xreg) {
    Emit *e = be->e;
    mov_ri(e, 1, RAX, lo);
    st64(e, RAX, R15, (s32)offsetof(JitEnv, vconst));
    mov_ri(e, 1, RAX, hi);
    st64(e, RAX, R15, (s32)offsetof(JitEnv, vconst) + 8);
    sse_mem15(e, 0xF3, 0x6F, xreg, (s32)offsetof(JitEnv, vconst));
}

/* ---- guest V-register cache ----
 * Block-local LRU cache of guest V registers in xmm5-15; xmm0-4 remain the
 * recipes' fixed scratch. Recipes fetch operands with vop_src (a movdqa
 * from the cached register, or the old movdqu from c->v[] under
 * A64_JIT_NOVRA) and commit full-vector results with vop_dst; lane/GPR-
 * crossing recipes instead spill the named registers and run their
 * memory-based code unchanged. All xmm registers are caller-saved, so
 * helper-calling slow paths store the dirty set before the call (dirty
 * bits kept) and reload every mapped register after, converging with the
 * fast path exactly like the GPR scheme. */
#define VXPOOL_LO 5

static int vra_enabled(void) {
    static int v = -1;
    if (v < 0) v = getenv("A64_JIT_NOVRA") == NULL;
    return v;
}
static void vld_q(BE *be, int hx, unsigned vn) { /* movdqu hx, c->v[vn] */
    sse_mem(be->e, 0xF3, 0x6F, hx, OFF_V(vn));
}
static void vst_q(BE *be, int hx, unsigned vn) {
    sse_mem(be->e, 0xF3, 0x7F, hx, OFF_V(vn));
}
static int vra_alloc(BE *be) {
    int best = -1;
    u32 oldest = ~0u;
    for (int h = VXPOOL_LO; h < 16; h++) {
        if (be->vh2v[h] == 32) return h;
        if (be->vlru[h] < oldest) { oldest = be->vlru[h]; best = h; }
    }
    unsigned v = be->vh2v[best];
    if (be->vdirty[v]) vst_q(be, best, v);
    be->vv2h[v] = -1;
    be->vdirty[v] = 0;
    be->vh2v[best] = 32;
    return best;
}
static int vra_use(BE *be, unsigned vn) {
    int h = be->vv2h[vn];
    if (h < 0) {
        h = vra_alloc(be);
        vld_q(be, h, vn);
        be->vv2h[vn] = (s8)h;
        be->vh2v[h] = (u8)vn;
        be->vdirty[vn] = 0;
    }
    be->vlru[h] = ++be->stamp;
    return h;
}
static int vra_def(BE *be, unsigned vn) {
    int h = be->vv2h[vn];
    if (h < 0) {
        h = vra_alloc(be);
        be->vv2h[vn] = (s8)h;
        be->vh2v[h] = (u8)vn;
    }
    be->vdirty[vn] = 1;
    be->vlru[h] = ++be->stamp;
    return h;
}
/* memory made current; mapping kept (STV reads c->v[] on its fast path) */
static void vra_flush(BE *be, unsigned vn) {
    if (be->vv2h[vn] >= 0 && be->vdirty[vn]) {
        vst_q(be, be->vv2h[vn], vn);
        be->vdirty[vn] = 0;
    }
}
/* memory made current and the mapping dropped (legacy recipes / LDV) */
static void vra_spill(BE *be, unsigned vn) {
    int h = be->vv2h[vn];
    if (h < 0) return;
    if (be->vdirty[vn]) vst_q(be, h, vn);
    be->vv2h[vn] = -1;
    be->vdirty[vn] = 0;
    be->vh2v[h] = 32;
}
static void vra_sync_all(BE *be) {
    for (unsigned v = 0; v < 32; v++) vra_flush(be, v);
}
static void vra_inval_all(BE *be) {
    for (unsigned v = 0; v < 32; v++)
        if (be->vv2h[v] >= 0) {
            be->vh2v[(int)be->vv2h[v]] = 32;
            be->vv2h[v] = -1;
            be->vdirty[v] = 0;
        }
}
static void vra_slow_store_dirty(BE *be) {
    for (unsigned v = 0; v < 32; v++)
        if (be->vv2h[v] >= 0 && be->vdirty[v]) vst_q(be, be->vv2h[v], v);
}
static void vra_slow_reload_all(BE *be) {
    for (unsigned v = 0; v < 32; v++)
        if (be->vv2h[v] >= 0) vld_q(be, be->vv2h[v], v);
}

/* Recipe operand fetch: xscratch = guest Vn. */
static void vop_src(BE *be, int xscratch, unsigned vn) {
    if (!vra_enabled()) { vld_q(be, xscratch, vn); return; }
    sse_rr(be->e, 0x66, 0x6F, xscratch, vra_use(be, vn));
}
/* Recipe result commit: Vd = xscratch; !q zero-extends first (the scalar /
 * 64-bit forms' architectural clear-high). */
static void vop_dst(BE *be, int xscratch, unsigned vn, int q) {
    if (!q) sse_rr(be->e, 0xF3, 0x7E, xscratch, xscratch);  /* movq zext */
    if (!vra_enabled()) { vst_q(be, xscratch, vn); return; }
    sse_rr(be->e, 0x66, 0x6F, vra_def(be, vn), xscratch);
}

/* Per-host capability/fidelity table (see ir.h VC_*). */
int be_vop_ok(unsigned vclass, u32 insn) {
    unsigned size = (insn >> 22) & 3, U = (insn >> 29) & 1;
    unsigned opc3 = (insn >> 11) & 0x1f;
    switch (vclass) {
        case VC_BITW: case VC_ADDSUB: case VC_MOVI: case VC_COPY:
        case VC_F1:
        case VC_FCSEL: case VC_FMOVI: case VC_FMOVG:
        case VC_CVTIF: case VC_FCVT:
            return 1;
        case VC_F3:
            /* scalar FMADD family: fused only — vfmadd231; an unfused
             * mul+add would diverge from the interpreter's __builtin_fma */
            return cpu_has_fma();
        case VC_CVTFI:
            /* FCVTZS/FCVTZU inline branches AROUND cvttsd2si on the NaN and
             * saturation paths (and loads 0 for small-negative unsigned), so
             * the host invalid/inexact flags the FPSR accumulation relies on
             * never fire there. The interpreter helper raises them by hand;
             * the a64 backend's native fcvtzs is architecturally exact and
             * keeps its inline. */
            return 0;
        case VC_FCMP: case VC_FCCMP:             /* half needs F16C to widen */
            return (((insn >> 22) & 3) == 3) ? cpu_has_f16c() : 1;
        case VC_FCVTH:                           /* FP16 converts: need F16C */
            return cpu_has_f16c();
        case VC_H1:                              /* scalar half 1-src: F16C */
            return cpu_has_f16c();
        case VC_H2: {                            /* half 2-src; MAX/MIN decline */
            unsigned opc = (insn >> 12) & 0xf;
            if (opc >= 4 && opc <= 7) return 0;
            return cpu_has_f16c();
        }
        case VC_H3:
            /* half FMADD: the interpreter computes in double and narrows once;
             * x86 has no double->half, and double->single->half re-introduces
             * a double-rounding error (a tiny addend lost below half a single
             * ULP on a half-midpoint product). Keep the interpreter helper. */
            return 0;
        case VC_VH3: case VC_VHCM:               /* vector half: F16C */
            return cpu_has_f16c();
        case VC_VH2M: {
            /* the FRINT keys the frontend now sends are a64-only (native
             * half replay); the widen/op/narrow recipe covers the rest */
            unsigned hkey = (U << 6) | (((insn >> 23) & 1) << 5) |
                            ((insn >> 12) & 0x1f);
            if (hkey == 0x18 || hkey == 0x38 || hkey == 0x58 ||
                hkey == 0x19 || hkey == 0x39 || hkey == 0x59 || hkey == 0x79)
                return 0;
            return cpu_has_f16c();
        }
        case VC_F2: {
            /* FMUL/FDIV/FADD/FSUB/FNMUL inline; FMAX/FMIN/FMAXNM/FMINNM (opc
             * 4-7) keep the interpreter helper — maxss/minss get ARM's NaN
             * propagation and +0/-0 ordering wrong (matches the a64 backend). */
            unsigned f2opc = (insn >> 12) & 0xf;
            return !(f2opc >= 4 && f2opc <= 7);
        }
        case VC_CM3:
            /* pcmpeq/pcmpgt b/h/s; unsigned and GE/TST forms via sign-flip
             * and inversion. 64-bit lanes: CMEQ/CMTST via the pcmpeqd+
             * pshufd composite (SSE2), the ordered ones via pcmpgtq. */
            if (size <= 2) return 1;
            return opc3 == 0x11 ? 1 : cpu_has_sse42();
        case VC_MINMAX:
            /* SSE2 natives: unsigned byte, signed halfword; the rest are
             * SSE4.1 pm{in,ax}{s,u}{b,w,d}. */
            if ((size == 0 && U) || (size == 1 && !U)) return 1;
            return cpu_has_sse41();
        case VC_SHIFTI: {
            unsigned immh = (insn >> 19) & 0xf;
            unsigned sz = (immh & 8) ? 3 : (immh & 4) ? 2 : (immh & 2) ? 1 : 0;
            if (opc3 == 0x10) return 1;          /* SHRN(2): psrl + narrow */
            if (opc3 == 0x14)                    /* S/USHLL(2): widen */
                return U ? 1 : sz <= 1;          /* no 64-bit arith shift */
            if (sz == 0)                         /* bytes: w-shift + mask */
                return opc3 == 0x0a ? !U : U;    /* SSHR/SSRA.b: helper */
            if ((opc3 == 0x00 || opc3 == 0x02) && !U && sz == 3)
                return 0;                        /* no psraq (SSHR/SSRA.2d) */
            return 1;
        }
        case VC_S3S:
            return 1;                            /* SSE2 / GPR recipes */
        case VC_SSHIFTI:
            return 1;                            /* psllq/psrlq; sar for S */
        case VC_2MISC:
            switch ((U << 5) | ((insn >> 12) & 0x1f)) {
                case 0x08: case 0x28: case 0x09:
                case 0x29: case 0x0a:            /* compares with #0 */
                    return size <= 2;
                case 0x0b:                       /* ABS */
                    return size <= 2 && cpu_has_ssse3();
                case 0x2b:                       /* NEG (psub from zero) */
                    return 1;
                case 0x25:                       /* NOT / RBIT.v (size 1) */
                    return size == 0 ? 1 : cpu_has_ssse3();
                case 0x12:                       /* XTN / XTN2 */
                    return size <= 2;
                case 0x00:                       /* REV64: pshufb perm */
                    return cpu_has_ssse3();
                case 0x20:                       /* REV32 */
                    return cpu_has_ssse3();
                case 0x01:                       /* REV16 */
                    return cpu_has_ssse3();
                case 0x05:                       /* CNT: nibble LUT */
                    return cpu_has_ssse3();
                case 0x02:                       /* SADDLP: b/h widen-add;
                                                  * s->d needs 64-bit sar */
                    return size <= 1;
                case 0x22:                       /* UADDLP */
                    return size <= 2;
                default:
                    return 0;                    /* CLZ/CLS/SHLL */
            }
        case VC_VF3S:
            if (opc3 == 0x19 && !U) return cpu_has_fma();  /* FMLA/FMLS */
            return 1;                            /* arith, FADDP, compares */
        case VC_VFCM:
            return 1;
        case VC_VMISCF: {
            /* FABS/FNEG/FSQRT/FCM#0 are SSE2; FRINT* needs roundps (SSE4.1)
             * and FRINTA has no ties-away encoding; the estimates are
             * a64-only (architected table). */
            unsigned key = (U << 6) | (((insn >> 23) & 1) << 5) |
                           ((insn >> 12) & 0x1f);
            switch (key) {
                case 0x2f: case 0x6f: case 0x7f:
                case 0x2c: case 0x6c: case 0x2d: case 0x6d: case 0x2e:
                    return 1;
                case 0x18: case 0x38: case 0x19: case 0x39:
                case 0x59: case 0x79:
                    return cpu_has_sse41();
                default:                         /* FRINTA, FRECPE/FRSQRTE */
                    return 0;
            }
        }
        case VC_FRINTS: {
            /* roundss/sd; FRINTA (opc 0xc) has no ties-away imm and the
             * half form has no native op — both stay helpers. */
            unsigned ropc = (insn >> 15) & 0x3f;
            if (((insn >> 22) & 3) == 3 || ropc == 0xc) return 0;
            return cpu_has_sse41();
        }
        case VC_FPAIRS:
            return 1;                            /* ADDP.d / FADDP: SSE2 */
        case VC_FELEM: {
            /* FMUL by element: pshufd broadcast + mulps. FMLA/FMLS need
             * FMA3. FMULX (0*inf special case) and the half form decline. */
            unsigned eopc = (insn >> 12) & 0xf;
            if (((insn >> 22) & 3) == 0) return 0;
            if (eopc == 0x9) return U ? 0 : 1;   /* FMULX : FMUL */
            return cpu_has_fma();                /* FMLA / FMLS */
        }
        case VC_FSELEM: {
            unsigned eopc = (insn >> 12) & 0xf;
            if (eopc == 0x9) return U ? 0 : 1;   /* FMULX : FMUL */
            return cpu_has_fma();                /* FMLA / FMLS */
        }
        case VC_PAIRI:
            if (opc3 == 0x17) return 1;          /* ADDP, all sizes */
            if (size == 0) return 1;             /* byte min/max: SSE2 */
            return cpu_has_sse41();              /* h/s via pmin/maxsd */
        case VC_MUL3:
            /* pmullw / pmulld; bytes via widen+pmullw+pack */
            return size == 2 ? cpu_has_sse41() : 1;
        case VC_ACROSS: {
            unsigned opc17 = (insn >> 12) & 0x1f;
            if (opc17 == 0x1b) return 1;         /* ADDV: padd ladder */
            if ((size == 0 && U) || (size == 1 && !U))
                return 1;                        /* SSE2 pmin/max forms */
            return cpu_has_sse41();
        }
        default:
            return 0;
    }
}

/* NaN-result fallback for the self-counting scalar-FP classes (VC_F2 arith,
 * VC_F3): discard the inline result and re-run the insn via jit_exec1
 * (which handles icount and events). Mirrors emit_atomic's slow path; the
 * fast path stored its result and bumped icount before jumping over this. */
/* res_scratch >= 0: a cached (V-allocated) NaN-gated class converges with
 * its result in that scratch register — the slow arm reloads it from the
 * interpreter's committed c->v[rd] so the post-merge vop_dst commits the
 * same value on both paths. slow2 is an optional second entry (a pre-op
 * gate like the FRINTX/I rounding-mode check). */
static void vop_slowpath2(BE *be, const IROp *o, u8 *slow, u8 *slow2,
                          int res_scratch) {
    Emit *e = be->e;
    u8 *done = jmp_fwd(e);
    fwd_here(e, slow);
    fwd_here(e, slow2);
    slow_store_dirty(be);
    mov_rr(e, 1, RDI, R14);                      /* jit_exec1(c, pc, insn) */
    rex(e, 1, 0, 0, RSI); e8(e, (u8)(0xB8 | RSI)); e64(e, o->imm2pc);
    mov_ri(e, 0, RDX, (u32)o->imm);
    ld64(e, RAX, R15, (s32)offsetof(JitEnv, helper_exec1));
    e8(e, 0xFF); e8(e, 0xD0);
    op_rr(e, 0, 0x85, RAX, RAX);
    u8 *ok = jcc_fwd(e, CC_E);
    exit_plain(be, o->icnt);
    fwd_here(e, ok);
    slow_reload_clobbered(be);
    if (res_scratch >= 0)
        vld_q(be, res_scratch, (u32)o->imm & 31);
    fwd_here(e, done);
}
static void vop_slowpath(BE *be, const IROp *o, u8 *slow, int res_scratch) {
    vop_slowpath2(be, o, slow, NULL, res_scratch);
}

/* FRINTX/FRINTI gate: the interpreter honors guest FPCR.RMode in software
 * while the inline roundss below hardwires round-to-nearest (MXCSR never
 * changes). A nonzero RMode takes the helper. Clobbers eax and EFLAGS. */
static u8 *rmode_gate(BE *be) {
    Emit *e = be->e;
    ld32(e, RAX, R14, (s32)offsetof(CPU, fpcr));
    alu_ri32(e, 0, 4, RAX, 3u << 22);            /* and eax, RMode mask */
    return jcc_fwd(e, CC_NE);
}

/* Which classes run with cached operands/results (full-vector recipes with
 * the result in one scratch register)? The rest — lane and GPR-crossing
 * shapes, scalar FP, the rax-composed narrows — spill the named registers
 * and keep their memory-based recipes. */
static int vop_cached(const IROp *o) {
    u32 insn = (u32)o->imm;
    if (!vra_enabled()) return 0;
    switch (VC(o->aux)) {
        case VC_BITW: case VC_ADDSUB: case VC_CM3: case VC_MINMAX:
        case VC_MUL3: case VC_SSHIFTI: case VC_S3S:
        case VC_VF3S: case VC_VFCM: case VC_VMISCF: case VC_FELEM:
            return 1;
        case VC_SHIFTI:
            return ((insn >> 11) & 0x1f) != 0x10;    /* SHRN(2): legacy */
        case VC_2MISC:
            return ((insn >> 12) & 0x1f) != 0x12;    /* XTN(2): legacy */
        case VC_PAIRI:
            return (insn >> 30) & 1;                 /* !Q: rax-composed */
        default:
            return 0;
    }
}

/* One IRO_VOP. xmm0-4 and rax/rcx are scratch; operands come from the
 * V-register cache (vop_src) for the cached classes. Only FCMP touches
 * guest flags. */
static void emit_vop(BE *be, const IRBlock *ir, int i, const IROp *o) {
    Emit *e = be->e;
    u32 insn = (u32)o->imm;
    unsigned rd = insn & 31, rn = (insn >> 5) & 31, rm = (insn >> 16) & 31;
    unsigned vclass = VC(o->aux);

    if (!vop_cached(o)) {
        /* legacy memory-based recipe: make c->v[] current and unmapped
         * for every register the recipe may read or write */
        if (vclass == VC_MOVI) {
            vra_spill(be, VMOVI_RD(o->aux));
        } else if (vclass == VC_FMOVI) {
            vra_spill(be, (o->aux >> 8) & 31);
        } else {
            vra_spill(be, rn);
            vra_spill(be, rm);
            vra_spill(be, rd);
            if (vclass == VC_F3) vra_spill(be, (insn >> 10) & 31);
        }
    }

    switch (vclass) {
        case VC_BITW: {
            unsigned U = (insn >> 29) & 1, size = (insn >> 22) & 3;
            unsigned Q = (insn >> 30) & 1;
            vop_src(be, 0, rn);                              /* xmm0 = Vn */
            vop_src(be, 1, rm);                              /* xmm1 = Vm */
            if (!U) switch (size) {
                case 0: sse_rr(e, 0x66, 0xDB, 0, 1); break;  /* AND: pand */
                case 1: sse_rr(e, 0x66, 0xDF, 1, 0);         /* BIC: pandn */
                        sse_rr(e, 0xF3, 0x6F, 0, 1); break;  /*  (res in 1) */
                case 2: sse_rr(e, 0x66, 0xEB, 0, 1); break;  /* ORR: por */
                default:                                     /* ORN */
                        sse_rr(e, 0x66, 0x76, 2, 2);         /* ones: pcmpeqd */
                        sse_rr(e, 0x66, 0xEF, 1, 2);         /* not Vm */
                        sse_rr(e, 0x66, 0xEB, 0, 1); break;  /* or */
            } else {
                /* EOR / BSL / BIT / BIF — all from d ^ ((d^a)&mask) forms */
                if (size == 0) {
                    sse_rr(e, 0x66, 0xEF, 0, 1);             /* EOR: pxor */
                } else {
                    vop_src(be, 2, rd);                      /* xmm2 = Vd */
                    if (size == 1) {                         /* BSL:
                                                              * m^((m^n)&d) */
                        sse_rr(e, 0x66, 0xEF, 0, 1);         /* x0 = n^m */
                        sse_rr(e, 0x66, 0xDB, 0, 2);         /* &= d */
                        sse_rr(e, 0x66, 0xEF, 0, 1);         /* ^= m */
                    } else if (size == 2) {                  /* BIT:
                                                              * d^((d^n)&m) */
                        sse_rr(e, 0x66, 0xEF, 0, 2);         /* x0 = n^d */
                        sse_rr(e, 0x66, 0xDB, 0, 1);         /* &= m */
                        sse_rr(e, 0x66, 0xEF, 0, 2);         /* ^= d */
                    } else {                                 /* BIF:
                                                              * d^((d^n)&~m) */
                        sse_rr(e, 0x66, 0xEF, 2, 0);         /* x2 = d^n */
                        sse_rr(e, 0x66, 0xDF, 1, 2);         /* x1=~m&(d^n) */
                        vop_src(be, 0, rd);
                        sse_rr(e, 0x66, 0xEF, 0, 1);         /* d ^ that */
                    }
                }
            }
            vop_dst(be, 0, rd, (int)Q);
            break;
        }
        case VC_ADDSUB: {
            unsigned U = (insn >> 29) & 1, size = (insn >> 22) & 3;
            unsigned Q = (insn >> 30) & 1;
            static const u8 padd[4] = { 0xFC, 0xFD, 0xFE, 0xD4 };
            static const u8 psub[4] = { 0xF8, 0xF9, 0xFA, 0xFB };
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            sse_rr(e, 0x66, U ? psub[size] : padd[size], 0, 1);
            vop_dst(be, 0, rd, (int)Q);
            break;
        }
        case VC_CM3: {
            unsigned U = (insn >> 29) & 1, size = (insn >> 22) & 3;
            unsigned Q = (insn >> 30) & 1, opc3 = (insn >> 11) & 0x1f;
            static const u8 pcmpeq[3] = { 0x74, 0x75, 0x76 };
            static const u8 pcmpgt[3] = { 0x64, 0x65, 0x66 };
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            if (size == 3) {
                /* 64-bit lanes: CMEQ via the pcmpeqd + swapped-pair pand
                 * composite; CMTST on top of it; the ordered compares via
                 * pcmpgtq (SSE4.2), unsigned by sign-flipping both. */
                if (opc3 == 0x11) {
                    /* CMEQ: n ==32 m in both halves of each 64-lane.
                     * CMTST: (n&m) ==32 0 in both halves, then invert. */
                    if (!U) {
                        sse_rr(e, 0x66, 0xDB, 0, 1);      /* pand */
                        sse_rr(e, 0x66, 0xEF, 1, 1);      /* zero */
                    }
                    sse_rr(e, 0x66, 0x76, 0, 1);          /* pcmpeqd */
                    sse_rr(e, 0x66, 0x70, 1, 0); e8(e, 0xB1);   /* swap */
                    sse_rr(e, 0x66, 0xDB, 0, 1);          /* both halves */
                    if (!U) {
                        sse_rr(e, 0x66, 0x76, 1, 1);      /* ones */
                        sse_rr(e, 0x66, 0xEF, 0, 1);      /* != 0 */
                    }
                } else {
                    if (U) {                     /* flip both sign bits */
                        sse_rr(e, 0x66, 0x76, 2, 2);      /* ones */
                        sse_shift_i(e, 0x73, 6, 2, 63);   /* psllq 63 */
                        sse_rr(e, 0x66, 0xEF, 0, 2);
                        sse_rr(e, 0x66, 0xEF, 1, 2);
                    }
                    if (opc3 == 0x06) {          /* CMGT/CMHI: n > m */
                        sse38_rr(e, 0x37, 0, 1); /* pcmpgtq */
                    } else {                     /* CMGE/CMHS: ~(m > n) */
                        sse38_rr(e, 0x37, 1, 0);
                        sse_rr(e, 0x66, 0x76, 0, 0);      /* ones */
                        sse_rr(e, 0x66, 0xEF, 0, 1);
                    }
                }
                vop_dst(be, 0, rd, (int)Q);
                break;
            }
            if (U && opc3 != 0x11) {
                /* CMHI/CMHS: flip sign bits, then signed compare */
                sse_rr(e, 0x66, 0x76, 2, 2);     /* ones */
                if (size == 0) {                 /* 0x80 bytes */
                    sse_shift_i(e, 0x71, 6, 2, 15);
                    sse_rr(e, 0x66, 0x63, 2, 2); /* packsswb: -32768 -> -128 */
                } else if (size == 1) {
                    sse_shift_i(e, 0x71, 6, 2, 15);
                } else {
                    sse_shift_i(e, 0x72, 6, 2, 31);
                }
                sse_rr(e, 0x66, 0xEF, 0, 2);
                sse_rr(e, 0x66, 0xEF, 1, 2);
            }
            if (opc3 == 0x11 && U) {             /* CMEQ */
                sse_rr(e, 0x66, pcmpeq[size], 0, 1);
            } else if (opc3 == 0x11) {           /* CMTST: ~((n & m) == 0) */
                sse_rr(e, 0x66, 0xDB, 0, 1);     /* pand */
                sse_rr(e, 0x66, 0xEF, 1, 1);     /* zero */
                sse_rr(e, 0x66, pcmpeq[size], 0, 1);
                sse_rr(e, 0x66, 0x76, 1, 1);     /* ones */
                sse_rr(e, 0x66, 0xEF, 0, 1);     /* invert */
            } else if (opc3 == 0x06) {           /* CMGT / CMHI */
                sse_rr(e, 0x66, pcmpgt[size], 0, 1);
            } else {                             /* CMGE/CMHS: ~(m > n) */
                sse_rr(e, 0x66, pcmpgt[size], 1, 0);
                sse_rr(e, 0x66, 0x76, 0, 0);     /* ones */
                sse_rr(e, 0x66, 0xEF, 0, 1);     /* x0 = ~x1 */
            }
            vop_dst(be, 0, rd, (int)Q);
            break;
        }
        case VC_PAIRI: {
            /* Pairwise ADDP / S,U MAXP/MINP: split each source into even
             * and odd lanes widened one step (zero- or sign-extended per
             * signedness), run the op at the wider width, and pack the two
             * per-source results back side by side — the packed layout is
             * exactly ARM's [pairs-of-Vn | pairs-of-Vm]. glibc's strlen /
             * memchr inner loops are UMINP/UMAXP.16b. */
            unsigned U = (insn >> 29) & 1, size = (insn >> 22) & 3;
            unsigned Q = (insn >> 30) & 1, opc3 = (insn >> 11) & 0x1f;
            int add = (opc3 == 0x17), mx = (opc3 == 0x14);
            int res = 2;
            if (Q) {
                vop_src(be, 0, rn);
                vop_src(be, 1, rm);
            } else {                             /* legacy (rax-composed) */
                sse_mem(e, 0xF3, 0x6F, 0, OFF_V(rn));
                sse_mem(e, 0xF3, 0x6F, 1, OFF_V(rm));
            }
            if (size == 3) {                     /* ADDP.2d */
                sse_rr(e, 0x66, 0x6F, 2, 0);
                sse_rr(e, 0x66, 0x6C, 2, 1);     /* punpcklqdq: n0 m0 */
                sse_rr(e, 0x66, 0x6D, 0, 1);     /* punpckhqdq: n1 m1 */
                sse_rr(e, 0x66, 0xD4, 2, 0);     /* paddq */
            } else if (size == 2) {              /* .4s via shufps */
                sse_rr(e, 0x66, 0x6F, 2, 0);
                sse_rr(e, 0, 0xC6, 2, 1); e8(e, 0x88);   /* evens */
                sse_rr(e, 0, 0xC6, 0, 1); e8(e, 0xDD);   /* odds */
                if (add) sse_rr(e, 0x66, 0xFE, 2, 0);
                else sse38_rr(e, (u8)(0x38 | (mx ? 4 : 0) | (U ? 2 : 0) | 1),
                              2, 0);
            } else {
                /* b/h: widen both sources' even/odd lanes, op, pack */
                u8 shl = size ? 0x72 : 0x71;     /* pslld/w family */
                u8 shift = size ? 16 : 8;
                int sgn = (!add && !U);
                sse_rr(e, 0x66, 0x6F, 2, 0);
                sse_rr(e, 0x66, 0x6F, 3, 1);
                sse_shift_i(e, shl, 6, 2, shift);            /* evens << */
                sse_shift_i(e, shl, 6, 3, shift);
                sse_shift_i(e, shl, sgn ? 4 : 2, 2, shift);  /* back (ext) */
                sse_shift_i(e, shl, sgn ? 4 : 2, 3, shift);
                sse_shift_i(e, shl, sgn ? 4 : 2, 0, shift);  /* odds */
                sse_shift_i(e, shl, sgn ? 4 : 2, 1, shift);
                if (add) {
                    sse_rr(e, 0x66, size ? 0xFE : 0xFD, 2, 0);
                    sse_rr(e, 0x66, size ? 0xFE : 0xFD, 3, 1);
                } else if (size == 0) {          /* fits signed words */
                    sse_rr(e, 0x66, mx ? 0xEE : 0xEA, 2, 0);
                    sse_rr(e, 0x66, mx ? 0xEE : 0xEA, 3, 1);
                } else {                         /* fits signed dwords */
                    sse38_rr(e, mx ? 0x3D : 0x39, 2, 0);
                    sse38_rr(e, mx ? 0x3D : 0x39, 3, 1);
                }
                /* pack exact: sign-extend the low element, packss */
                sse_shift_i(e, shl, 6, 2, shift);
                sse_shift_i(e, shl, 4, 2, shift);
                sse_shift_i(e, shl, 6, 3, shift);
                sse_shift_i(e, shl, 4, 3, shift);
                sse_rr(e, 0x66, size ? 0x6B : 0x63, 2, 3);
            }
            if (Q) {
                vop_dst(be, res, rd, 1);
            } else {
                /* 64-bit form: [low pairs of n | low pairs of m] */
                e8(e, 0x66); e8(e, 0x0F); e8(e, 0x7E);       /* movd eax */
                e8(e, (u8)(0xC0 | (res << 3) | RAX));
                sse_shift_i(e, 0x73, 3, res, 8);             /* psrldq 8 */
                e8(e, 0x66); e8(e, 0x0F); e8(e, 0x7E);       /* movd ecx */
                e8(e, (u8)(0xC0 | (res << 3) | RCX));
                shift_ri(e, 1, 4, RCX, 32);
                op_rr(e, 1, 0x0B, RAX, RCX);                 /* or */
                st64(e, RAX, R14, OFF_V(rd));
                st_imm_r14(e, OFF_V(rd) + 8, 0);
            }
            break;
        }
        case VC_2MISC: {
            unsigned U = (insn >> 29) & 1, size = (insn >> 22) & 3;
            unsigned Q = (insn >> 30) & 1;
            unsigned key = (U << 5) | ((insn >> 12) & 0x1f);
            static const u8 pcmpeq[3] = { 0x74, 0x75, 0x76 };
            static const u8 pcmpgt[3] = { 0x64, 0x65, 0x66 };
            static const u8 psub[4] = { 0xF8, 0xF9, 0xFA, 0xFB };
            if (key == 0x12) sse_mem(e, 0xF3, 0x6F, 0, OFF_V(rn));
            else             vop_src(be, 0, rn);
            switch (key) {
                case 0x08:                       /* CMGT #0 */
                    sse_rr(e, 0x66, 0xEF, 1, 1);
                    sse_rr(e, 0x66, pcmpgt[size], 0, 1);
                    break;
                case 0x09:                       /* CMEQ #0 */
                    sse_rr(e, 0x66, 0xEF, 1, 1);
                    sse_rr(e, 0x66, pcmpeq[size], 0, 1);
                    break;
                case 0x0a:                       /* CMLT #0: 0 > n */
                    sse_rr(e, 0x66, 0xEF, 1, 1);
                    sse_rr(e, 0x66, pcmpgt[size], 1, 0);
                    sse_rr(e, 0x66, 0x6F, 0, 1);
                    break;
                case 0x28:                       /* CMGE #0: ~(0 > n) */
                    sse_rr(e, 0x66, 0xEF, 1, 1);
                    sse_rr(e, 0x66, pcmpgt[size], 1, 0);
                    sse_rr(e, 0x66, 0x76, 0, 0); /* ones */
                    sse_rr(e, 0x66, 0xEF, 0, 1);
                    break;
                case 0x29:                       /* CMLE #0: ~(n > 0) */
                    sse_rr(e, 0x66, 0xEF, 1, 1);
                    sse_rr(e, 0x66, pcmpgt[size], 0, 1);
                    sse_rr(e, 0x66, 0x76, 1, 1); /* ones */
                    sse_rr(e, 0x66, 0xEF, 0, 1);
                    break;
                case 0x2b:                       /* NEG: 0 - n */
                    sse_rr(e, 0x66, 0xEF, 1, 1);
                    sse_rr(e, 0x66, psub[size], 1, 0);
                    sse_rr(e, 0x66, 0x6F, 0, 1);
                    break;
                case 0x0b:                       /* ABS (SSSE3 pabs) */
                    sse38_rr(e, (u8)(0x1C + size), 0, 0);
                    break;
                case 0x25:
                    if (size == 0) {             /* NOT */
                        sse_rr(e, 0x66, 0x76, 1, 1);     /* ones */
                        sse_rr(e, 0x66, 0xEF, 0, 1);
                        break;
                    }
                    /* RBIT.v: nibble-reverse LUTs, high | low */
                    sse_rr(e, 0x66, 0x6F, 1, 0);
                    sse_shift_i(e, 0x71, 2, 1, 4);
                    emit_const128(be, 0x0f0f0f0f0f0f0f0fULL,
                                  0x0f0f0f0f0f0f0f0fULL, 3);
                    sse_rr(e, 0x66, 0xDB, 0, 3);
                    sse_rr(e, 0x66, 0xDB, 1, 3);
                    emit_const128(be, 0xe060a020c0408000ULL,
                                  0xf070b030d0509010ULL, 2);
                    sse38_rr(e, 0x00, 2, 0);     /* rev(lo nib) << 4 */
                    emit_const128(be, 0x0e060a020c040800ULL,
                                  0x0f070b030d050901ULL, 3);
                    sse38_rr(e, 0x00, 3, 1);     /* rev(hi nib) */
                    sse_rr(e, 0x66, 0xEB, 2, 3); /* por */
                    sse_rr(e, 0x66, 0x6F, 0, 2);
                    break;
                case 0x00: case 0x20: case 0x01: {   /* REV64/REV32/REV16 */
                    unsigned grp = key == 0x00 ? 8 : key == 0x20 ? 4 : 2;
                    unsigned esz = 1u << size;
                    u64 pl = 0, ph = 0;
                    for (unsigned bi = 0; bi < 16; bi++) {
                        unsigned base = bi & ~(grp - 1), off = bi & (grp - 1);
                        u64 src = base + (grp - esz - (off & ~(esz - 1))) +
                                  (off & (esz - 1));
                        if (bi < 8) pl |= src << (8 * bi);
                        else        ph |= src << (8 * (bi - 8));
                    }
                    emit_const128(be, pl, ph, 1);
                    sse38_rr(e, 0x00, 0, 1);     /* pshufb by the perm */
                    break;
                }
                case 0x05:                       /* CNT: nibble-popcount */
                    sse_rr(e, 0x66, 0x6F, 1, 0);
                    sse_shift_i(e, 0x71, 2, 1, 4);
                    emit_const128(be, 0x0f0f0f0f0f0f0f0fULL,
                                  0x0f0f0f0f0f0f0f0fULL, 3);
                    sse_rr(e, 0x66, 0xDB, 0, 3);
                    sse_rr(e, 0x66, 0xDB, 1, 3);
                    emit_const128(be, 0x0302020102010100ULL,
                                  0x0403030203020201ULL, 2);
                    sse_rr(e, 0x66, 0x6F, 3, 2);
                    sse38_rr(e, 0x00, 2, 0);     /* cnt(lo nibbles) */
                    sse38_rr(e, 0x00, 3, 1);     /* cnt(hi nibbles) */
                    sse_rr(e, 0x66, 0xFC, 2, 3); /* paddb */
                    sse_rr(e, 0x66, 0x6F, 0, 2);
                    break;
                case 0x02: case 0x22: {          /* S/UADDLP: widen pairs */
                    static const u8 shq[3] = { 0x71, 0x72, 0x73 };
                    static const u8 pad2[3] = { 0xFD, 0xFE, 0xD4 };
                    unsigned ext = U ? 2 : 4;    /* psrl vs psra */
                    u8 esb = (u8)(8u << size);
                    sse_rr(e, 0x66, 0x6F, 1, 0);
                    sse_shift_i(e, shq[size], ext, 1, esb);   /* odd */
                    sse_shift_i(e, shq[size], 6, 0, esb);
                    sse_shift_i(e, shq[size], ext, 0, esb);   /* even */
                    sse_rr(e, 0x66, pad2[size], 0, 1);
                    break;
                }
                case 0x12: {                     /* XTN / XTN2: narrow */
                    if (size == 0) {             /* h -> b: sext + packsswb */
                        sse_shift_i(e, 0x71, 6, 0, 8);
                        sse_shift_i(e, 0x71, 4, 0, 8);
                        sse_rr(e, 0x66, 0x63, 0, 0);
                    } else if (size == 1) {      /* s -> h */
                        sse_shift_i(e, 0x72, 6, 0, 16);
                        sse_shift_i(e, 0x72, 4, 0, 16);
                        sse_rr(e, 0x66, 0x6B, 0, 0);     /* packssdw */
                    } else {                     /* d -> s: pshufd 0,2 */
                        sse_rr(e, 0x66, 0x70, 0, 0);
                        e8(e, 0x08);
                    }
                    movq_rax_x(e, 1, 0);         /* low 8 = narrowed */
                    if (Q) {                     /* XTN2: high half only */
                        st64(e, RAX, R14, OFF_V(rd) + 8);
                    } else {
                        st64(e, RAX, R14, OFF_V(rd));
                        st_imm_r14(e, OFF_V(rd) + 8, 0);
                    }
                    break;
                }
            }
            if (key != 0x12) vop_dst(be, 0, rd, (int)Q);
            break;
        }
        case VC_MINMAX: {
            unsigned U = (insn >> 29) & 1, size = (insn >> 22) & 3;
            unsigned Q = (insn >> 30) & 1;
            int mx = (((insn >> 11) & 0x1f) == 0x0c);        /* MAX vs MIN */
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            if (size == 0 && U)                              /* pmax/pminub */
                sse_rr(e, 0x66, mx ? 0xDE : 0xDA, 0, 1);
            else if (size == 1 && !U)                        /* pmax/pminsw */
                sse_rr(e, 0x66, mx ? 0xEE : 0xEA, 0, 1);
            else                                             /* SSE4.1 */
                sse38_rr(e, (u8)(0x38 | (mx ? 4 : 0) | (U ? 2 : 0) |
                                 (size == 2 ? 1 : 0)), 0, 1);
            vop_dst(be, 0, rd, (int)Q);
            break;
        }
        case VC_SHIFTI: {
            unsigned U = (insn >> 29) & 1, opc3 = (insn >> 11) & 0x1f;
            unsigned Q = (insn >> 30) & 1;
            unsigned immh = (insn >> 19) & 0xf;
            unsigned immhb = ((insn >> 16) & 0x7f);
            unsigned size = (immh & 8) ? 3 : (immh & 4) ? 2 : (immh & 2) ? 1 : 0;
            unsigned esize = 8u << size;
            static const u8 shopc[3] = { 0x71, 0x72, 0x73 };  /* h/s/d */
            if (opc3 == 0x10) sse_mem(e, 0xF3, 0x6F, 0, OFF_V(rn));
            else              vop_src(be, 0, rn);
            if (opc3 == 0x10) {
                /* SHRN(2): shift the wide lanes right, then narrow (the
                 * same sign-extend-and-pack / lane-gather as XTN). Q form
                 * writes only the high half of Vd. */
                sse_shift_i(e, shopc[size], 2, 0, (u8)(2 * esize - immhb));
                if (size == 0) {
                    sse_shift_i(e, 0x71, 6, 0, 8);
                    sse_shift_i(e, 0x71, 4, 0, 8);
                    sse_rr(e, 0x66, 0x63, 0, 0);              /* packsswb */
                } else if (size == 1) {
                    sse_shift_i(e, 0x72, 6, 0, 16);
                    sse_shift_i(e, 0x72, 4, 0, 16);
                    sse_rr(e, 0x66, 0x6B, 0, 0);              /* packssdw */
                } else {
                    sse_rr(e, 0x66, 0x70, 0, 0);              /* pshufd 0,2 */
                    e8(e, 0x08);
                }
                movq_rax_x(e, 1, 0);
                if (Q) {
                    st64(e, RAX, R14, OFF_V(rd) + 8);
                } else {
                    st64(e, RAX, R14, OFF_V(rd));
                    st_imm_r14(e, OFF_V(rd) + 8, 0);
                }
                break;
            }
            if (opc3 == 0x14) {
                /* S/USHLL(2): widen the low (or, for the 2-form, high)
                 * half, then shift left. esize here is the SOURCE width. */
                if (Q) sse_shift_i(e, 0x73, 3, 0, 8);         /* psrldq 8 */
                if (U) {
                    sse_rr(e, 0x66, 0xEF, 1, 1);              /* zero */
                    sse_rr(e, 0x66, size == 0 ? 0x60 :
                                    size == 1 ? 0x61 : 0x62, 0, 1);
                    sse_shift_i(e, shopc[size], 6, 0, (u8)(immhb - esize));
                } else {                                      /* sext widen */
                    sse_rr(e, 0x66, size == 0 ? 0x60 : 0x61, 0, 0);
                    sse_shift_i(e, shopc[size], 4, 0, (u8)esize);
                    sse_shift_i(e, shopc[size], 6, 0, (u8)(immhb - esize));
                }
                vop_dst(be, 0, rd, 1);
                break;
            }
            if (size == 0) {
                /* byte forms: 16-bit shift + kill the bits that crossed
                 * the byte boundary (mask replicated at translate time) */
                u8 m;
                if (opc3 == 0x0a) {                           /* SHL */
                    sse_shift_i(e, 0x71, 6, 0, (u8)(immhb - 8));
                    m = (u8)(0xff << (immhb - 8));
                } else {                                      /* USHR/USRA */
                    sse_shift_i(e, 0x71, 2, 0, (u8)(16 - immhb));
                    m = (u8)(0xff >> (16 - immhb));
                }
                u64 rep = 0x0101010101010101ULL * m;
                emit_const128(be, rep, rep, 1);
                sse_rr(e, 0x66, 0xDB, 0, 1);                  /* pand */
                if (opc3 == 0x02) {                           /* USRA.b */
                    vop_src(be, 1, rd);
                    sse_rr(e, 0x66, 0xFC, 0, 1);              /* paddb */
                }
                vop_dst(be, 0, rd, (int)Q);
                break;
            }
            if (opc3 == 0x02) {                               /* S/USRA */
                /* Shift right (psrl/psra saturate a count == esize exactly
                 * like vreg_shift), then accumulate into Vd. */
                static const u8 padd[4] = { 0xFC, 0xFD, 0xFE, 0xD4 };
                sse_shift_i(e, shopc[size - 1], U ? 2 : 4, 0,
                            (u8)(2 * esize - immhb));
                vop_src(be, 1, rd);
                sse_rr(e, 0x66, padd[size], 0, 1);
            } else if (opc3 == 0x0a) {                        /* SHL */
                sse_shift_i(e, shopc[size - 1], 6, 0, (u8)(immhb - esize));
            } else if (U) {                                   /* USHR */
                sse_shift_i(e, shopc[size - 1], 2, 0, (u8)(2 * esize - immhb));
            } else {                                          /* SSHR */
                sse_shift_i(e, shopc[size - 1], 4, 0, (u8)(2 * esize - immhb));
            }
            vop_dst(be, 0, rd, (int)Q);
            break;
        }
        case VC_S3S: {
            /* Scalar 3-same integer, D-form (size==3 whitelisted). ADD/SUB
             * stay pure SSE (movq loads zero-extend, matching the scalar
             * clear-high rule); the compares go through GPRs. */
            unsigned U = (insn >> 29) & 1, opc3 = (insn >> 11) & 0x1f;
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            if (opc3 == 0x10) {                               /* ADD / SUB */
                sse_rr(e, 0x66, U ? 0xFB : 0xD4, 0, 1);       /* psub/addq */
                vop_dst(be, 0, rd, 0);           /* D-form: clear high */
                break;
            }
            materialize_flags(be);                            /* cmp below */
            movq_rax_x(e, 1, 0);                              /* rax = n */
            e8(e, 0x66); e8(e, 0x48); e8(e, 0x0F); e8(e, 0x7E);
            e8(e, (u8)(0xC0 | (1 << 3) | RCX));               /* rcx = m */
            int cc;
            if (opc3 == 0x11 && !U) {                         /* CMTST */
                op_rr(e, 1, 0x85, RCX, RAX);                  /* test */
                cc = CC_NE;
            } else {
                op_rr(e, 1, 0x39, RCX, RAX);                  /* cmp n, m */
                cc = (opc3 == 0x11) ? CC_E                    /* CMEQ */
                   : (opc3 == 0x06) ? (U ? CC_A : CC_G)       /* CMHI/CMGT */
                   : (U ? CC_AE : CC_GE);                     /* CMHS/CMGE */
            }
            e8(e, 0x0F); e8(e, (u8)(0x90 | cc)); e8(e, 0xC0); /* setcc al */
            e8(e, 0x0F); e8(e, 0xB6); e8(e, 0xC0);            /* movzx eax,al */
            rex(e, 1, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xD8);   /* neg rax */
            movq_xr(e, 0, RAX);
            vop_dst(be, 0, rd, 0);
            break;
        }
        case VC_SSHIFTI: {
            /* Scalar shift-imm, D-form. Logical shifts and the U-accumulate
             * ride psllq/psrlq (count semantics match vreg_shift); the
             * signed ones need sar, so they go through a GPR. */
            unsigned U = (insn >> 29) & 1, opc3 = (insn >> 11) & 0x1f;
            unsigned immhb = ((insn >> 16) & 0x7f);
            vop_src(be, 0, rn);
            if (opc3 == 0x0a || U) {
                if (opc3 == 0x0a)                             /* SHL */
                    sse_shift_i(e, 0x73, 6, 0, (u8)(immhb - 64));
                else                                          /* USHR/USRA */
                    sse_shift_i(e, 0x73, 2, 0, (u8)(128 - immhb));
                if (opc3 == 0x02) {                           /* USRA */
                    vop_src(be, 1, rd);
                    sse_rr(e, 0x66, 0xD4, 0, 1);              /* paddq */
                }
                vop_dst(be, 0, rd, 0);           /* D-form: clear high */
                break;
            }
            /* SSHR / SSRA: sar with the interpreter's >=64 -> 63 clamp */
            unsigned sh = 128 - immhb;
            materialize_flags(be);
            movq_rax_x(e, 1, 0);
            shift_ri(e, 1, 7, RAX, sh >= 64 ? 63 : sh);       /* sar */
            if (opc3 == 0x02) {                               /* SSRA */
                vop_src(be, 1, rd);
                e8(e, 0x66); e8(e, 0x48); e8(e, 0x0F); e8(e, 0x7E);
                e8(e, (u8)(0xC0 | (1 << 3) | RCX));           /* rcx = Vd */
                op_rr(e, 1, 0x01, RCX, RAX);                  /* add */
            }
            movq_xr(e, 0, RAX);
            vop_dst(be, 0, rd, 0);
            break;
        }
        case VC_MUL3: {
            unsigned size = (insn >> 22) & 3, Q = (insn >> 30) & 1;
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            if (size == 1) {
                sse_rr(e, 0x66, 0xD5, 0, 1);     /* pmullw */
            } else if (size == 2) {
                sse38_rr(e, 0x40, 0, 1);         /* pmulld (SSE4.1) */
            } else {
                /* bytes: widen both halves, pmullw, keep the low byte of
                 * each product (sign-agnostic), pack back */
                sse_rr(e, 0x66, 0xEF, 3, 3);     /* zero */
                sse_rr(e, 0x66, 0x6F, 2, 0);
                sse_rr(e, 0x66, 0x60, 2, 3);     /* punpcklbw n-lo */
                sse_rr(e, 0x66, 0x68, 0, 3);     /* punpckhbw n-hi */
                sse_rr(e, 0x66, 0x6F, 4, 1);
                sse_rr(e, 0x66, 0x60, 4, 3);
                sse_rr(e, 0x66, 0x68, 1, 3);
                sse_rr(e, 0x66, 0xD5, 2, 4);
                sse_rr(e, 0x66, 0xD5, 0, 1);
                sse_shift_i(e, 0x71, 6, 2, 8);   /* keep low bytes */
                sse_shift_i(e, 0x71, 2, 2, 8);
                sse_shift_i(e, 0x71, 6, 0, 8);
                sse_shift_i(e, 0x71, 2, 0, 8);
                sse_rr(e, 0x66, 0x67, 2, 0);     /* packuswb */
                sse_rr(e, 0x66, 0x6F, 0, 2);
            }
            vop_dst(be, 0, rd, (int)Q);
            break;
        }
        case VC_ACROSS: {
            /* Reduce with a psrldq halving ladder; the scalar result goes
             * to Vd lane 0, rest cleared. Non-Q data occupies the low 8
             * bytes and the ladder never pulls high-half garbage into the
             * lanes it still consumes. */
            unsigned U = (insn >> 29) & 1, size = (insn >> 22) & 3;
            unsigned Q = (insn >> 30) & 1;
            unsigned opc17 = (insn >> 12) & 0x1f;
            int add = (opc17 == 0x1b), mx = (opc17 == 0x0a);
            static const u8 padd[3] = { 0xFC, 0xFD, 0xFE };
            sse_mem(e, 0xF3, 0x6F, 0, OFF_V(rn));
            for (unsigned s = Q ? 8 : 4; s >= (1u << size); s >>= 1) {
                sse_rr(e, 0x66, 0x6F, 1, 0);
                sse_shift_i(e, 0x73, 3, 1, (u8)s);       /* psrldq */
                if (add) sse_rr(e, 0x66, padd[size], 0, 1);
                else if (size == 0 && U)
                    sse_rr(e, 0x66, mx ? 0xDE : 0xDA, 0, 1);
                else if (size == 1 && !U)
                    sse_rr(e, 0x66, mx ? 0xEE : 0xEA, 0, 1);
                else
                    sse38_rr(e, (u8)(0x38 | (mx ? 4 : 0) | (U ? 2 : 0) |
                                     (size == 2 ? 1 : 0)), 0, 1);
            }
            movq_rax_x(e, 1, 0);
            st_imm_r14(e, OFF_V(rd), 0);
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            st_lane_rax(e, size, OFF_V(rd));
            break;
        }
        case VC_MOVI: {
            unsigned vd = VMOVI_RD(o->aux), q = VMOVI_Q(o->aux);
            unsigned kind = VMOVI_KIND(o->aux);
            if (kind == 0) {                     /* plain write */
                mov_ri(e, 1, RAX, o->imm);
                st64(e, RAX, R14, OFF_V(vd));
                if (q) st64(e, RAX, R14, OFF_V(vd) + 8);
                else   st_imm_r14(e, OFF_V(vd) + 8, 0);
            } else {                             /* ORR/BIC into Vd */
                materialize_flags(be);
                mov_ri(e, 1, RCX, kind == 2 ? ~o->imm : o->imm);
                ld64(e, RAX, R14, OFF_V(vd));
                op_rr(e, 1, kind == 2 ? 0x23 : 0x0B, RAX, RCX);
                st64(e, RAX, R14, OFF_V(vd));
                if (q) {
                    ld64(e, RAX, R14, OFF_V(vd) + 8);
                    op_rr(e, 1, kind == 2 ? 0x23 : 0x0B, RAX, RCX);
                    st64(e, RAX, R14, OFF_V(vd) + 8);
                } else {
                    st_imm_r14(e, OFF_V(vd) + 8, 0);
                }
            }
            break;
        }
        case VC_COPY: {
            unsigned Q = (insn >> 30) & 1, op29 = (insn >> 29) & 1;
            unsigned imm5 = (insn >> 16) & 31, imm4 = (insn >> 11) & 0xf;
            unsigned size = (imm5 & 1) ? 0 : (imm5 & 2) ? 1 : (imm5 & 4) ? 2 : 3;
            unsigned index = imm5 >> (size + 1);
            unsigned esz = 1u << size;
            materialize_flags(be);               /* imul/bit ops below */
            if (op29 == 1) {                     /* INS (element) */
                unsigned idx2 = imm4 >> size;
                ld_lane_rax(e, size, OFF_V(rn) + (s32)(idx2 * esz));
                st_lane_rax(e, size, OFF_V(rd) + (s32)(index * esz));
                break;
            }
            if (imm4 == 0x3) {                   /* INS (general) */
                int hsrc = ra_use(be, o->a);
                mov_rr(e, 1, RAX, hsrc);
                st_lane_rax(e, size, OFF_V(rd) + (s32)(index * esz));
                break;
            }
            if (imm4 == 0x5 || imm4 == 0x7) {    /* SMOV / UMOV */
                if (o->dst == VREG_ZERO) break;
                ld_lane_rax(e, size, OFF_V(rn) + (s32)(index * esz));
                if (imm4 == 0x5) {               /* SMOV: sign-extend */
                    if (size == 0) { e8(e, 0x48); e8(e, 0x0F); e8(e, 0xBE); e8(e, 0xC0); }
                    else if (size == 1) { e8(e, 0x48); e8(e, 0x0F); e8(e, 0xBF); e8(e, 0xC0); }
                    else if (size == 2) { e8(e, 0x48); e8(e, 0x63); e8(e, 0xC0); }
                    if (!Q) mov_rr(e, 0, RAX, RAX);   /* Wd form: zext32 */
                }
                int hd = ra_def(be, o->dst);
                mov_rr(e, 1, hd, RAX);
                break;
            }
            /* DUP (element imm4==0, general imm4==1): splat -> both lanes */
            if (imm4 == 0x0) ld_lane_rax(e, size, OFF_V(rn) + (s32)(index * esz));
            else { int hsrc = ra_use(be, o->a); mov_rr(e, 1, RAX, hsrc); }
            if (size == 0) {                     /* rax = rep8 */
                e8(e, 0x0F); e8(e, 0xB6); e8(e, 0xC0);       /* movzx eax,al */
                mov_ri(e, 1, RCX, 0x0101010101010101ULL);
                op0f_rr(e, 1, 0xAF, RAX, RCX);               /* imul rax,rcx */
            } else if (size == 1) {
                e8(e, 0x0F); e8(e, 0xB7); e8(e, 0xC0);       /* movzx eax,ax */
                mov_ri(e, 1, RCX, 0x0001000100010001ULL);
                op0f_rr(e, 1, 0xAF, RAX, RCX);
            } else if (size == 2) {
                mov_rr(e, 0, RAX, RAX);                      /* zext32 */
                mov_rr(e, 1, RCX, RAX);
                shift_ri(e, 1, 4, RCX, 32);
                op_rr(e, 1, 0x0B, RAX, RCX);                 /* or */
            }
            st64(e, RAX, R14, OFF_V(rd));
            if (Q) st64(e, RAX, R14, OFF_V(rd) + 8);
            else   st_imm_r14(e, OFF_V(rd) + 8, 0);
            break;
        }
        case VC_F2: {                            /* scalar arith, S/D:
                                                  * self-counting class */
            int dbl = ((insn >> 22) & 3) == 1;
            unsigned opc = (insn >> 12) & 0xf;
            int arith = (opc <= 3 || opc == 8);  /* NaN-gated (see below) */
            u8 pfx = dbl ? 0xF2 : 0xF3;
            /* FMAX/FMIN(NM) (opc 4-7) are declined by be_vop_ok and never reach
             * here — they keep the interpreter helper for correct ARM NaN/±0. */
            if (arith) materialize_flags(be);    /* ucomis / xor below */
            sse_mem(e, pfx, 0x10, 0, OFF_V(rn)); /* movss/sd xmm0, Vn */
            sse_mem(e, pfx, 0x10, 1, OFF_V(rm));
            switch (opc) {
                case 0x0: sse_rr(e, pfx, 0x59, 0, 1); break; /* FMUL */
                case 0x1: sse_rr(e, pfx, 0x5E, 0, 1); break; /* FDIV */
                case 0x2: sse_rr(e, pfx, 0x58, 0, 1); break; /* FADD */
                case 0x3: sse_rr(e, pfx, 0x5C, 0, 1); break; /* FSUB */
                default:  sse_rr(e, pfx, 0x59, 0, 1); break; /* FNMUL: below */
            }
            /* A NaN result means NaN inputs or an invalid op — cases where
             * the bits depend on gcc's operand order in the interpreter.
             * Discard and re-run the insn there (vop_slowpath). */
            u8 *slow = NULL;
            if (arith) {
                sse_rr(e, dbl ? 0x66 : 0, 0x2E, 0, 0);   /* ucomis x0, x0 */
                slow = jcc_fwd(e, CC_P);
            }
            icount_add(be, 1);
            /* result -> rax (int path handles lane write + high clear) */
            movq_rax_x(e, dbl, 0);
            if (opc == 0x8) {                    /* FNMUL: flip the sign bit */
                mov_ri(e, 1, RCX, dbl ? 0x8000000000000000ULL : 0x80000000ULL);
                op_rr(e, 1, 0x33, RAX, RCX);     /* xor rax, rcx */
            }
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            if (slow) vop_slowpath(be, o, slow, -1);
            break;
        }
        case VC_F1: {                            /* FMOV/FABS/FNEG/FSQRT */
            int dbl = ((insn >> 22) & 3) == 1;
            unsigned opc = (insn >> 15) & 0x3f;
            u8 *slow = NULL;
            /* FSQRT needs the flags for its NaN gate below; FABS/FNEG use xor. */
            if (opc == 0x1 || opc == 0x2 || opc == 0x3) materialize_flags(be);
            if (opc == 0x3) {                    /* FSQRT via SSE */
                u8 pfx = dbl ? 0xF2 : 0xF3;
                sse_mem(e, pfx, 0x10, 0, OFF_V(rn));
                sse_rr(e, pfx, 0x51, 0, 0);      /* sqrtss/sd */
                /* Same NaN gate as VC_F2: sqrt of a negative is an invalid
                 * operation, and the host's DefaultNaN has the wrong sign, so
                 * the answer has to come from the interpreter (exec_fpsimd.c
                 * fpnan_*). FABS/FNEG below are pure sign bit ops on a value
                 * that already is what it should be, so they need no gate. */
                sse_rr(e, dbl ? 0x66 : 0, 0x2E, 0, 0);   /* ucomis x0, x0 */
                slow = jcc_fwd(e, CC_P);
                if (dbl) { e8(e, 0x66); e8(e, 0x48); e8(e, 0x0F); e8(e, 0x7E); e8(e, 0xC0); }
                else     { e8(e, 0x66); e8(e, 0x0F); e8(e, 0x7E); e8(e, 0xC0); }
            } else {                             /* pure bit ops on the lane */
                if (dbl) ld64(e, RAX, R14, OFF_V(rn));
                else     ld32(e, RAX, R14, OFF_V(rn));       /* zext */
                if (opc == 0x1 || opc == 0x2) {
                    mov_ri(e, 1, RCX,
                           dbl ? 0x8000000000000000ULL : 0x80000000ULL);
                    if (opc == 0x1) {            /* FABS: clear sign */
                        rex(e, 1, 0, 0, RCX); e8(e, 0xF7); e8(e, 0xD1);
                        op_rr(e, 1, 0x23, RAX, RCX);         /* and */
                    } else {
                        op_rr(e, 1, 0x33, RAX, RCX);         /* FNEG: xor */
                    }
                }
            }
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            /* FSQRT is the gated arm, so it is the self-counted one (ir.h):
             * count it here on the fast path, because the slow arm's
             * jit_exec1 counts it and ninsns no longer does. FABS/FNEG/FMOV
             * never gate and stay in the block's ninsns. */
            if (slow) {
                icount_add(be, 1);
                vop_slowpath(be, o, slow, -1);
            }
            break;
        }
        case VC_FCMP: {
            unsigned ft = (insn >> 22) & 3;
            int dbl = (ft == 1), half = (ft == 3);
            int with_zero = (insn >> 3) & 1;
            materialize_flags(be);               /* about to clobber EFLAGS */
            if (half) {                          /* widen halves -> single */
                vcvtph2ps_m(e, 0, OFF_V(rn));
                if (with_zero) sse_rr(e, 0x66, 0xEF, 1, 1);  /* pxor: +0.0 */
                else vcvtph2ps_m(e, 1, OFF_V(rm));
                sse_rr(e, 0, 0x2E, 0, 1);                    /* ucomiss */
            } else {
                u8 mpfx = dbl ? 0xF2 : 0xF3;
                sse_mem(e, mpfx, 0x10, 0, OFF_V(rn));
                if (with_zero) sse_rr(e, 0x66, 0xEF, 1, 1);  /* pxor: +0.0 */
                else sse_mem(e, mpfx, 0x10, 1, OFF_V(rm));
                if (dbl) sse_rr(e, 0x66, 0x2E, 0, 1);        /* ucomisd */
                else     sse_rr(e, 0, 0x2E, 0, 1);           /* ucomiss */
            }
            /* interpreter mapping: lt->N eq->Z|C gt->C uo->C|V */
            u8 *juo = jcc_fwd(e, CC_P);
            u8 *jlt = jcc_fwd(e, CC_B);
            u8 *jeq = jcc_fwd(e, CC_E);
            mov_ri(e, 0, RAX, 0x20000000u);      /* gt: C */
            u8 *j1 = jmp_fwd(e);
            fwd_here(e, juo);
            mov_ri(e, 0, RAX, 0x30000000u);      /* uo: C|V */
            u8 *j2 = jmp_fwd(e);
            fwd_here(e, jlt);
            mov_ri(e, 0, RAX, 0x80000000u);      /* lt: N */
            u8 *j3 = jmp_fwd(e);
            fwd_here(e, jeq);
            mov_ri(e, 0, RAX, 0x60000000u);      /* eq: Z|C */
            fwd_here(e, j1); fwd_here(e, j2); fwd_here(e, j3);
            st32(e, RAX, R14, OFF_NZCV);
            be->fl = FL_MEM;
            break;
        }
        case VC_FCSEL: {
            unsigned ft = (insn >> 22) & 3;
            int dbl = (ft == 1), half = (ft == 3);
            unsigned cond = (insn >> 12) & 0xf;
            int cc = cond_setup(be, cond);       /* may clobber rax/rcx/rdx */
            if (dbl) {
                ld64(e, RAX, R14, OFF_V(rn));
                ld64(e, RCX, R14, OFF_V(rm));
            } else {                             /* single or half: low 32b */
                ld32(e, RAX, R14, OFF_V(rn));
                ld32(e, RCX, R14, OFF_V(rm));
            }
            if (cc != CC_ALWAYS) {
                if (cc == CC_NEVER) mov_rr(e, 1, RAX, RCX);
                else op0f_rr(e, 1, (u8)(0x40 | (cc ^ 1)), RAX, RCX); /* cmovncc */
            }
            if (half) alu_ri32(e, 0, 4, RAX, 0xffff);   /* Hd = low 16 bits */
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            /* loads/cmov preserve EFLAGS, but the next op may clobber
             * them: keep host flags only for a following consumer, else
             * store NZCV now (same discipline as the integer CSEL). */
            if (be->fl != FL_MEM && flags_next_use(ir, i) == FLAGS_UNKNOWN)
                materialize_flags(be);
            break;
        }
        case VC_VF3S: {
            /* Vector FP three-same arithmetic (packed SSE2 = the
             * interpreter's per-lane host C); self-counting, NaN-gated:
             * any NaN result lane re-runs the insn in the interpreter
             * (same rationale as VC_F2/F3). */
            unsigned Q = (insn >> 30) & 1, sz = (insn >> 22) & 1;
            unsigned a23 = (insn >> 23) & 1, U = (insn >> 29) & 1;
            unsigned opc3 = (insn >> 11) & 0x1f;
            u8 pfx = sz ? 0x66 : 0;              /* pd : ps */
            int res = 0;
            materialize_flags(be);
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            if (opc3 == 0x19) {                  /* FMLA / FMLS: FMA3 fused —
                                                  * be_vop_ok declined us if
                                                  * the host has none */
                vop_src(be, 2, rd);              /* Vd is the accumulator */
                fma231_rr(e, a23 ? 0xBC : 0xB8, (int)sz, 2, 0, 1);
                res = 2;
            } else if (opc3 == 0x1a && U && !a23) { /* FADDP (a23 set is FABD):
                                                  * fold pairs — even lanes of
                                                  * n:m + odd lanes */
                sse_rr(e, 0x66, 0x6F, 2, 0);     /* x2 = n */
                if (sz) {
                    sse_rr(e, 0x66, 0xC6, 2, 1); e8(e, 0);   /* [n0, m0] */
                    sse_rr(e, 0x66, 0xC6, 0, 1); e8(e, 3);   /* [n1, m1] */
                    sse_rr(e, pfx, 0x58, 2, 0);              /* addpd */
                } else {
                    sse_rr(e, 0, 0xC6, 2, 1); e8(e, 0x88);   /* evens */
                    sse_rr(e, 0, 0xC6, 0, 1); e8(e, 0xDD);   /* odds */
                    sse_rr(e, pfx, 0x58, 2, 0);              /* addps */
                    if (!Q) {                    /* .2s: sums sit in lanes
                                                  * 0 and 2 — compact them */
                        sse_rr(e, 0x66, 0x70, 2, 2); e8(e, 0xF8);
                    }
                }
                res = 2;
            } else if (opc3 == 0x1a && !U) {     /* FADD / FSUB */
                sse_rr(e, pfx, a23 ? 0x5C : 0x58, 0, 1);
            } else if (opc3 == 0x1b) {           /* FMUL */
                sse_rr(e, pfx, 0x59, 0, 1);
            } else if (opc3 == 0x1f) {           /* FDIV */
                sse_rr(e, pfx, 0x5E, 0, 1);
            } else {                             /* FABD: |n - m| */
                sse_rr(e, pfx, 0x5C, 0, 1);
                sse_rr(e, 0x66, 0x76, 1, 1);     /* ones */
                sse_shift_i(e, sz ? 0x73 : 0x72, 2, 1, 1);   /* abs mask */
                sse_rr(e, 0x66, 0xDB, 0, 1);     /* pand */
            }
            sse_rr(e, 0x66, 0x6F, 1, res);       /* copy for the NaN check */
            sse_rr(e, pfx, 0xC2, 1, 1);          /* cmpps/pd unord */
            e8(e, 3);
            sse_rr(e, pfx, 0x50, RAX, 1);        /* movmskps/pd eax */
            if (!sz && !Q) alu_ri32(e, 0, 4, RAX, 0x3);
            op_rr(e, 0, 0x85, RAX, RAX);
            u8 *slow = jcc_fwd(e, CC_NE);
            icount_add(be, 1);
            /* both arms converge with the result in `res` (the slow arm
             * reloads the interpreter's commit); one post-merge vop_dst */
            vop_slowpath(be, o, slow, res);
            vop_dst(be, res, rd, (int)Q);
            break;
        }
        case VC_VFCM: {
            /* Vector FP compares: per-lane mask, NaN -> false — cmpps with
             * the right predicate/order is the C expression exactly. */
            unsigned Q = (insn >> 30) & 1, sz = (insn >> 22) & 1;
            unsigned a23 = (insn >> 23) & 1;
            unsigned opc3 = (insn >> 11) & 0x1f, U = (insn >> 29) & 1;
            u8 pfx = sz ? 0x66 : 0;
            int res;
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            if (opc3 == 0x1d) {                  /* FACGE/FACGT: abs first */
                sse_rr(e, 0x66, 0x76, 2, 2);
                sse_shift_i(e, sz ? 0x73 : 0x72, 2, 2, 1);
                sse_rr(e, 0x66, 0xDB, 0, 2);
                sse_rr(e, 0x66, 0xDB, 1, 2);
            }
            if (!U) {                            /* FCMEQ */
                sse_rr(e, pfx, 0xC2, 0, 1); e8(e, 0);
                res = 0;
            } else {                             /* GE: m<=n / GT: m<n */
                sse_rr(e, pfx, 0xC2, 1, 0); e8(e, a23 ? 1 : 2);
                res = 1;
            }
            vop_dst(be, res, rd, (int)Q);
            break;
        }
        case VC_F3: {
            /* Scalar FMADD family: FMA3 231-form with the addend preloaded
             * into the destination — fused exactly like the interpreter's
             * __builtin_fma; a NaN result re-runs there (the operand-
             * priority NaN selection and canonical generated NaN live in
             * fpnan_*). */
            int dbl = ((insn >> 22) & 3) == 1;
            unsigned ra = (insn >> 10) & 31;
            int o1 = (insn >> 21) & 1, o0 = (insn >> 15) & 1;
            u8 pfx = dbl ? 0xF2 : 0xF3;
            materialize_flags(be);
            sse_mem(e, pfx, 0x10, 0, OFF_V(rn));         /* n */
            sse_mem(e, pfx, 0x10, 1, OFF_V(rm));         /* m */
            sse_mem(e, pfx, 0x10, 2, OFF_V(ra));         /* addend */
            /* FMADD  a + nm -> vfmadd231; FMSUB  a - nm -> vfnmadd231;
             * FNMADD -a - nm -> vfnmsub231; FNMSUB -a + nm -> vfmsub231 */
            fma231_rr(e, !o1 ? (!o0 ? 0xB9 : 0xBD) : (!o0 ? 0xBF : 0xBB),
                      dbl, 2, 0, 1);
            sse_rr(e, dbl ? 0x66 : 0, 0x2E, 2, 2);       /* ucomis x2,x2 */
            u8 *slow = jcc_fwd(e, CC_P);
            icount_add(be, 1);
            movq_rax_x(e, dbl, 2);
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            vop_slowpath(be, o, slow, -1);
            break;
        }
        case VC_VMISCF: {
            /* Vector two-misc FP (S/D): FABS/FNEG are sign-mask bit ops
             * (exact, ungated), FSQRT is sqrtps + NaN gate, the compares
             * with #0 are cmpps predicates whose NaN/IE behavior is the
             * interpreter's exactly (like VC_VFCM), and FRINT* is roundps —
             * NaN-gated, with FRINTX/I bailing unless FPCR.RMode is RN.
             * FRINTA and the estimates were declined by be_vop_ok. */
            unsigned Q = (insn >> 30) & 1, sz = (insn >> 22) & 1;
            unsigned key = (((insn >> 29) & 1) << 6) | (((insn >> 23) & 1) << 5) |
                           ((insn >> 12) & 0x1f);
            u8 pfx = sz ? 0x66 : 0;
            u8 *slow2 = NULL;
            int res = 0, gated = 1;
            materialize_flags(be);
            if (key == 0x59 || key == 0x79) slow2 = rmode_gate(be);
            vop_src(be, 0, rn);
            switch (key) {
                case 0x2f:                       /* FABS: clear sign bits */
                    sse_rr(e, 0x66, 0x76, 1, 1);
                    sse_shift_i(e, sz ? 0x73 : 0x72, 2, 1, 1);
                    sse_rr(e, 0x66, 0xDB, 0, 1);
                    /* the single form is NOT a pure bit op in the
                     * interpreter: its widen-through-double quiets SNaN
                     * lanes (and raises IOC) — keep the gate there. The
                     * double form reads the lane directly and is pure. */
                    gated = !sz;
                    break;
                case 0x6f:                       /* FNEG: flip sign bits */
                    sse_rr(e, 0x66, 0x76, 1, 1);
                    sse_shift_i(e, sz ? 0x73 : 0x72, 6, 1, sz ? 63 : 31);
                    sse_rr(e, 0x66, 0xEF, 0, 1);
                    gated = !sz;                 /* same SNaN-quiet rule */
                    break;
                case 0x7f:                       /* FSQRT */
                    sse_rr(e, pfx, 0x51, 0, 0);
                    break;
                case 0x2c:                       /* FCMGT #0: 0 < x */
                case 0x6c:                       /* FCMGE #0: 0 <= x */
                    sse_rr(e, 0x66, 0xEF, 1, 1);
                    sse_rr(e, pfx, 0xC2, 1, 0); e8(e, key == 0x2c ? 1 : 2);
                    res = 1; gated = 0;
                    break;
                case 0x2d:                       /* FCMEQ #0 */
                case 0x6d:                       /* FCMLE #0: x <= 0 */
                case 0x2e:                       /* FCMLT #0: x < 0 */
                    sse_rr(e, 0x66, 0xEF, 1, 1);
                    sse_rr(e, pfx, 0xC2, 0, 1);
                    e8(e, key == 0x2d ? 0 : key == 0x6d ? 2 : 1);
                    gated = 0;
                    break;
                default: {                       /* FRINT N/M/P/Z/X/I */
                    u8 imm = key == 0x18 ? 0x8   /* N: even, PE off */
                           : key == 0x38 ? 0xA   /* P: +inf */
                           : key == 0x19 ? 0x9   /* M: -inf */
                           : key == 0x39 ? 0xB   /* Z: trunc */
                           : key == 0x59 ? 0x0   /* X: even, PE on */
                           : 0x8;                /* I: even (RMode gated) */
                    sse3a_rr(e, sz ? 0x09 : 0x08, 0, 0, imm);
                    break;
                }
            }
            if (!gated) {
                icount_add(be, 1);
                vop_dst(be, res, rd, (int)Q);
                break;
            }
            sse_rr(e, 0x66, 0x6F, 1, res);       /* copy for the NaN check */
            sse_rr(e, pfx, 0xC2, 1, 1); e8(e, 3);
            sse_rr(e, pfx, 0x50, RAX, 1);        /* movmskps/pd */
            if (!sz && !Q) alu_ri32(e, 0, 4, RAX, 0x3);
            op_rr(e, 0, 0x85, RAX, RAX);
            u8 *slow = jcc_fwd(e, CC_NE);
            icount_add(be, 1);
            vop_slowpath2(be, o, slow, slow2, res);
            vop_dst(be, res, rd, (int)Q);
            break;
        }
        case VC_FRINTS: {
            /* Scalar FRINT S/D via roundss/sd (SSE4.1); half and FRINTA
             * were declined. X and I run only under guest RN. */
            int dbl = ((insn >> 22) & 3) == 1;
            unsigned ropc = (insn >> 15) & 0x3f;
            u8 pfx = dbl ? 0xF2 : 0xF3;
            u8 *slow2 = NULL;
            materialize_flags(be);
            if (ropc == 0xe || ropc == 0xf) slow2 = rmode_gate(be);
            sse_mem(e, pfx, 0x10, 0, OFF_V(rn));
            {
                u8 imm = ropc == 0x8 ? 0x8 : ropc == 0x9 ? 0xA
                       : ropc == 0xa ? 0x9 : ropc == 0xb ? 0xB
                       : ropc == 0xe ? 0x0 : 0x8;    /* X reports PE */
                sse3a_rr(e, dbl ? 0x0B : 0x0A, 0, 0, imm);
            }
            sse_rr(e, dbl ? 0x66 : 0, 0x2E, 0, 0);       /* ucomis x0,x0 */
            u8 *slow = jcc_fwd(e, CC_P);
            icount_add(be, 1);
            movq_rax_x(e, dbl, 0);
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            vop_slowpath2(be, o, slow, slow2, -1);
            break;
        }
        case VC_FPAIRS: {
            /* Scalar pairwise: ADDP.d is an exact integer fold; FADDP folds
             * the two low lanes with a NaN gate. */
            unsigned U = (insn >> 29) & 1, sz = (insn >> 22) & 1;
            sse_mem(e, 0xF3, 0x6F, 0, OFF_V(rn));        /* movdqu Vn */
            if (!U) {                                    /* ADDP.d */
                sse_rr(e, 0x66, 0x70, 1, 0); e8(e, 0x4E);/* swap halves */
                sse_rr(e, 0x66, 0xD4, 0, 1);             /* paddq */
                icount_add(be, 1);
                movq_rax_x(e, 1, 0);
                st64(e, RAX, R14, OFF_V(rd));
                st_imm_r14(e, OFF_V(rd) + 8, 0);
                break;
            }
            materialize_flags(be);
            if (sz) {
                sse_rr(e, 0x66, 0x70, 1, 0); e8(e, 0x4E);/* x1 = [n1, n0] */
                sse_rr(e, 0xF2, 0x58, 0, 1);             /* addsd */
            } else {
                sse_rr(e, 0x66, 0x70, 1, 0); e8(e, 0x01);/* x1 lane0 = n1 */
                sse_rr(e, 0xF3, 0x58, 0, 1);             /* addss */
            }
            sse_rr(e, sz ? 0x66 : 0, 0x2E, 0, 0);        /* ucomis x0,x0 */
            u8 *slow = jcc_fwd(e, CC_P);
            icount_add(be, 1);
            movq_rax_x(e, (int)sz, 0);
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            vop_slowpath(be, o, slow, -1);
            break;
        }
        case VC_FSELEM: {
            /* Scalar FP by-element: the element is a compile-time lane, so
             * load it straight from c->v[rm] by offset; FMLA/FMLS preload
             * the addend and use FMA3 (be_vop_ok gated). */
            int dbl = ((insn >> 22) & 3) == 3;
            unsigned eopc = (insn >> 12) & 0xf;
            unsigned H = (insn >> 11) & 1, L = (insn >> 21) & 1;
            unsigned idx = dbl ? H : ((H << 1) | L);
            u8 pfx = dbl ? 0xF2 : 0xF3;
            int res = 0;
            materialize_flags(be);
            sse_mem(e, pfx, 0x10, 0, OFF_V(rn));
            sse_mem(e, pfx, 0x10, 1, OFF_V(rm) + (s32)(idx << (dbl ? 3 : 2)));
            if (eopc == 0x9) {                           /* FMUL */
                sse_rr(e, pfx, 0x59, 0, 1);
            } else {                                     /* FMLA / FMLS */
                sse_mem(e, pfx, 0x10, 2, OFF_V(rd));
                fma231_rr(e, eopc == 0x5 ? 0xBD : 0xB9, dbl, 2, 0, 1);
                res = 2;
            }
            sse_rr(e, dbl ? 0x66 : 0, 0x2E, res, res);
            u8 *slow = jcc_fwd(e, CC_P);
            icount_add(be, 1);
            movq_rax_x(e, dbl, res);
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            vop_slowpath(be, o, slow, -1);
            break;
        }
        case VC_FELEM: {
            /* Vector FP by-element: pshufd-broadcast the element, then
             * mulps or FMA3 into the preloaded accumulator; NaN-gated like
             * VC_VF3S. The half form was declined. */
            unsigned Q = (insn >> 30) & 1;
            int dbl = ((insn >> 22) & 3) == 3;
            unsigned eopc = (insn >> 12) & 0xf;
            unsigned H = (insn >> 11) & 1, L = (insn >> 21) & 1;
            unsigned idx = dbl ? H : ((H << 1) | L);
            u8 pfx = dbl ? 0x66 : 0;
            int res = 0;
            materialize_flags(be);
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            sse_rr(e, 0x66, 0x70, 1, 1);                 /* broadcast elem */
            e8(e, dbl ? (idx ? 0xEE : 0x44) : (u8)(idx * 0x55));
            if (eopc == 0x9) {                           /* FMUL */
                sse_rr(e, pfx, 0x59, 0, 1);
            } else {                                     /* FMLA / FMLS */
                vop_src(be, 2, rd);
                fma231_rr(e, eopc == 0x5 ? 0xBC : 0xB8, dbl, 2, 0, 1);
                res = 2;
            }
            sse_rr(e, 0x66, 0x6F, 1, res);               /* NaN check copy */
            sse_rr(e, pfx, 0xC2, 1, 1); e8(e, 3);
            sse_rr(e, pfx, 0x50, RAX, 1);
            if (!dbl && !Q) alu_ri32(e, 0, 4, RAX, 0x3);
            op_rr(e, 0, 0x85, RAX, RAX);
            u8 *slow = jcc_fwd(e, CC_NE);
            icount_add(be, 1);
            vop_slowpath(be, o, slow, res);
            vop_dst(be, res, rd, (int)Q);
            break;
        }
        case VC_VH3: {   /* vector half three-same arith (self-counting, NaN-
                          * gated). Widen each half lane to single, compute
                          * packed (single ops round half correctly), narrow. */
            unsigned Q = (insn >> 30) & 1;
            unsigned key = (((insn >> 29) & 1) << 4) | (((insn >> 23) & 1) << 3) |
                           ((insn >> 11) & 7);
            u8 op = 0x58; int abd = 0;               /* FADD */
            switch (key) {
                case 0x0a: op = 0x5C; break;         /* FSUB */
                case 0x13: op = 0x59; break;         /* FMUL */
                case 0x17: op = 0x5E; break;         /* FDIV */
                case 0x1a: op = 0x5C; abd = 1; break;/* FABD */
                default: break;
            }
            materialize_flags(be);
            vcvtph2ps_m(e, 0, OFF_V(rn));            /* n lo */
            vcvtph2ps_m(e, 2, OFF_V(rm));            /* m lo */
            sse_rr(e, 0, op, 0, 2);
            if (abd) { sse_rr(e, 0x66, 0x76, 2, 2); sse_shift_i(e, 0x72, 2, 2, 1);
                       sse_rr(e, 0, 0x54, 0, 2); }   /* |.|: andps 0x7fffffff */
            if (Q) {
                vcvtph2ps_m(e, 1, OFF_V(rn) + 8);
                vcvtph2ps_m(e, 3, OFF_V(rm) + 8);
                sse_rr(e, 0, op, 1, 3);
                if (abd) { sse_rr(e, 0x66, 0x76, 3, 3); sse_shift_i(e, 0x72, 2, 3, 1);
                           sse_rr(e, 0, 0x54, 1, 3); }
            }
            sse_rr(e, 0x66, 0x6F, 4, 0);             /* NaN check copy */
            sse_rr(e, 0, 0xC2, 4, 4); e8(e, 3);      /* cmpps unord */
            if (Q) { sse_rr(e, 0x66, 0x6F, 5, 1); sse_rr(e, 0, 0xC2, 5, 5); e8(e, 3);
                     sse_rr(e, 0x66, 0xEB, 4, 5); }  /* por lo|hi */
            sse_rr(e, 0, 0x50, RAX, 4);
            op_rr(e, 0, 0x85, RAX, RAX);
            u8 *slow = jcc_fwd(e, CC_NE);
            icount_add(be, 1);
            vcvtps2ph_r(e, 4, 0, 0);                 /* narrow lo -> 4 halves */
            movq_rax_x(e, 1, 4);
            st64(e, RAX, R14, OFF_V(rd));
            if (Q) { vcvtps2ph_r(e, 5, 1, 0); movq_rax_x(e, 1, 5);
                     st64(e, RAX, R14, OFF_V(rd) + 8); }
            else st_imm_r14(e, OFF_V(rd) + 8, 0);
            vop_slowpath(be, o, slow, -1);
            break;
        }
        case VC_VHCM: {   /* vector half three-same compares -> per-lane mask */
            unsigned Q = (insn >> 30) & 1, U = (insn >> 29) & 1, a = (insn >> 23) & 1;
            int absf = (((insn >> 11) & 7) == 5);    /* FACGE/FACGT */
            vcvtph2ps_m(e, 0, OFF_V(rn));
            vcvtph2ps_m(e, 2, OFF_V(rm));
            if (Q) { vcvtph2ps_m(e, 1, OFF_V(rn) + 8); vcvtph2ps_m(e, 3, OFF_V(rm) + 8); }
            if (absf) {                              /* clear sign of all lanes */
                sse_rr(e, 0x66, 0x76, 6, 6); sse_shift_i(e, 0x72, 2, 6, 1);
                sse_rr(e, 0, 0x54, 0, 6); sse_rr(e, 0, 0x54, 2, 6);
                if (Q) { sse_rr(e, 0, 0x54, 1, 6); sse_rr(e, 0, 0x54, 3, 6); }
            }
            int lo, hi;
            if (!U) {                                /* FCMEQ: n==m */
                sse_rr(e, 0, 0xC2, 0, 2); e8(e, 0);
                if (Q) { sse_rr(e, 0, 0xC2, 1, 3); e8(e, 0); }
                lo = 0; hi = 1;
            } else {                                 /* GE: m<=n / GT: m<n */
                sse_rr(e, 0, 0xC2, 2, 0); e8(e, a ? 1 : 2);
                if (Q) { sse_rr(e, 0, 0xC2, 3, 1); e8(e, a ? 1 : 2); }
                lo = 2; hi = 3;
            }
            if (Q) { sse_rr(e, 0x66, 0x6B, lo, hi); sse_mem(e, 0, 0x11, lo, OFF_V(rd)); }
            else   { sse_rr(e, 0x66, 0x6B, lo, lo); movq_rax_x(e, 1, lo);
                     st64(e, RAX, R14, OFF_V(rd)); st_imm_r14(e, OFF_V(rd) + 8, 0); }
            break;
        }
        case VC_VH2M: {   /* vector half two-reg misc: FABS/FNEG/FSQRT (gated) +
                           * FCMxx#0 (mask). Self-counting. */
            unsigned Q = (insn >> 30) & 1;
            unsigned key = (((insn >> 29) & 1) << 6) | (((insn >> 23) & 1) << 5) |
                           ((insn >> 12) & 0x1f);
            int is_cmp = (key == 0x2c || key == 0x6c || key == 0x2d ||
                          key == 0x6d || key == 0x2e);
            vcvtph2ps_m(e, 0, OFF_V(rn));
            if (Q) vcvtph2ps_m(e, 1, OFF_V(rn) + 8);
            if (is_cmp) {                            /* compare vs 0 -> mask */
                u8 imm; int swap;
                switch (key) {
                    case 0x2c: swap = 1; imm = 1; break; /* GT: 0<n */
                    case 0x6c: swap = 1; imm = 2; break; /* GE: 0<=n */
                    case 0x2d: swap = 0; imm = 0; break; /* EQ: n==0 */
                    case 0x6d: swap = 0; imm = 2; break; /* LE: n<=0 */
                    default:   swap = 0; imm = 1; break; /* LT: n<0 */
                }
                sse_rr(e, 0x66, 0xEF, 2, 2);         /* xmm2 = 0 */
                if (Q) sse_rr(e, 0x66, 0xEF, 3, 3);
                int lo, hi;
                if (swap) { sse_rr(e, 0, 0xC2, 2, 0); e8(e, imm);
                            if (Q) { sse_rr(e, 0, 0xC2, 3, 1); e8(e, imm); }
                            lo = 2; hi = 3; }
                else      { sse_rr(e, 0, 0xC2, 0, 2); e8(e, imm);
                            if (Q) { sse_rr(e, 0, 0xC2, 1, 3); e8(e, imm); }
                            lo = 0; hi = 1; }
                icount_add(be, 1);
                if (Q) { sse_rr(e, 0x66, 0x6B, lo, hi); sse_mem(e, 0, 0x11, lo, OFF_V(rd)); }
                else   { sse_rr(e, 0x66, 0x6B, lo, lo); movq_rax_x(e, 1, lo);
                         st64(e, RAX, R14, OFF_V(rd)); st_imm_r14(e, OFF_V(rd) + 8, 0); }
                break;
            }
            materialize_flags(be);
            if (key == 0x2f) {                       /* FABS */
                sse_rr(e, 0x66, 0x76, 2, 2); sse_shift_i(e, 0x72, 2, 2, 1);
                sse_rr(e, 0, 0x54, 0, 2); if (Q) sse_rr(e, 0, 0x54, 1, 2);
            } else if (key == 0x6f) {                /* FNEG */
                sse_rr(e, 0x66, 0x76, 2, 2); sse_shift_i(e, 0x72, 6, 2, 31);
                sse_rr(e, 0, 0x57, 0, 2); if (Q) sse_rr(e, 0, 0x57, 1, 2);
            } else {                                 /* FSQRT (0x7f) */
                sse_rr(e, 0, 0x51, 0, 0); if (Q) sse_rr(e, 0, 0x51, 1, 1);
            }
            sse_rr(e, 0x66, 0x6F, 4, 0); sse_rr(e, 0, 0xC2, 4, 4); e8(e, 3);
            if (Q) { sse_rr(e, 0x66, 0x6F, 5, 1); sse_rr(e, 0, 0xC2, 5, 5); e8(e, 3);
                     sse_rr(e, 0x66, 0xEB, 4, 5); }
            sse_rr(e, 0, 0x50, RAX, 4); op_rr(e, 0, 0x85, RAX, RAX);
            u8 *slow = jcc_fwd(e, CC_NE);
            icount_add(be, 1);
            vcvtps2ph_r(e, 4, 0, 0); movq_rax_x(e, 1, 4);
            st64(e, RAX, R14, OFF_V(rd));
            if (Q) { vcvtps2ph_r(e, 5, 1, 0); movq_rax_x(e, 1, 5);
                     st64(e, RAX, R14, OFF_V(rd) + 8); }
            else st_imm_r14(e, OFF_V(rd) + 8, 0);
            vop_slowpath(be, o, slow, -1);
            break;
        }
        case VC_H1: {   /* scalar half 1-source (self-counting). Compute in
                         * single (widen->op->narrow); FABS/FNEG/FSQRT NaN-gate
                         * (the interpreter's f64_to_f16 canonicalizes NaN),
                         * FMOV is a plain 16-bit copy. */
            unsigned opc = (insn >> 15) & 0x3f;
            if (opc == 0x0) {                        /* FMOV: 16-bit copy */
                ld32(e, RAX, R14, OFF_V(rn));
                alu_ri32(e, 0, 4, RAX, 0xffff);
                icount_add(be, 1);
                st64(e, RAX, R14, OFF_V(rd));
                st_imm_r14(e, OFF_V(rd) + 8, 0);
                break;
            }
            materialize_flags(be);
            vcvtph2ps_m(e, 0, OFF_V(rn));            /* widen Hn -> single */
            if (opc == 0x1) {                        /* FABS: clear sign */
                sse_rr(e, 0x66, 0x76, 1, 1);         /* pcmpeqd ones */
                sse_shift_i(e, 0x72, 2, 1, 1);       /* psrld 1 -> 0x7fffffff */
                sse_rr(e, 0, 0x54, 0, 1);            /* andps */
            } else if (opc == 0x2) {                 /* FNEG: flip sign */
                sse_rr(e, 0x66, 0x76, 1, 1);
                sse_shift_i(e, 0x72, 6, 1, 31);      /* pslld 31 -> 0x80000000 */
                sse_rr(e, 0, 0x57, 0, 1);            /* xorps */
            } else {                                 /* opc 0x3: FSQRT */
                sse_rr(e, 0xF3, 0x51, 0, 0);         /* sqrtss */
            }
            sse_rr(e, 0, 0x2E, 0, 0);                /* ucomiss NaN? */
            u8 *slow = jcc_fwd(e, CC_P);
            vcvtps2ph_r(e, 1, 0, 0);                 /* narrow -> half */
            icount_add(be, 1);
            movq_rax_x(e, 0, 1);
            alu_ri32(e, 0, 4, RAX, 0xffff);
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            vop_slowpath(be, o, slow, -1);
            break;
        }
        case VC_H2: {   /* scalar half 2-source arith (self-counting, NaN-gated).
                         * FMAX/FMIN(NM) declined by be_vop_ok. */
            unsigned opc = (insn >> 12) & 0xf;
            materialize_flags(be);
            vcvtph2ps_m(e, 0, OFF_V(rn));
            vcvtph2ps_m(e, 1, OFF_V(rm));
            switch (opc) {
                case 0x1: sse_rr(e, 0, 0x5E, 0, 1); break;   /* FDIV */
                case 0x2: sse_rr(e, 0, 0x58, 0, 1); break;   /* FADD */
                case 0x3: sse_rr(e, 0, 0x5C, 0, 1); break;   /* FSUB */
                default:  sse_rr(e, 0, 0x59, 0, 1); break;   /* FMUL / FNMUL */
            }
            sse_rr(e, 0, 0x2E, 0, 0);                /* ucomiss NaN? */
            u8 *slow = jcc_fwd(e, CC_P);
            vcvtps2ph_r(e, 1, 0, 0);                 /* narrow -> half */
            icount_add(be, 1);
            movq_rax_x(e, 0, 1);
            alu_ri32(e, 0, 4, RAX, 0xffff);
            if (opc == 0x8) alu_ri32(e, 0, 6, RAX, 0x8000);  /* FNMUL: flip sign */
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            vop_slowpath(be, o, slow, -1);
            break;
        }
        /* VC_H3 (half FMADD) is declined by be_vop_ok on x86 (keeps the
         * interpreter helper) -- see the note there -- so it never reaches
         * here. The a64 backend computes it natively in double. */
        case VC_FCVT: {                          /* S<->D: plain casts */
            int to_dbl = ((insn >> 15) & 0x3f) == 0x5;
            if (to_dbl) {
                sse_mem(e, 0xF3, 0x10, 0, OFF_V(rn));
                sse_rr(e, 0xF3, 0x5A, 0, 0);             /* cvtss2sd */
            } else {
                sse_mem(e, 0xF2, 0x10, 0, OFF_V(rn));
                sse_rr(e, 0xF2, 0x5A, 0, 0);             /* cvtsd2ss */
            }
            movq_rax_x(e, to_dbl, 0);
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            break;
        }
        case VC_FCVTH: {   /* FP16 precision converts (F16C); self-counting.
                            * The interpreter widens half->single->double and
                            * narrows via a portable RNE routine that canon-
                            * icalizes NaN; F16C matches for finite values, so
                            * a NaN on the single/double side re-runs in the
                            * interpreter (source for narrow, result for widen). */
            int scalar = (insn >> 28) & 1;
            materialize_flags(be);                   /* ucomis / cmpps below */
            u8 *slow;
            if (scalar) {
                unsigned ftype = (insn >> 22) & 3, opc = (insn >> 15) & 0x3f;
                if (opc == 0x4 || opc == 0x5) {      /* h -> s / d (widen) */
                    int dbl = (opc == 0x5);
                    vcvtph2ps_m(e, 0, OFF_V(rn));    /* xmm0 lane0 = widen(h0) */
                    if (dbl) sse_rr(e, 0xF3, 0x5A, 0, 0);     /* cvtss2sd */
                    sse_rr(e, dbl ? 0x66 : 0, 0x2E, 0, 0);    /* ucomis x0,x0 */
                    slow = jcc_fwd(e, CC_P);
                    icount_add(be, 1);
                    movq_rax_x(e, dbl, 0);
                    st64(e, RAX, R14, OFF_V(rd));
                    st_imm_r14(e, OFF_V(rd) + 8, 0);
                } else {                             /* opc 0x7: s/d -> h (narrow) */
                    int dbl = (ftype == 1);
                    u8 pfx = dbl ? 0xF2 : 0xF3;
                    sse_mem(e, pfx, 0x10, 0, OFF_V(rn));      /* movss/sd = src */
                    sse_rr(e, dbl ? 0x66 : 0, 0x2E, 0, 0);    /* NaN? on source */
                    slow = jcc_fwd(e, CC_P);
                    if (dbl) sse_rr(e, 0xF2, 0x5A, 0, 0);     /* cvtsd2ss */
                    vcvtps2ph_r(e, 1, 0, 0);                  /* xmm1 low16 = half */
                    icount_add(be, 1);
                    movq_rax_x(e, 0, 1);                       /* movd eax */
                    alu_ri32(e, 0, 4, RAX, 0xffff);           /* keep lane0 only */
                    st64(e, RAX, R14, OFF_V(rd));
                    st_imm_r14(e, OFF_V(rd) + 8, 0);
                }
            } else {                                 /* vector FCVTL / FCVTN */
                unsigned Q = (insn >> 30) & 1, opc = (insn >> 12) & 0x1f;
                if (opc == 0x17) {                   /* FCVTL: 4h -> 4s (widen) */
                    vcvtph2ps_m(e, 0, OFF_V(rn) + (Q ? 8 : 0));
                    sse_rr(e, 0x66, 0x6F, 1, 0);              /* movdqa copy */
                    sse_rr(e, 0, 0xC2, 1, 1); e8(e, 3);       /* cmpps unord */
                    sse_rr(e, 0, 0x50, RAX, 1);               /* movmskps eax */
                    op_rr(e, 0, 0x85, RAX, RAX);
                    slow = jcc_fwd(e, CC_NE);
                    icount_add(be, 1);
                    sse_mem(e, 0, 0x11, 0, OFF_V(rd));        /* movups [rd]=4s */
                } else {                             /* FCVTN: 4s -> 4h (narrow) */
                    sse_mem(e, 0, 0x10, 0, OFF_V(rn));        /* movups = 4 singles */
                    sse_rr(e, 0x66, 0x6F, 1, 0);
                    sse_rr(e, 0, 0xC2, 1, 1); e8(e, 3);       /* NaN? on source */
                    sse_rr(e, 0, 0x50, RAX, 1);
                    op_rr(e, 0, 0x85, RAX, RAX);
                    slow = jcc_fwd(e, CC_NE);
                    vcvtps2ph_r(e, 1, 0, 0);                  /* xmm1 low64 = 4h */
                    icount_add(be, 1);
                    movq_rax_x(e, 1, 1);                       /* rax = 4 halves */
                    if (Q) {                                  /* FCVTN2: keep low */
                        st64(e, RAX, R14, OFF_V(rd) + 8);
                    } else {
                        st64(e, RAX, R14, OFF_V(rd));
                        st_imm_r14(e, OFF_V(rd) + 8, 0);
                    }
                }
            }
            vop_slowpath(be, o, slow, -1);
            break;
        }
        case VC_CVTIF: {                         /* SCVTF/UCVTF: C casts */
            int dbl = ((insn >> 22) & 3) == 1;
            unsigned sf = insn >> 31, uns = ((insn >> 16) & 7) == 3;
            int hsrc = ra_use(be, o->a);
            if (!sf) {
                if (uns) {                       /* (fp)(u32): zext + 64-cvt */
                    mov_rr(e, 0, RAX, hsrc);
                    cvtsi2f(e, dbl, 1, 0, RAX);
                } else {
                    cvtsi2f(e, dbl, 0, 0, hsrc); /* (fp)(s32) */
                }
            } else if (!uns) {
                cvtsi2f(e, dbl, 1, 0, hsrc);     /* (fp)(s64) */
            } else {                             /* (fp)(u64): gcc's shape */
                materialize_flags(be);
                mov_rr(e, 1, RAX, hsrc);
                op_rr(e, 1, 0x85, RAX, RAX);     /* test rax, rax */
                u8 *neg = jcc_fwd(e, CC_S);
                cvtsi2f(e, dbl, 1, 0, RAX);
                u8 *j = jmp_fwd(e);
                fwd_here(e, neg);                /* halve, keep lsb, double */
                mov_rr(e, 1, RCX, RAX);
                alu_ri32(e, 0, 4, RCX, 1);       /* and ecx, 1 */
                shift_ri(e, 1, 5, RAX, 1);       /* shr rax, 1 */
                op_rr(e, 1, 0x0B, RAX, RCX);     /* or rax, rcx */
                cvtsi2f(e, dbl, 1, 0, RAX);
                sse_rr(e, dbl ? 0xF2 : 0xF3, 0x58, 0, 0);   /* x0 += x0 */
                fwd_here(e, j);
            }
            movq_rax_x(e, dbl, 0);
            st64(e, RAX, R14, OFF_V(rd));
            st_imm_r14(e, OFF_V(rd) + 8, 0);
            break;
        }
        case VC_CVTFI: {
            /* FCVTZS/FCVTZU: replicate the interpreter's expressions —
             * a NaN gate up front (FPToFixed -> 0, like the C code's
             * `if (r != r) r = 0`), then the saturation compares around cvtt;
             * the S source is widened to double first, like the C code. */
            int dbl = ((insn >> 22) & 3) == 1;
            unsigned sf = insn >> 31, uns = ((insn >> 16) & 7) & 1;
            if (o->dst == VREG_ZERO) break;
            materialize_flags(be);
            sse_mem(e, dbl ? 0xF2 : 0xF3, 0x10, 0, OFF_V(rn));
            if (!dbl) sse_rr(e, 0xF3, 0x5A, 0, 0);       /* cvtss2sd */
            sse_rr(e, 0x66, 0x2E, 0, 0);                 /* ucomisd r,r: PF if NaN */
            u8 *jnan = jcc_fwd(e, CC_P);
            if (!uns) {
                mov_ri(e, 1, RAX, sf ? 0x43E0000000000000ULL     /* 2^63 */
                                     : 0x41DFFFFFFFC00000ULL);   /* 2^31-1 */
                movq_xr(e, 1, RAX);
                sse_rr(e, 0x66, 0x2E, 0, 1);             /* ucomisd r, max */
                u8 *jmax = jcc_fwd(e, CC_AE);
                mov_ri(e, 1, RAX, sf ? 0xC3E0000000000000ULL     /* -2^63 */
                                     : 0xC1E0000000000000ULL);   /* -2^31 */
                movq_xr(e, 1, RAX);
                sse_rr(e, 0x66, 0x2E, 1, 0);             /* ucomisd min, r */
                u8 *jmin = jcc_fwd(e, CC_AE);
                cvttd2si(e, sf, RAX, 0);                 /* in-range / NaN */
                u8 *j1 = jmp_fwd(e);
                fwd_here(e, jmax);
                mov_ri(e, 1, RAX, sf ? 0x7FFFFFFFFFFFFFFFULL : 0x7FFFFFFFULL);
                u8 *j2 = jmp_fwd(e);
                fwd_here(e, jmin);
                mov_ri(e, 1, RAX, sf ? 0x8000000000000000ULL : 0x80000000ULL);
                fwd_here(e, j1); fwd_here(e, j2);
            } else {
                sse_rr(e, 0x66, 0xEF, 1, 1);             /* xmm1 = 0.0 */
                sse_rr(e, 0x66, 0x2E, 1, 0);             /* ucomisd 0, r */
                u8 *jneg = jcc_fwd(e, CC_A);             /* r < 0 -> 0 */
                mov_ri(e, 1, RAX, sf ? 0x43F0000000000000ULL     /* 2^64 */
                                     : 0x41EFFFFFFFE00000ULL);   /* 2^32-1 */
                movq_xr(e, 1, RAX);
                sse_rr(e, 0x66, 0x2E, 0, 1);
                u8 *jmax = jcc_fwd(e, CC_AE);
                if (sf) {                        /* gcc's (u64)double shape */
                    mov_ri(e, 1, RAX, 0x43E0000000000000ULL);    /* 2^63 */
                    movq_xr(e, 1, RAX);
                    sse_rr(e, 0x66, 0x2F, 0, 1);         /* comisd r, 2^63 */
                    u8 *big = jcc_fwd(e, CC_AE);
                    cvttd2si(e, 1, RAX, 0);
                    u8 *jj = jmp_fwd(e);
                    fwd_here(e, big);
                    sse_rr(e, 0xF2, 0x5C, 0, 1);         /* r -= 2^63 */
                    cvttd2si(e, 1, RAX, 0);
                    e8(e, 0x48); e8(e, 0x0F); e8(e, 0xBA);
                    e8(e, 0xF8); e8(e, 0x3F);            /* btc rax, 63 */
                    fwd_here(e, jj);
                } else {                         /* (u32): 64-bit cvtt, low */
                    cvttd2si(e, 1, RAX, 0);
                    mov_rr(e, 0, RAX, RAX);
                }
                u8 *j1 = jmp_fwd(e);
                fwd_here(e, jneg);
                mov_ri(e, 0, RAX, 0);
                u8 *j2 = jmp_fwd(e);
                fwd_here(e, jmax);
                mov_ri(e, 1, RAX, sf ? ~0ULL : 0xFFFFFFFFULL);
                fwd_here(e, j1); fwd_here(e, j2);
            }
            u8 *jdone = jmp_fwd(e);
            fwd_here(e, jnan);
            mov_ri(e, 0, RAX, 0);                        /* NaN -> 0 (FPToFixed) */
            fwd_here(e, jdone);
            int hd = ra_def(be, o->dst);
            mov_rr(e, 1, hd, RAX);
            break;
        }
        case VC_FCCMP: {
            int dbl = ((insn >> 22) & 3) == 1;
            unsigned cond = (insn >> 12) & 0xf;
            u32 nzcv_imm = (u32)(insn & 0xf) << 28;
            int cc = cond_setup(be, cond);
            if (cc == CC_NEVER) {
                mov_ri(e, 0, RAX, nzcv_imm);
                st32(e, RAX, R14, OFF_NZCV);
                be->fl = FL_MEM;
                break;
            }
            u8 *jf = (cc == CC_ALWAYS) ? NULL : jcc_fwd(e, cc ^ 1);
            int half = ((insn >> 22) & 3) == 3;  /* taken: FCMP recompose */
            if (half) {                          /* widen halves -> single */
                vcvtph2ps_m(e, 0, OFF_V(rn));
                vcvtph2ps_m(e, 1, OFF_V(rm));
                sse_rr(e, 0, 0x2E, 0, 1);        /* ucomiss */
            } else {
                u8 mpfx = dbl ? 0xF2 : 0xF3;
                sse_mem(e, mpfx, 0x10, 0, OFF_V(rn));
                sse_mem(e, mpfx, 0x10, 1, OFF_V(rm));
                if (dbl) sse_rr(e, 0x66, 0x2E, 0, 1);
                else     sse_rr(e, 0, 0x2E, 0, 1);
            }
            u8 *juo = jcc_fwd(e, CC_P);
            u8 *jlt = jcc_fwd(e, CC_B);
            u8 *jeq = jcc_fwd(e, CC_E);
            mov_ri(e, 0, RAX, 0x20000000u);      /* gt: C */
            u8 *j1 = jmp_fwd(e);
            fwd_here(e, juo);
            mov_ri(e, 0, RAX, 0x30000000u);      /* uo: C|V */
            u8 *j2 = jmp_fwd(e);
            fwd_here(e, jlt);
            mov_ri(e, 0, RAX, 0x80000000u);      /* lt: N */
            u8 *j3 = jmp_fwd(e);
            fwd_here(e, jeq);
            mov_ri(e, 0, RAX, 0x60000000u);      /* eq: Z|C */
            fwd_here(e, j1); fwd_here(e, j2); fwd_here(e, j3);
            if (jf) {
                u8 *jend = jmp_fwd(e);
                fwd_here(e, jf);                 /* cond false: imm nzcv */
                mov_ri(e, 0, RAX, nzcv_imm);
                fwd_here(e, jend);
            }
            st32(e, RAX, R14, OFF_NZCV);
            be->fl = FL_MEM;
            break;
        }
        case VC_FMOVI: {                         /* scalar FMOV #imm */
            unsigned vd = (o->aux >> 8) & 31;
            mov_ri(e, 1, RAX, o->imm);
            st64(e, RAX, R14, OFF_V(vd));
            st_imm_r14(e, OFF_V(vd) + 8, 0);
            break;
        }
        case VC_FMOVG: {                         /* gpr <-> fpr bit moves */
            unsigned sf = insn >> 31, rmode = (insn >> 19) & 3;
            unsigned opcode = (insn >> 16) & 7;
            int top = (sf == 1 && ((insn >> 22) & 3) == 2 && rmode == 1);
            if (opcode == 6) {                   /* to gpr */
                if (o->dst == VREG_ZERO) break;
                if (top)      ld64(e, RAX, R14, OFF_V(rn) + 8);
                else if (sf)  ld64(e, RAX, R14, OFF_V(rn));
                else          ld32(e, RAX, R14, OFF_V(rn));
                int hd = ra_def(be, o->dst);
                mov_rr(e, 1, hd, RAX);
            } else {                             /* from gpr */
                int hsrc = ra_use(be, o->a);
                if (top) {
                    st64(e, hsrc, R14, OFF_V(rd) + 8);       /* keep low half */
                } else if (sf) {
                    st64(e, hsrc, R14, OFF_V(rd));
                    st_imm_r14(e, OFF_V(rd) + 8, 0);
                } else {
                    mov_rr(e, 0, RAX, hsrc);                 /* zext32 */
                    st64(e, RAX, R14, OFF_V(rd));
                    st_imm_r14(e, OFF_V(rd) + 8, 0);
                }
            }
            break;
        }
    }
}

/* ---- inline atomics (IRO_ATOMIC; decode.c ldst_exclusive/ldst_atomic are
 * the reference semantics) ---- */

/* Size-suffixed r/m op on [rdx]: `reg` is the /r field. `two` selects the
 * 0F-prefixed table; opc32 is the 32-bit-form opcode (byte form = opc32-1,
 * the x86 convention). Handles 66/REX.W and the dil/sil byte-REX quirk. */
static void mem_op_rdx(Emit *e, unsigned szlog, int two, u8 opc32, int reg) {
    if (szlog == 1) e8(e, 0x66);
    u8 r = (u8)(0x40 | ((szlog == 3) << 3) | (((reg >> 3) & 1) << 2));
    if (r != 0x40 || (szlog == 0 && reg >= 4)) e8(e, r);
    if (two) e8(e, 0x0F);
    e8(e, szlog == 0 ? (u8)(opc32 - 1) : opc32);
    e8(e, (u8)(((reg & 7) << 3) | 2));           /* [rdx] */
}
/* Zero-extending load of [rdx] into rax. */
static void ld_zext_rdx(Emit *e, unsigned szlog) {
    switch (szlog) {
        case 0: e8(e, 0x0F); e8(e, 0xB6); e8(e, 0x02); break;
        case 1: e8(e, 0x0F); e8(e, 0xB7); e8(e, 0x02); break;
        case 2: e8(e, 0x8B); e8(e, 0x02); break;
        default: e8(e, 0x48); e8(e, 0x8B); e8(e, 0x02); break;
    }
}
/* rax = zext_szlog(src). */
static void mov_zext_r(Emit *e, unsigned szlog, int dst, int src) {
    if (szlog == 3) { mov_rr(e, 1, dst, src); return; }
    if (szlog == 2) { mov_rr(e, 0, dst, src); return; }
    u8 r = (u8)(0x40 | (((dst >> 3) & 1) << 2) | ((src >> 3) & 1));
    if (r != 0x40 || (szlog == 0 && src >= 4)) e8(e, r);
    e8(e, 0x0F);
    e8(e, szlog == 0 ? 0xB6 : 0xB7);
    e8(e, (u8)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}
static void mov_sext_r(Emit *e, unsigned szlog, int dst, int src) {
    if (szlog == 3) { mov_rr(e, 1, dst, src); return; }
    rex(e, 1, dst, 0, src);
    if (szlog == 2) e8(e, 0x63);                 /* movsxd */
    else { e8(e, 0x0F); e8(e, szlog ? 0xBF : 0xBE); }
    e8(e, (u8)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}
static void mov_zext_rax(Emit *e, unsigned szlog, int src) {
    if (szlog == 3) { mov_rr(e, 1, RAX, src); return; }
    if (szlog == 2) { mov_rr(e, 0, RAX, src); return; }
    u8 r = (u8)(0x40 | ((src >> 3) & 1));        /* REX.B for r8+; forced
                                                  * for sil/dil byte source */
    if (r != 0x40 || (szlog == 0 && src >= 4)) e8(e, r);
    e8(e, 0x0F);
    e8(e, szlog == 0 ? 0xB6 : 0xB7);
    e8(e, (u8)(0xC0 | (RAX << 3) | (src & 7)));
}
static void jcc_to(Emit *e, int cc, const u8 *target) {
    s64 rel = target - (e->rx + 6);
    e8(e, 0x0F); e8(e, (u8)(0x80 | cc));
    e32(e, (u32)(s32)rel);
}

#define OFF_EXCL_VALID ((s32)offsetof(CPU, excl_valid))
#define OFF_EXCL_ADDR  ((s32)offsetof(CPU, excl_addr))
#define OFF_EXCL_SIZE  ((s32)offsetof(CPU, excl_size))
#define OFF_EXCL_VAL   ((s32)offsetof(CPU, excl_val))

/* One IRO_ATOMIC. Fast path: align gate + D-TLB probe (write perm for
 * anything that may store) + host lock-prefixed op; the loaded/old value
 * converges in rax exactly like emit_mem's loads. Any miss/misalign re-runs
 * the instruction via jit_exec1 (which also handles the alignment fault and
 * counts the insn; the fast path bumps icount inline instead — IRO_ATOMIC
 * is not in ninsns). */
static void emit_atomic(BE *be, const IRBlock *ir, int i) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    unsigned kind = AT_KIND(o->aux), szlog = AT_SZL(o->aux);
    unsigned sz = 1u << szlog;
    int is_load_kind = (kind == AT_LDX || kind == AT_LDAR);
    int need = is_load_kind ? 1 /*PTE_R*/ : 2 /*PTE_W*/;
    int uses_b = !(kind == AT_LDX || kind == AT_LDAR);

    materialize_flags(be);
    int hb = uses_b ? ra_use(be, o->b) : -1;
    int hs = (kind == AT_CAS) ? ra_use(be, o->cc) : -1;
    int ha = ra_use(be, o->a);
    mov_rr(e, 1, RSI, ha);                       /* va (no offset forms) */

    u8 *slow0 = NULL, *slow1 = NULL, *slow2 = NULL, *slow3 = NULL;
    if (UNLIKELY(be->env->slowmem)) {
        slow0 = jmp_fwd(e);
    } else {
        if (sz > 1) {                            /* alignment gate */
            e8(e, 0x40); e8(e, 0xF6); e8(e, 0xC6); e8(e, (u8)(sz - 1));
            slow1 = jcc_fwd(e, CC_NE);           /* test sil, sz-1 ; jnz */
        }
        mov_rr(e, 1, RAX, RSI);                  /* aligned: never crosses */
        shift_ri(e, 1, 5, RAX, 12);
        mov_rr(e, 0, RCX, RSI);
        shift_ri(e, 0, 5, RCX, 12);
        alu_ri32(e, 0, 4, RCX, A64_DTLB_ENTRIES - 1);
        shift_ri(e, 0, 4, RCX, 4);
        op_rm(e, 1, 0x03, RCX, R15, (s32)offsetof(JitEnv, dtlb));
        op_rm(e, 1, 0x39, RAX, RCX, 0);
        slow2 = jcc_fwd(e, CC_NE);
        ld64(e, RDX, RCX, 8);
        e8(e, 0xF6); e8(e, 0xC2); e8(e, (u8)need);
        slow3 = jcc_fwd(e, CC_E);
        alu_ri32(e, 1, 4, RDX, 0xFFFFFFF8u);
        mov_rr(e, 0, RAX, RSI);
        alu_ri32(e, 0, 4, RAX, 0xfff);
        op_rr(e, 1, 0x01, RAX, RDX);             /* rdx = host ptr */
    }

    /* fast path retires unconditionally from here */
    u32 fix_fast = cache_off(be);
    icount_add(be, 1);

    switch (kind) {
        case AT_LDX:
            ld_zext_rdx(e, szlog);
            st64(e, RSI, R14, OFF_EXCL_ADDR);
            st_imm_r14(e, OFF_EXCL_SIZE, sz);
            st64(e, RAX, R14, OFF_EXCL_VAL);
            st_imm8_r14(e, OFF_EXCL_VALID, 1);
            break;                               /* x86 loads are acquire */
        case AT_STX: {
            /* monitor check; on any mismatch status=1 without a store */
            e8(e, 0x41); e8(e, 0x80);            /* cmp byte [r14+..], 0 */
            e8(e, (u8)(0xB8 | (R14 & 7)));
            e32(e, (u32)OFF_EXCL_VALID); e8(e, 0);
            u8 *f1 = jcc_fwd(e, CC_E);
            ld64(e, RAX, R14, OFF_EXCL_ADDR);
            op_rr(e, 1, 0x39, RSI, RAX);         /* cmp rax, rsi */
            u8 *f2 = jcc_fwd(e, CC_NE);
            ld64(e, RAX, R14, OFF_EXCL_SIZE);
            alu_ri32(e, 1, 7, RAX, sz);          /* cmp rax, sz */
            u8 *f3 = jcc_fwd(e, CC_NE);
            ld64(e, RAX, R14, OFF_EXCL_VAL);     /* expected */
            e8(e, 0xF0);                         /* lock cmpxchg [rdx], hb */
            mem_op_rdx(e, szlog, 1, 0xB1, hb);
            e8(e, 0x0F); e8(e, 0x95); e8(e, 0xC0);   /* setne al */
            e8(e, 0x0F); e8(e, 0xB6); e8(e, 0xC0);   /* movzx eax, al */
            u8 *join = jmp_fwd(e);
            fwd_here(e, f1); fwd_here(e, f2); fwd_here(e, f3);
            mov_ri(e, 0, RAX, 1);
            fwd_here(e, join);
            st_imm8_r14(e, OFF_EXCL_VALID, 0);   /* cleared on both paths */
            break;
        }
        case AT_LDAR:                            /* mov = acquire on TSO */
            ld_zext_rdx(e, szlog);
            break;
        case AT_STLR:                            /* mov = atomic + release */
            st_rdx_sized(e, szlog, hb);
            break;
        case AT_SWP:
            mov_rr(e, 1, RCX, hb);
            e8(e, 0xF0);                         /* lock xchg [rdx], rcx */
            mem_op_rdx(e, szlog, 0, 0x87, RCX);
            mov_zext_rax(e, szlog, RCX);
            break;
        case AT_LDADD:
            if (o->dst == VREG_ZERO) {           /* STADD: lock add */
                e8(e, 0xF0);
                mem_op_rdx(e, szlog, 0, 0x01, hb);
            } else {
                mov_rr(e, 1, RCX, hb);
                e8(e, 0xF0);                     /* lock xadd [rdx], rcx */
                mem_op_rdx(e, szlog, 1, 0xC1, RCX);
                mov_zext_rax(e, szlog, RCX);
            }
            break;
        case AT_LDCLR: case AT_LDEOR: case AT_LDSET: {
            u8 memop = kind == AT_LDCLR ? 0x21 : kind == AT_LDEOR ? 0x31 : 0x09;
            if (o->dst == VREG_ZERO) {           /* ST<op>: one lock op */
                if (kind == AT_LDCLR) {
                    mov_rr(e, 1, RCX, hb);
                    rex(e, 1, 0, 0, RCX); e8(e, 0xF7); e8(e, 0xD1);  /* not rcx */
                    e8(e, 0xF0); mem_op_rdx(e, szlog, 0, memop, RCX);
                } else {
                    e8(e, 0xF0); mem_op_rdx(e, szlog, 0, memop, hb);
                }
            } else {                             /* need old: cmpxchg loop */
                ld_zext_rdx(e, szlog);           /* rax = expected */
                const u8 *loop = e->rx;
                mov_rr(e, 1, RCX, hb);
                if (kind == AT_LDCLR) {
                    rex(e, 1, 0, 0, RCX); e8(e, 0xF7); e8(e, 0xD1);  /* not */
                    op_rr(e, 1, 0x23, RCX, RAX); /* and rcx, rax */
                } else if (kind == AT_LDEOR) {
                    op_rr(e, 1, 0x33, RCX, RAX); /* xor rcx, rax */
                } else {
                    op_rr(e, 1, 0x0B, RCX, RAX); /* or rcx, rax */
                }
                e8(e, 0xF0);                     /* lock cmpxchg [rdx], rcx */
                mem_op_rdx(e, szlog, 1, 0xB1, RCX);
                jcc_to(e, CC_NE, loop);          /* rax stays zero-extended */
            }
            break;
        }
        case AT_LDSMAX: case AT_LDSMIN: case AT_LDUMAX: case AT_LDUMIN: {
            /* cmpxchg loop; new value = compare-select of old vs operand at
             * the access width/signedness (decode.c LSE_RMW cases 4-7). The
             * extended copies feed the compare; the stored value's low bytes
             * are the same either way, so cmov picks between raw regs. */
            int sgn = (kind == AT_LDSMAX || kind == AT_LDSMIN);
            int mx = (kind == AT_LDSMAX || kind == AT_LDUMAX);
            u8 cc = (u8)(sgn ? (mx ? CC_G : CC_L) : (mx ? CC_A : CC_B));
            ld_zext_rdx(e, szlog);               /* rax = expected (zext) */
            const u8 *loop = e->rx;
            if (sgn) {
                mov_sext_r(e, szlog, RSI, RAX);  /* va in rsi is dead here */
                mov_sext_r(e, szlog, RCX, hb);
                op_rr(e, 1, 0x39, RCX, RSI);     /* cmp rsi, rcx */
            } else {
                mov_zext_r(e, szlog, RCX, hb);
                op_rr(e, 1, 0x39, RCX, RAX);     /* cmp rax, rcx */
            }
            op0f_rr(e, 1, (u8)(0x40 | cc), RCX, RAX);   /* old wins: rcx=rax */
            e8(e, 0xF0);                         /* lock cmpxchg [rdx], rcx */
            mem_op_rdx(e, szlog, 1, 0xB1, RCX);
            jcc_to(e, CC_NE, loop);              /* rax = old (zext) */
            break;
        }
        case AT_CAS:
            mov_zext_rax(e, szlog, hs);          /* expected */
            e8(e, 0xF0);                         /* lock cmpxchg [rdx], hb */
            mem_op_rdx(e, szlog, 1, 0xB1, hb);
            break;                               /* old in rax (still zext) */
    }
    u8 *done = jmp_fwd(e);

    /* ---- slow path: re-run the insn in the interpreter ---- */
    fwd_here(e, slow0);
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    fwd_here(e, slow3);
    be_fixup_add(be->env, fix_fast, cache_off(be));
    slow_store_dirty(be);
    mov_rr(e, 1, RDI, R14);                      /* jit_exec1(c, pc, insn) */
    rex(e, 1, 0, 0, RSI); e8(e, (u8)(0xB8 | RSI)); e64(e, o->imm2pc);
    mov_ri(e, 0, RDX, (u32)o->imm);
    ld64(e, RAX, R15, (s32)offsetof(JitEnv, helper_exec1));
    e8(e, 0xFF); e8(e, 0xD0);
    op_rr(e, 0, 0x85, RAX, RAX);
    u8 *ok = jcc_fwd(e, CC_E);
    exit_plain(be, o->icnt);
    fwd_here(e, ok);
    slow_reload_clobbered(be);
    if (o->dst != VREG_ZERO)
        ld_home(be, RAX, o->dst);                /* exec_a64 committed it */
    fwd_here(e, done);

    if (o->dst != VREG_ZERO) {
        int hd = ra_def(be, o->dst);
        mov_rr(e, 1, hd, RAX);
    }
    be->fl = FL_MEM;
}

static int emit_op(BE *be, const IRBlock *ir, int i);

int be_emit_block(Emit *e, JitEnv *env, JBlock *b, const struct IRBlock *ir) {
    BE be;
    memset(&be, 0, sizeof be);
    be.e = e;
    be.env = env;
    be.b = b;
    for (int v = 0; v < VREG_N; v++) be.v2h[v] = -1;
    for (int h = 0; h < HREG_N; h++) be.h2v[h] = VREG_N;
    for (int v = 0; v < 32; v++) be.vv2h[v] = -1;
    for (int h = 0; h < 16; h++) be.vh2v[h] = 32;
    be.fl = FL_MEM;
    b->exit_pc[0] = b->exit_pc[1] = ~0ULL;
    b->exit_off[0] = b->exit_off[1] = 0;
    b->patched[0] = b->patched[1] = 0;
    b->in_head = ~0u;

    /* safepoint: the hot entry is just cmp+jcc; the exit body sits after
     * the block's last op (cold, out of the decoder's way). c->pc must be
     * restored to the block's start on that path: a direct chain jump into
     * this block bypassed the predecessor's exit-stub pc write, so c->pc
     * is stale on entry — emu_loop needs the true resume pc to deliver
     * the pending signal / dispatch correctly. */
    op_rm(e, 0, 0x83, 7, R15, (s32)offsetof(JitEnv, interrupt));
    e8(e, 0x00);                                  /* the imm8 of 83 /7 */
    u8 *cold = jcc_fwd(e, CC_NE);

    for (int i = 0; i < ir->n && !e->overflow; )
        i += emit_op(&be, ir, i);

    if (e->overflow) return -1;
    fwd_here(e, cold);
    mov_ri(e, 1, RAX, b->pc);
    st64(e, RAX, R14, OFF_PC);
    exit_plain(&be, 0);
    return e->overflow ? -1 : 0;
}

static void emit_call1(BE *be, const IROp *o) {
    Emit *e = be->e;
    sync_all(be);
    materialize_flags(be);
    invalidate_all(be);
    mov_rr(e, 1, RDI, R14);                       /* arg0 = CPU* */
    rex(e, 1, 0, 0, RSI); e8(e, 0xB8 | RSI); e64(e, o->imm);   /* movabs rsi */
    mov_ri(e, 0, RDX, o->aux);                    /* insn word */
    ld64(e, RAX, R15,
         o->w ? (s32)offsetof(JitEnv, helper_exec1_ic)
              : (s32)offsetof(JitEnv, helper_exec1));
    e8(e, 0xFF); e8(e, 0xD0);                     /* call rax */
    op_rr(e, 0, 0x85, RAX, RAX);                  /* test eax, eax */
    u8 *cont = jcc_fwd(e, CC_E);
    exit_plain(be, o->icnt);
    fwd_here(e, cont);
    be->fl = FL_MEM;
}

/* Emits ir->ops[i]; returns how many IR ops were consumed (terminal
 * conditional branches consume their paired fallthrough IRO_JMP). */
static int emit_op(BE *be, const IRBlock *ir, int i) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    int w = o->w;

    switch (o->op) {
        case IRO_NOP:
            break;
        case IRO_MOVI: {
            int hd = ra_def(be, o->dst);
            mov_ri(e, w, hd, w ? o->imm : (u32)o->imm);
            break;
        }
        case IRO_MOV: {
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            mov_rr(e, w, hd, ha);
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }
        case IRO_MOVK: {
            unsigned sh = o->cc;
            u64 keep = ~(0xffffULL << sh);
            int hd = def_alias(be, o->dst, o->a, 1);
            if (w && !imm_is_s32(keep)) {
                mov_ri(e, 1, RDX, keep);
                op_rr(e, 1, 0x21, RDX, hd);       /* and hd, rdx */
            } else {
                alu_ri32(e, w, 4, hd, (u32)keep);
            }
            if (o->imm) {
                if (w && o->imm > 0x7fffffffULL) {
                    mov_ri(e, 1, RDX, o->imm);
                    op_rr(e, 1, 0x09, RDX, hd);
                } else {
                    alu_ri32(e, w, 1, hd, (u32)o->imm);
                }
            }
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }

        case IRO_ADD:
            if (be->fl != FL_MEM && flags_next_use(ir, i) == FLAGS_CONSUMED) {
                int ha = ra_use(be, o->a);
                int hb = ra_use(be, o->b);
                int hd = ra_def(be, o->dst);
                lea_bid(e, hd, ha, hb, 0);
                if (!w) mov_rr(e, 0, hd, hd);
                break;
            }
            alu_rrr(be, w, 0x01, 1, o->dst, o->a, o->b);
            break;
        case IRO_SUB:
            if (be->fl != FL_MEM && flags_next_use(ir, i) == FLAGS_CONSUMED) {
                int ha = ra_use(be, o->a);
                int hb = ra_use(be, o->b);
                mov_rr(e, 1, RDX, hb);
                rex(e, 1, 0, 0, RDX); e8(e, 0xF7); e8(e, 0xD2);   /* not */
                int hd = ra_def(be, o->dst);
                lea_bid(e, hd, ha, RDX, 1);      /* a + ~b + 1 */
                if (!w) mov_rr(e, 0, hd, hd);
                break;
            }
            alu_rrr(be, w, 0x29, 0, o->dst, o->a, o->b);
            break;
        case IRO_AND:  alu_rrr(be, w, 0x21, 1, o->dst, o->a, o->b); break;
        case IRO_ORR:  alu_rrr(be, w, 0x09, 1, o->dst, o->a, o->b); break;
        case IRO_EOR:  alu_rrr(be, w, 0x31, 1, o->dst, o->a, o->b); break;
        case IRO_BIC: case IRO_ORN: case IRO_EON: {
            int hb = ra_use(be, o->b);
            mov_rr(e, 1, RDX, hb);
            rex(e, 1, 0, 0, RDX); e8(e, 0xF7); e8(e, 0xD2);   /* not rdx */
            int hd = def_alias(be, o->dst, o->a, 1);
            u8 opc = o->op == IRO_BIC ? 0x21 : o->op == IRO_ORN ? 0x09 : 0x31;
            op_rr(e, w, opc, RDX, hd);
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }

        case IRO_ADC: case IRO_SBC: {
            /* Non-S: guest NZCV must survive, but adc/sbb clobber EFLAGS —
             * materialize first, then recover C from the word. */
            int sbc = (o->op == IRO_SBC);
            materialize_flags(be);
            carry_to_host(be, sbc);
            alu_rrr(be, w, sbc ? 0x19 : 0x11, !sbc, o->dst, o->a, o->b);
            break;
        }
        case IRO_ADCS: case IRO_SBCS: {
            int sbc = (o->op == IRO_SBCS);
            if (o->flags_dead && o->dst == VREG_ZERO) break;   /* fully dead */
            carry_to_host(be, sbc);
            if (o->flags_dead) {
                alu_rrr(be, w, sbc ? 0x19 : 0x11, !sbc, o->dst, o->a, o->b);
                break;
            }
            alu_rrr_S(be, w, sbc ? 0x19 : 0x11, o->dst, o->a, o->b);
            /* x86 adc/sbb CF and OF are exactly ARM's C (inverted for the
             * subtract) and V of the 3-input op: the existing kinds fit. */
            set_flags_state(be, ir, i, sbc ? FL_SUB : FL_ADD);
            break;
        }

        case IRO_ADDS:
            if (o->flags_dead) { alu_rrr(be, w, 0x01, 1, o->dst, o->a, o->b); break; }
            alu_rrr_S(be, w, 0x01, o->dst, o->a, o->b);
            set_flags_state(be, ir, i, FL_ADD);
            break;
        case IRO_SUBS:
            if (o->flags_dead) { alu_rrr(be, w, 0x29, 0, o->dst, o->a, o->b); break; }
            alu_rrr_S(be, w, 0x29, o->dst, o->a, o->b);
            set_flags_state(be, ir, i, FL_SUB);
            break;
        case IRO_ANDS:
            if (o->flags_dead) { alu_rrr(be, w, 0x21, 1, o->dst, o->a, o->b); break; }
            alu_rrr_S(be, w, 0x21, o->dst, o->a, o->b);
            set_flags_state(be, ir, i, FL_LOGIC);
            break;
        case IRO_BICS: {
            int hb = ra_use(be, o->b);
            mov_rr(e, 1, RDX, hb);
            rex(e, 1, 0, 0, RDX); e8(e, 0xF7); e8(e, 0xD2);   /* not rdx */
            if (o->dst == VREG_ZERO) {
                int ha = ra_use(be, o->a);
                op_rr(e, w, 0x85, RDX, ha);       /* test ha, rdx */
            } else {
                int hd = def_alias(be, o->dst, o->a, 1);
                op_rr(e, w, 0x21, RDX, hd);
            }
            if (o->flags_dead) break;
            set_flags_state(be, ir, i, FL_LOGIC);
            break;
        }

        case IRO_ADDI: case IRO_SUBI: case IRO_ANDI: case IRO_ORRI:
        case IRO_EORI: {
            int n;                                /* 81 /n */
            u8 rr;                                /* reg-reg opcode */
            switch (o->op) {
                case IRO_ADDI: n = 0; rr = 0x01; break;
                case IRO_SUBI: n = 5; rr = 0x29; break;
                case IRO_ANDI: n = 4; rr = 0x21; break;
                case IRO_ORRI: n = 1; rr = 0x09; break;
                default:       n = 6; rr = 0x31; break;
            }
            u64 imm = w ? o->imm : (u32)o->imm;
            if ((o->op == IRO_ADDI || o->op == IRO_SUBI) &&
                be->fl != FL_MEM && flags_next_use(ir, i) == FLAGS_CONSUMED) {
                /* flag-preserving: lea hd, [ha +- imm] (32-bit results
                 * wrap identically in the low half, then zero-extend) */
                s64 d = o->op == IRO_ADDI ? (s64)imm : -(s64)imm;
                if (!w) d = (s32)(u32)d;
                if (d >= INT32_MIN && d <= INT32_MAX) {
                    int ha = ra_use(be, o->a);
                    int hd = ra_def(be, o->dst);
                    lea_rbd(e, hd, ha, (s32)d);
                    if (!w) mov_rr(e, 0, hd, hd);
                    break;
                }
            }
            int hd = def_alias(be, o->dst, o->a, 1);
            if (!w || imm_is_s32(imm)) {
                alu_ri32(e, w, n, hd, (u32)imm);
            } else {
                mov_ri(e, 1, RDX, imm);
                op_rr(e, 1, rr, RDX, hd);
            }
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }
        case IRO_ADDIS: case IRO_SUBIS: case IRO_ANDIS: {
            int plain = o->flags_dead;
            int n = o->op == IRO_ADDIS ? 0 : o->op == IRO_SUBIS ? 5 : 4;
            u64 imm = w ? o->imm : (u32)o->imm;
            int big = w && !imm_is_s32(imm);
            if (big) mov_ri(e, 1, RDX, imm);
            if (o->dst == VREG_ZERO && !plain) {  /* cmp/cmn/tst */
                int ha = ra_use(be, o->a);
                if (o->op == IRO_ADDIS) {         /* cmn: need add result */
                    mov_rr(e, 1, RAX, ha);
                    if (big) op_rr(e, w, 0x01, RDX, RAX);
                    else alu_ri32(e, w, 0, RAX, (u32)imm);
                } else if (o->op == IRO_SUBIS) {
                    if (big) op_rr(e, w, 0x39, RDX, ha);
                    else alu_ri32(e, w, 7, ha, (u32)imm);
                } else {
                    if (big) op_rr(e, w, 0x85, RDX, ha);
                    else {
                        rex(e, w, 0, 0, ha); e8(e, 0xF7);
                        e8(e, (u8)(0xC0 | (ha & 7)));
                        e32(e, (u32)imm);
                    }
                }
            } else {
                int hd = def_alias(be, o->dst, o->a, 1);
                if (big) {
                    u8 rr2 = o->op == IRO_ADDIS ? 0x01
                           : o->op == IRO_SUBIS ? 0x29 : 0x21;
                    op_rr(e, 1, rr2, RDX, hd);
                } else {
                    alu_ri32(e, w, n, hd, (u32)imm);
                }
            }
            if (plain) {
                if (!w && o->dst != VREG_ZERO)
                    mov_rr(e, 0, be->v2h[o->dst], be->v2h[o->dst]);
                break;
            }
            set_flags_state(be, ir, i,
                            o->op == IRO_ADDIS ? FL_ADD
                          : o->op == IRO_SUBIS ? FL_SUB : FL_LOGIC);
            break;
        }

        case IRO_LSLI: case IRO_LSRI: case IRO_ASRI: case IRO_RORI: {
            static const u8 n[] = { 4, 5, 7, 1 };
            int hd = def_alias(be, o->dst, o->a, w ? 1 : 0);
            if (o->imm) shift_ri(e, w, n[o->op - IRO_LSLI], hd,
                                 (unsigned)o->imm);
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }
        case IRO_LSLV: case IRO_LSRV: case IRO_ASRV: case IRO_RORV: {
            static const u8 n[] = { 4, 5, 7, 1 };
            int hb = ra_use(be, o->b);
            mov_rr(e, 1, RCX, hb);
            int hd = def_alias(be, o->dst, o->a, w ? 1 : 0);
            shift_cl(e, w, n[o->op - IRO_LSLV], hd);
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }
        case IRO_EXTR: {
            int ha = ra_use(be, o->a);            /* hi */
            int hb = ra_use(be, o->b);            /* lo */
            mov_rr(e, 1, RAX, hb);
            /* shrd rax, ha, imm */
            rex(e, w, ha, 0, RAX);
            e8(e, 0x0F); e8(e, 0xAC);
            e8(e, (u8)(0xC0 | ((ha & 7) << 3) | (RAX & 7)));
            e8(e, (u8)o->imm);
            int hd = ra_def(be, o->dst);
            mov_rr(e, w, hd, RAX);
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }

        case IRO_MADD: case IRO_MSUB: {
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            mov_rr(e, 1, RAX, ha);
            op0f_rr(e, w, 0xAF, RAX, hb);         /* imul rax, hb */
            if (o->cc != VREG_ZERO) {
                int hr = ra_use(be, o->cc);
                if (o->op == IRO_MADD) {
                    op_rr(e, w, 0x01, hr, RAX);   /* add rax, hr */
                    int hd = ra_def(be, o->dst);
                    mov_rr(e, w, hd, RAX);
                    if (!w) mov_rr(e, 0, hd, hd);
                    break;
                }
                mov_rr(e, 1, RDX, hr);
                op_rr(e, w, 0x29, RAX, RDX);      /* sub rdx, rax */
                int hd = ra_def(be, o->dst);
                mov_rr(e, w, hd, RDX);
                if (!w) mov_rr(e, 0, hd, hd);
                break;
            }
            if (o->op == IRO_MSUB) {              /* 0 - a*b */
                rex(e, w, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xD8);   /* neg rax */
            }
            int hd = ra_def(be, o->dst);
            mov_rr(e, w, hd, RAX);
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }
        case IRO_SMADDL: case IRO_SMSUBL: case IRO_UMADDL: case IRO_UMSUBL: {
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            int sign = (o->op == IRO_SMADDL || o->op == IRO_SMSUBL);
            if (sign) {
                op_rr(e, 1, 0x63, RAX, ha);       /* movsxd rax, ha32 */
                op_rr(e, 1, 0x63, RDX, hb);
            } else {
                mov_rr(e, 0, RAX, ha);            /* zext32 */
                mov_rr(e, 0, RDX, hb);
            }
            op0f_rr(e, 1, 0xAF, RAX, RDX);        /* imul rax, rdx */
            int subv = (o->op == IRO_SMSUBL || o->op == IRO_UMSUBL);
            if (o->cc != VREG_ZERO) {
                int hr = ra_use(be, o->cc);
                if (!subv) {
                    op_rr(e, 1, 0x01, hr, RAX);
                } else {
                    mov_rr(e, 1, RDX, hr);
                    op_rr(e, 1, 0x29, RAX, RDX);
                    mov_rr(e, 1, RAX, RDX);
                }
            } else if (subv) {
                rex(e, 1, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xD8);
            }
            int hd = ra_def(be, o->dst);
            mov_rr(e, 1, hd, RAX);
            break;
        }
        case IRO_SMULH: case IRO_UMULH: {
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            mov_rr(e, 1, RAX, ha);
            rex(e, 1, 0, 0, hb); e8(e, 0xF7);
            e8(e, (u8)(0xC0 | ((o->op == IRO_SMULH ? 5 : 4) << 3) | (hb & 7)));
            int hd = ra_def(be, o->dst);
            mov_rr(e, 1, hd, RDX);
            break;
        }
        case IRO_UDIV: case IRO_SDIV: {
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            mov_rr(e, 1, RCX, hb);
            mov_rr(e, 1, RAX, ha);
            op_rr(e, w, 0x85, RCX, RCX);          /* test hb, hb */
            u8 *zero = jcc_fwd(e, CC_E);
            u8 *ovf_done = NULL;
            if (o->op == IRO_SDIV) {
                alu_ri32(e, w, 7, RCX, 0xffffffffu);    /* cmp rcx, -1 */
                u8 *do_div = jcc_fwd(e, CC_NE);
                if (w) {
                    mov_ri(e, 1, RDX, 0x8000000000000000ULL);
                    op_rr(e, 1, 0x39, RDX, RAX);
                } else {
                    alu_ri32(e, 0, 7, RAX, 0x80000000u);
                }
                u8 *do_div2 = jcc_fwd(e, CC_NE);
                ovf_done = jmp_fwd(e);            /* result = a (in rax) */
                fwd_here(e, do_div);
                fwd_here(e, do_div2);
            }
            if (o->op == IRO_UDIV) {
                op_rr(e, 0, 0x31, RDX, RDX);      /* xor edx, edx */
                rex(e, w, 0, 0, RCX); e8(e, 0xF7);
                e8(e, (u8)(0xC0 | (6 << 3) | (RCX & 7)));   /* div rcx */
            } else {
                if (w) { e8(e, 0x48); e8(e, 0x99); }        /* cqo */
                else e8(e, 0x99);                            /* cdq */
                rex(e, w, 0, 0, RCX); e8(e, 0xF7);
                e8(e, (u8)(0xC0 | (7 << 3) | (RCX & 7)));   /* idiv rcx */
            }
            u8 *done = jmp_fwd(e);
            fwd_here(e, zero);
            mov_ri(e, 0, RAX, 0);
            fwd_here(e, done);
            if (ovf_done) fwd_here(e, ovf_done);
            int hd = ra_def(be, o->dst);
            mov_rr(e, w, hd, RAX);
            if (!w) mov_rr(e, 0, hd, hd);
            break;
        }

        case IRO_CLZ: {
            int ha = ra_use(be, o->a);
            mov_ri(e, 0, RCX, 0xffffffffu);
            rex(e, 1, RCX, 0, RCX); e8(e, 0x63);  /* movsxd rcx, ecx: -1 */
            e8(e, (u8)(0xC0 | ((RCX & 7) << 3) | (RCX & 7)));
            op0f_rr(e, w, 0xBD, RDX, ha);         /* bsr rdx, ha */
            op0f_rr(e, 1, 0x44, RDX, RCX);        /* cmove rdx, rcx */
            mov_ri(e, 0, RAX, w ? 63 : 31);
            op_rr(e, 1, 0x29, RDX, RAX);          /* sub rax, rdx */
            int hd = ra_def(be, o->dst);
            mov_rr(e, 1, hd, RAX);
            break;
        }
        case IRO_REV64: case IRO_REV32: {
            int w2 = (o->op == IRO_REV64);
            int hd = def_alias(be, o->dst, o->a, w2 ? 1 : 0);
            rex(e, w2, 0, 0, hd);
            e8(e, 0x0F); e8(e, (u8)(0xC8 | (hd & 7)));      /* bswap */
            if (!w2) mov_rr(e, 0, hd, hd);
            break;
        }

        case IRO_RBIT: {
            /* byte-reverse, then swap nibbles, 2-bit pairs, single bits */
            static const u64 rm[3] = { 0x0f0f0f0f0f0f0f0fULL,
                                       0x3333333333333333ULL,
                                       0x5555555555555555ULL };
            static const u8 rs[3] = { 4, 2, 1 };
            int ha = ra_use(be, o->a);
            mov_rr(e, 1, RAX, ha);
            rex(e, w, 0, 0, RAX);
            e8(e, 0x0F); e8(e, (u8)(0xC8 | RAX));           /* bswap */
            for (int k = 0; k < 3; k++) {
                mov_rr(e, 1, RCX, RAX);
                shift_ri(e, w, 5, RCX, rs[k]);              /* shr */
                mov_ri(e, w, RDX, w ? rm[k] : (u32)rm[k]);
                op_rr(e, w, 0x23, RCX, RDX);                /* rcx &= m */
                op_rr(e, w, 0x23, RAX, RDX);                /* rax &= m */
                shift_ri(e, w, 4, RAX, rs[k]);              /* shl */
                op_rr(e, w, 0x0B, RAX, RCX);                /* rax |= rcx */
            }
            int hd = ra_def(be, o->dst);
            mov_rr(e, w, hd, RAX);
            break;
        }

        case IRO_CSEL: case IRO_CSINC: case IRO_CSINV: case IRO_CSNEG: {
            int cc = cond_setup(be, o->cc);
            int ha = (o->a == VREG_ZERO) ? -1 : ra_use(be, o->a);
            int hb = (o->b == VREG_ZERO) ? -1 : ra_use(be, o->b);
            /* rax = alternative f(b) — all flag-preserving ops */
            if (hb < 0) mov_ri(e, 0, RAX, 0);
            else mov_rr(e, w, RAX, hb);
            if (o->op == IRO_CSINC) {
                rex(e, w, RAX, 0, RAX); e8(e, 0x8D);         /* lea rax,[rax+1] */
                e8(e, 0x80 | ((RAX & 7) << 3) | (RAX & 7));
                e32(e, 1);
            } else if (o->op == IRO_CSINV) {
                rex(e, w, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xD0);   /* not */
            } else if (o->op == IRO_CSNEG) {
                rex(e, w, 0, 0, RAX); e8(e, 0xF7); e8(e, 0xD0);
                rex(e, w, RAX, 0, RAX); e8(e, 0x8D);
                e8(e, 0x80 | ((RAX & 7) << 3) | (RAX & 7));
                e32(e, 1);
            }
            if (cc == CC_ALWAYS) {
                if (ha < 0) mov_ri(e, 0, RAX, 0);
                else mov_rr(e, w, RAX, ha);
            } else if (cc != CC_NEVER) {
                if (ha < 0) { mov_ri(e, 0, RDX, 0); ha = RDX; }
                /* cmovcc rax, ha */
                rex(e, w, RAX, 0, ha);
                e8(e, 0x0F); e8(e, (u8)(0x40 | cc));
                e8(e, (u8)(0xC0 | ((RAX & 7) << 3) | (ha & 7)));
            }
            int hd = ra_def(be, o->dst);
            mov_rr(e, w, hd, RAX);
            if (!w) mov_rr(e, 0, hd, hd);
            /* CSEL preserved EFLAGS (mov/lea/not/cmov only), but the next
             * op may clobber them: keep host flags only for a following
             * consumer, else store NZCV now. */
            if (be->fl != FL_MEM && flags_next_use(ir, i) == FLAGS_UNKNOWN)
                materialize_flags(be);
            break;
        }

        case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI: {
            int is_imm = (o->op == IRO_CCMPI || o->op == IRO_CCMNI);
            int is_cmn = (o->op == IRO_CCMNR || o->op == IRO_CCMNI);
            /* Allocator actions (loads/evictions) must be emitted OUTSIDE
             * the conditional region below: the recorded register state has
             * to hold on both runtime paths. */
            int ha = ra_use(be, o->a);
            int hb = is_imm ? -1 : ra_use(be, o->b);
            int cc = cond_setup(be, o->cc);
            u8 *els = NULL, *end = NULL;
            if (cc == CC_NEVER) {
                mov_ri(e, 0, RAX, o->aux);
                st32(e, RAX, R14, OFF_NZCV);
                be->fl = FL_MEM;
                break;
            }
            if (cc != CC_ALWAYS) els = jcc_fwd(e, cc ^ 1);   /* !cond */
            {   /* compare path (scratch-only: no allocator calls here) */
                if (is_cmn) {
                    mov_rr(e, 1, RAX, ha);
                    if (is_imm) alu_ri32(e, w, 0, RAX, (u32)o->imm);
                    else op_rr(e, w, 0x01, hb, RAX);
                    be->fl = FL_ADD;
                } else {
                    if (is_imm) alu_ri32(e, w, 7, ha, (u32)o->imm);
                    else op_rr(e, w, 0x39, hb, ha);
                    be->fl = FL_SUB;
                }
                materialize_flags(be);
            }
            if (cc != CC_ALWAYS) {
                end = jmp_fwd(e);
                fwd_here(e, els);
                mov_ri(e, 0, RAX, o->aux);
                st32(e, RAX, R14, OFF_NZCV);
                fwd_here(e, end);
            }
            be->fl = FL_MEM;
            break;
        }

        /* ---- terminals ---- */
        case IRO_JMP: {
            sync_all(be);
            int kind = be->fl;
            if (kind != FL_MEM) { e8(e, 0x9C); e8(e, 0x58); }   /* pushfq;pop rax */
            be->fl = FL_MEM;
            exit_stub(be, 0, o->imm, kind, o->icnt);
            break;
        }
        case IRO_BCOND: {
            sync_all(be);
            int cc = cond_setup(be, o->cc);       /* may switch fl to MEM */
            int kind = be->fl;                    /* stub recompose kind */
            if (kind != FL_MEM) { e8(e, 0x9C); e8(e, 0x58); }   /* snapshot */
            be->fl = FL_MEM;
            const IROp *nxt = &ir->ops[i + 1];    /* the fallthrough IRO_JMP */
            if (cc == CC_ALWAYS) {
                exit_stub(be, 0, o->imm, kind, o->icnt);
                return 2;
            }
            if (cc == CC_NEVER) {
                exit_stub(be, 0, nxt->imm, kind, nxt->icnt);
                return 2;
            }
            u8 *taken = jcc_fwd(e, cc);
            exit_stub(be, 1, nxt->imm, kind, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, kind, o->icnt);
            return 2;
        }
        case IRO_CBZ: case IRO_CBNZ: {
            sync_all(be);
            int kind = be->fl;
            if (kind != FL_MEM) { e8(e, 0x9C); e8(e, 0x58); }
            be->fl = FL_MEM;
            int ha = ra_use(be, o->a);
            op_rr(e, w, 0x85, ha, ha);            /* test (after snapshot) */
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = jcc_fwd(e, o->op == IRO_CBZ ? CC_E : CC_NE);
            exit_stub(be, 1, nxt->imm, kind, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, kind, o->icnt);
            return 2;
        }
        case IRO_TBZ: case IRO_TBNZ: {
            sync_all(be);
            int kind = be->fl;
            if (kind != FL_MEM) { e8(e, 0x9C); e8(e, 0x58); }
            be->fl = FL_MEM;
            int ha = ra_use(be, o->a);
            /* bt ha, bit */
            rex(e, 1, 0, 0, ha);
            e8(e, 0x0F); e8(e, 0xBA);
            e8(e, (u8)(0xC0 | (4 << 3) | (ha & 7)));
            e8(e, o->cc);
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = jcc_fwd(e, o->op == IRO_TBZ ? CC_AE /*!CF*/ : CC_B);
            exit_stub(be, 1, nxt->imm, kind, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, kind, o->icnt);
            return 2;
        }
        case IRO_JMPIND: {
            sync_all(be);
            materialize_flags(be);
            int ha = ra_use(be, o->a);
            mov_rr(e, 1, RAX, ha);
            st64(e, RAX, R14, OFF_PC);
            /* plain add is fine: guest flags are in memory now */
            if (o->icnt) {
                rex(e, 1, 0, 0, R14); e8(e, 0x81);
                e8(e, (u8)(0x80 | (0 << 3) | (R14 & 7)));
                e32(e, (u32)OFF_ICOUNT);
                e32(e, o->icnt);
            }
            /* rcx = &env->jcache[(pc >> 2) & mask] */
            mov_rr(e, 1, RCX, RAX);
            shift_ri(e, 1, 5, RCX, 2);
            alu_ri32(e, 0, 4, RCX, JIT_JC_SIZE - 1);
            shift_ri(e, 1, 4, RCX, 4);
            /* lea rcx, [r15 + rcx + off] (SIB) */
            rex(e, 1, RCX, RCX, R15);
            e8(e, 0x8D);
            e8(e, 0x84 | ((RCX & 7) << 3));       /* mod10 rm=100 (SIB) */
            e8(e, (u8)((0 << 6) | ((RCX & 7) << 3) | (R15 & 7)));
            e32(e, (u32)offsetof(JitEnv, jcache));
            op_rm(e, 1, 0x3B, RAX, RCX, 0);       /* cmp rax, [rcx] — needs
                                                     base rcx: rm=1 ok */
            u8 *miss = jcc_fwd(e, CC_NE);
            /* jmp [rcx+8] loaded */
            rex(e, 1, RCX, 0, RCX);
            e8(e, 0x8B);
            e8(e, 0x49); /* mod01 rm=rcx: mov rcx,[rcx+disp8] */
            e8(e, 0x08);
            e8(e, 0xFF); e8(e, 0xE1);             /* jmp rcx */
            fwd_here(e, miss);
            mov_ri(e, 0, RAX, JIT_EXIT_NONE);
            jmp_to(e, be->env->epilogue_rx);
            break;
        }
        case IRO_LD: case IRO_ST: {
            int k = fuse_enabled() ? jit_mem_run_len(ir, i) : 1;
            if (k >= 2) { emit_mem_run(be, ir, i, k); return k; }
            emit_mem(be, ir, i);
            break;
        }
        case IRO_LDV: case IRO_STV:
            emit_mem(be, ir, i);
            break;
        case IRO_ATOMIC:
            emit_atomic(be, ir, i);
            break;
        case IRO_VOP:
            emit_vop(be, ir, i, o);
            break;
        case IRO_CALL1:
            emit_call1(be, o);
            break;

        case IRO_CPULD: {                        /* dst = *(u64*)(CPU+imm) */
            int hd = ra_def(be, o->dst);
            ld64(e, hd, R14, (s32)o->imm);       /* movs: flag-safe */
            break;
        }
        case IRO_CPUST: {
            int ha = ra_use(be, o->a);
            st64(e, ha, R14, (s32)o->imm);
            break;
        }
        case IRO_FENCE:                          /* mfence: flag-safe */
            e8(e, 0x0F); e8(e, 0xAE); e8(e, 0xF0);
            break;

        default:
            /* unreached: frontend only emits the ops above */
            e->overflow = 1;
            break;
    }
    return 1;
}

/* ---- chaining ---- */

void be_patch_chain(JitEnv *env, JBlock *b, int slot, const u8 *target_rx) {
    u8 *site_rw = env->cache_rw + (b->code - env->cache_rx) + b->exit_off[slot];
    const u8 *site_rx = b->code + b->exit_off[slot];
    s32 rel = (s32)(target_rx - (site_rx + 5));
    site_rw[0] = 0xE9;
    memcpy(site_rw + 1, &rel, 4);
    b->patched[slot] = 1;
}

void be_unpatch_chain(JitEnv *env, JBlock *b, int slot) {
    u8 *site_rw = env->cache_rw + (b->code - env->cache_rx) + b->exit_off[slot];
    site_rw[0] = 0x48;                            /* movabs rax, exit_pc */
    site_rw[1] = 0xB8;
    memcpy(site_rw + 2, &b->exit_pc[slot], 8);
    b->patched[slot] = 0;
}

void be_flush_icache(const u8 *rx, const u8 *rw, size_t len) {
    (void)rx; (void)rw; (void)len;
}

#endif /* __x86_64__ */
