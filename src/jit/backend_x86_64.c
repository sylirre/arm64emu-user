/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* x86-64 code generator. Conventions in generated code:
 *   r14 = CPU*, r15 = JitEnv*        (callee-saved, survive helper calls)
 *   rax/rcx/rdx                      emitter scratch, never allocated
 *   rbx rsi rdi r8-r13               allocatable pool (guest values)
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

#include <string.h>

enum { RAX = 0, RCX, RDX, RBX, RSP_, RBP, RSI, RDI,
       R8, R9, R10, R11, R12, R13, R14, R15, HREG_N };

/* allocatable pool, preference order */
static const u8 pool[] = { RBX, RSI, RDI, R8, R9, R10, R11, R12, R13 };
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

static void sync_all(BE *be) {                   /* flag-safe (movs only) */
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && be->dirty[v]) { v_store(be, v); be->dirty[v] = 0; }
}
static void invalidate_all(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0) ra_unmap(be, v);
}

/* Caller-saved host regs don't survive a C call; drop their (clean, after a
 * sync_all) mappings so a memory-op slow-path call can't corrupt live guest
 * values. Callee-saved mappings (rbx/r12/r13) stay resident. */
static int is_caller_saved(int h) {
    return h == RSI || h == RDI || h == R8 || h == R9 || h == R10 || h == R11;
}
static void drop_caller_saved(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && is_caller_saved(be->v2h[v])) ra_unmap(be, v);
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
        case 0:  alu_ri32(e, 0, 0 /*F7 path below*/, RAX, 0); break;
        default: break;
    }
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

/* After emitting an S-op: decide whether host flags survive to the next op
 * (which will consume them) or must be recomposed now. */
static int next_consumes_flags(const IRBlock *ir, int i) {
    if (i + 1 >= ir->n) return 0;
    const IROp *o = &ir->ops[i + 1];
    switch (o->op) {
        case IRO_BCOND:
        case IRO_CSEL: case IRO_CSINC: case IRO_CSINV: case IRO_CSNEG:
        case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI:
            return 1;
        default:
            return 0;
    }
}
static void set_flags_state(BE *be, const IRBlock *ir, int i, int kind) {
    be->fl = kind;
    if (!next_consumes_flags(ir, i)) materialize_flags(be);
}

/* ---- common op patterns ---- */

/* dst = a; returns host reg of dst primed with a's value. Safe for d == a.
 * (Callers must not read `b` through this reg before using it.) */
static int def_alias(BE *be, int d, int a, int w) {
    if (d == a) {
        int h = ra_use(be, a);
        be->dirty[d] = 1;
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

/* icount += n without touching flags (mov/lea only). Clobbers rax. */
static void icount_add(BE *be, u32 n) {
    if (!n) return;
    Emit *e = be->e;
    ld64(e, RAX, R14, OFF_ICOUNT);
    /* lea rax, [rax + n] */
    rex(e, 1, RAX, 0, RAX);
    e8(e, 0x8D);
    e8(e, 0x80 | ((RAX & 7) << 3) | (RAX & 7));
    e32(e, n);
    st64(e, RAX, R14, OFF_ICOUNT);
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
        if (opc_rr == 0x01) {                     /* adds xzr: need result */
            mov_rr(e, 1, RAX, ha);
            op_rr(e, w, 0x01, hb, RAX);
            return;
        }
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

/* Inline memory op: sync guest state, probe the D-TLB, fast host access, or
 * out-of-line slow helper. Operands are read from / results written to the
 * CPU struct (memory), so no host-register state crosses the op — the slow
 * call is safe and both paths converge trivially. */
static void emit_mem(BE *be, const IRBlock *ir, int i) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    int is_st = (o->op == IRO_ST || o->op == IRO_STV);
    int is_v  = (o->op == IRO_LDV || o->op == IRO_STV);
    unsigned desc = o->aux;
    unsigned rt = MDESC_RT(desc);
    unsigned szlog = is_v ? MDESC_VSZL(desc) : o->cc;
    unsigned sz = 1u << szlog;                   /* 1..16 bytes */
    int need = is_st ? 2 /*PTE_W*/ : 1 /*PTE_R*/;

    sync_all(be);
    materialize_flags(be);
    drop_caller_saved(be);

    /* va = base + offset  -> rsi */
    ld_home(be, RSI, o->a);
    if (o->imm) {
        u64 off = o->imm;
        if (imm_is_s32(off)) alu_ri32(e, 1, 0, RSI, (u32)off);
        else { mov_ri(e, 1, RDX, off); op_rr(e, 1, 0x01, RDX, RSI); }
    }
    /* page -> rax ; ent ptr -> rcx */
    mov_rr(e, 1, RAX, RSI);
    shift_ri(e, 1, 5, RAX, 12);
    mov_rr(e, 0, RCX, RAX);
    alu_ri32(e, 0, 4, RCX, A64_DTLB_ENTRIES - 1);
    shift_ri(e, 0, 4, RCX, 4);
    op_rm(e, 1, 0x03, RCX, R15, (s32)offsetof(JitEnv, dtlb));  /* add rcx,[r15+dtlb] */
    op_rm(e, 1, 0x39, RAX, RCX, 0);            /* cmp [rcx], rax (tag==page) */
    u8 *slow1 = jcc_fwd(e, CC_NE);
    ld64(e, RDX, RCX, 8);                      /* pte -> rdx */
    e8(e, 0xF6); e8(e, 0xC2); e8(e, (u8)need); /* test dl, need */
    u8 *slow2 = jcc_fwd(e, CC_E);
    u8 *slow3 = NULL;
    if (sz > 1) {                              /* page-cross gate */
        mov_rr(e, 0, RAX, RSI);
        alu_ri32(e, 0, 4, RAX, 0xfff);
        alu_ri32(e, 0, 0, RAX, sz);
        alu_ri32(e, 0, 7, RAX, 0x1000);        /* cmp eax, 4096 */
        slow3 = jcc_fwd(e, CC_A);
    }
    alu_ri32(e, 1, 4, RDX, 0xFFFFFFF8u);       /* and rdx, ~7 : host base */
    mov_rr(e, 0, RAX, RSI);
    alu_ri32(e, 0, 4, RAX, 0xfff);             /* page offset */
    op_rr(e, 1, 0x01, RAX, RDX);               /* add rdx, rax : host ptr */

    /* ---- fast access (data reg = rax, ptr = rdx) ---- */
    if (!is_v) {
        if (is_st) {
            ld_home(be, RAX, o->b);
            switch (szlog) {
                case 0: e8(e, 0x88); e8(e, 0x02); break;             /* mov [rdx],al */
                case 1: e8(e, 0x66); e8(e, 0x89); e8(e, 0x02); break;/* mov [rdx],ax */
                case 2: e8(e, 0x89); e8(e, 0x02); break;             /* mov [rdx],eax */
                default: e8(e, 0x48); e8(e, 0x89); e8(e, 0x02); break;/* mov [rdx],rax */
            }
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
            if (rt != 31) {
                st64(e, RAX, R14, OFF_X(rt));
                ra_unmap(be, rt);   /* result now lives in memory: drop any
                                     * stale host-reg mapping for rt */
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
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    if (slow3) fwd_here(e, slow3);
    mov_rr(e, 1, RDI, R14);                     /* arg0 = CPU* ; rsi = va */
    s32 hoff;
    if (o->op == IRO_ST) {                      /* jit_st(c, va, val, pc, desc) */
        ld_home(be, RDX, o->b);
        mov_ri(e, 1, RCX, o->imm2pc);
        mov_ri(e, 0, R8, desc);
        hoff = (s32)offsetof(JitEnv, helper_st);
    } else {                                    /* ld/ldv/stv(c, va, pc, desc) */
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
    exit_plain(be, o->icnt);                   /* faulted: leave the block */
    fwd_here(e, ok);
    fwd_here(e, done);
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
    be.fl = FL_MEM;
    b->exit_pc[0] = b->exit_pc[1] = ~0ULL;
    b->exit_off[0] = b->exit_off[1] = 0;
    b->patched[0] = b->patched[1] = 0;
    b->in_head = ~0u;

    /* safepoint: cmp dword [r15+interrupt], 0 ; je +cont ; set pc, exit.
     * c->pc must be restored to the block's start here: a direct chain jump
     * into this block bypassed the predecessor's exit-stub pc write, so
     * c->pc is stale on entry — emu_loop needs the true resume pc to deliver
     * the pending signal / dispatch correctly. */
    op_rm(e, 0, 0x83, 7, R15, (s32)offsetof(JitEnv, interrupt));
    e8(e, 0x00);                                  /* the imm8 of 83 /7 */
    u8 *skip = jcc_fwd(e, CC_E);
    mov_ri(e, 1, RAX, b->pc);
    st64(e, RAX, R14, OFF_PC);
    exit_plain(&be, 0);
    fwd_here(e, skip);

    for (int i = 0; i < ir->n && !e->overflow; )
        i += emit_op(&be, ir, i);

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

        case IRO_ADD:  alu_rrr(be, w, 0x01, 1, o->dst, o->a, o->b); break;
        case IRO_SUB:  alu_rrr(be, w, 0x29, 0, o->dst, o->a, o->b); break;
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
            if (be->fl != FL_MEM && !next_consumes_flags(ir, i))
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
        case IRO_LD: case IRO_ST: case IRO_LDV: case IRO_STV:
            emit_mem(be, ir, i);
            break;
        case IRO_CALL1:
            emit_call1(be, o);
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
