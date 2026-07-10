/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* AArch64 code generator (same-ISA host). Conventions in generated code:
 *   x27 = JitEnv*, x28 = CPU*        (callee-saved, survive helper calls)
 *   x16/x17                          emitter scratch (IP0/IP1)
 *   x19-x26, x9-x15                  allocatable pool (guest values)
 *
 * Guest NZCV maps 1:1 onto host NZCV: S-ops emit native ADDS/SUBS/ANDS and
 * consumers use native B.cond/CSEL/CCMP. Because MRS reads NZCV without
 * destroying it, materializing the architectural c->nzcv costs two
 * instructions and never forces the memory-condition path the way it does
 * on x86 — flags are stored to the CPU struct whenever the next op is not a
 * consumer, and again (cheaply) before chainable exits. */
#include "ir.h"

#ifdef __aarch64__

#include <string.h>

enum { FL_MEM, FL_HOST };

static const u8 pool[] = { 19, 20, 21, 22, 23, 24, 25, 26,
                           9, 10, 11, 12, 13, 14, 15 };
#define POOL_N ((int)sizeof pool)
#define HREG_N 32

#define OFF_X(n)   ((s32)(offsetof(CPU, x) + 8 * (n)))
#define OFF_SP     ((s32)offsetof(CPU, sp_el))
#define OFF_PC     ((s32)offsetof(CPU, pc))
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
    int fl;
} BE;

/* ---- raw emission ---- */

static void ei(Emit *e, u32 insn) {
    if (UNLIKELY(e->rw + 4 > e->rw_end)) { e->overflow = 1; return; }
    memcpy(e->rw, &insn, 4);
    e->rw += 4; e->rx += 4;
}

/* forward label: returns rw position of a branch to patch via *_here */
static u8 *b_fwd(Emit *e) { u8 *p = e->rw; ei(e, 0x14000000u); return p; }
static u8 *cbz_fwd(Emit *e, int w, unsigned rt) {
    u8 *p = e->rw;
    ei(e, ((u32)w << 31) | 0x34000000u | rt);
    return p;
}
static u8 *cbnz_fwd(Emit *e, int w, unsigned rt) {
    u8 *p = e->rw;
    ei(e, ((u32)w << 31) | 0x35000000u | rt);
    return p;
}
static u8 *bcond_fwd(Emit *e, unsigned cond) {
    u8 *p = e->rw;
    ei(e, 0x54000000u | cond);
    return p;
}
static void fwd_here(Emit *e, u8 *p) {
    if (!p || e->overflow) return;
    u32 insn;
    memcpy(&insn, p, 4);
    s64 off = (e->rw - p) >> 2;
    if ((insn & 0x7C000000u) == 0x14000000u)        /* B */
        insn |= ((u32)off & 0x03FFFFFFu);
    else if ((insn & 0x7E000000u) == 0x34000000u)   /* CBZ/CBNZ */
        insn |= (((u32)off & 0x7FFFFu) << 5);
    else                                            /* B.cond */
        insn |= (((u32)off & 0x7FFFFu) << 5);
    memcpy(p, &insn, 4);
}

/* ---- encoders ---- */

static u32 enc_ldstp64(int load, int mode, unsigned rt, unsigned rt2,
                       unsigned rn, int imm_bytes) {
    u32 base = mode == 1 ? 0xA9800000u : mode == 2 ? 0xA8800000u : 0xA9000000u;
    return base | (load ? 0x00400000u : 0) | ((((u32)(imm_bytes / 8)) & 0x7f) << 15) |
           (rt2 << 10) | (rn << 5) | rt;
}
static u32 enc_ldr(unsigned size, unsigned rt, unsigned rn, unsigned off) {
    return (size == 3 ? 0xF9400000u : 0xB9400000u) | ((off >> size) << 10) |
           (rn << 5) | rt;
}
static u32 enc_str(unsigned size, unsigned rt, unsigned rn, unsigned off) {
    return (size == 3 ? 0xF9000000u : 0xB9000000u) | ((off >> size) << 10) |
           (rn << 5) | rt;
}
static u32 enc_movz(int w, unsigned rd, unsigned imm16, unsigned hw) {
    return ((u32)w << 31) | 0x52800000u | (hw << 21) | (imm16 << 5) | rd;
}
static u32 enc_movk(int w, unsigned rd, unsigned imm16, unsigned hw) {
    return ((u32)w << 31) | 0x72800000u | (hw << 21) | (imm16 << 5) | rd;
}
static u32 enc_movn(int w, unsigned rd, unsigned imm16, unsigned hw) {
    return ((u32)w << 31) | 0x12800000u | (hw << 21) | (imm16 << 5) | rd;
}
/* ORR shifted register (also MOV): rd = rn | (rm shift amt) */
static u32 enc_orr(int w, unsigned rd, unsigned rn, unsigned rm) {
    return ((u32)w << 31) | 0x2A000000u | (rm << 16) | (rn << 5) | rd;
}
static u32 enc_mov(int w, unsigned rd, unsigned rm) {
    return enc_orr(w, rd, 31, rm);
}
static u32 enc_br(unsigned rn)  { return 0xD61F0000u | (rn << 5); }
static u32 enc_blr(unsigned rn) { return 0xD63F0000u | (rn << 5); }
static u32 enc_b(s64 off) { return 0x14000000u | (((u32)(off >> 2)) & 0x03FFFFFFu); }

static void b_to(Emit *e, const u8 *target) { ei(e, enc_b(target - e->rx)); }

/* Load an arbitrary 64-bit immediate into rd (2-5 insns, movz/movn based). */
static void emit_imm64(Emit *e, unsigned rd, u64 v) {
    int neg = 0;
    u64 probe = v;
    int nz = 0, nf = 0;
    for (int hw = 0; hw < 4; hw++) {
        u64 c = (probe >> (16 * hw)) & 0xffff;
        if (c) nz++;
        if (c != 0xffff) nf++;
    }
    if (nf < nz) neg = 1;
    int first = 1;
    for (int hw = 0; hw < 4; hw++) {
        unsigned c = (unsigned)((v >> (16 * hw)) & 0xffff);
        if (first) {
            if (neg) {
                if (c == 0xffff && hw != 3 &&
                    ((v >> (16 * (hw + 1))) & 0xffff) != 0xffff)
                    continue;   /* pick a non-ffff chunk to seed movn */
                ei(e, enc_movn(1, rd, (~c) & 0xffff, (unsigned)hw));
            } else {
                if (c == 0 && hw != 3) continue;
                ei(e, enc_movz(1, rd, c, (unsigned)hw));
            }
            first = 0;
            /* backfill skipped chunks that don't match the seed fill */
            for (int j = 0; j < hw; j++) {
                unsigned cj = (unsigned)((v >> (16 * j)) & 0xffff);
                if ((neg && cj != 0xffff) || (!neg && cj != 0))
                    ei(e, enc_movk(1, rd, cj, (unsigned)j));
            }
        } else {
            if ((neg && c != 0xffff) || (!neg && c != 0))
                ei(e, enc_movk(1, rd, c, (unsigned)hw));
        }
    }
    if (first) ei(e, enc_movz(1, rd, 0, 0));       /* v == 0 or all-ones */
}

/* ---- register allocator (mirrors backend_x86_64.c) ---- */

static s32 v_home(int v) {
    if (v < 31) return OFF_X(v);
    if (v == VREG_SP) return OFF_SP;
    return -1;
}
static s32 v_spill(int v) { return (s32)(offsetof(JitEnv, tmp_spill) + 8 * (v - VREG_TMP0)); }

static void v_store(BE *be, int v) {
    int h = be->v2h[v];
    s32 off = v_home(v);
    if (off >= 0) ei(be->e, enc_str(3, (unsigned)h, 28, (unsigned)off));
    else ei(be->e, enc_str(3, (unsigned)h, 27, (unsigned)v_spill(v)));
}
static void v_load_into(BE *be, int v, int h) {
    if (v == VREG_ZERO) { ei(be->e, enc_movz(1, (unsigned)h, 0, 0)); return; }
    s32 off = v_home(v);
    if (off >= 0) ei(be->e, enc_ldr(3, (unsigned)h, 28, (unsigned)off));
    else ei(be->e, enc_ldr(3, (unsigned)h, 27, (unsigned)v_spill(v)));
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
static int ra_def(BE *be, int v) {
    if (v == VREG_ZERO) return 16;                 /* scratch: discard */
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
static void sync_all(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && be->dirty[v]) { v_store(be, v); be->dirty[v] = 0; }
}
static void invalidate_all(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0) ra_unmap(be, v);
}

/* Caller-saved host regs (x9-x15 in our pool) don't survive a C call; drop
 * their (clean, post sync_all) mappings around a memory-op slow path. The
 * callee-saved half (x19-x26) stays resident. */
static int is_caller_saved(int h) { return h >= 9 && h <= 15; }
static void drop_caller_saved(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && is_caller_saved(be->v2h[v])) ra_unmap(be, v);
}

/* ---- flags ---- */

static void materialize_flags(BE *be) {          /* MRS preserves NZCV */
    if (be->fl == FL_MEM) return;
    ei(be->e, 0xD53B4200u | 16);                  /* mrs x16, nzcv */
    ei(be->e, enc_str(2, 16, 28, (unsigned)OFF_NZCV));
    be->fl = FL_MEM;
}
static void flags_to_host(BE *be) {               /* consumer needs NZCV */
    if (be->fl == FL_HOST) return;
    ei(be->e, enc_ldr(2, 16, 28, (unsigned)OFF_NZCV));
    ei(be->e, 0xD51B4200u | 16);                  /* msr nzcv, x16 */
    /* architectural copy still matches: stays FL_MEM upgraded to both */
}

static int next_consumes_flags(const IRBlock *ir, int i) {
    if (i + 1 >= ir->n) return 0;
    switch (ir->ops[i + 1].op) {
        case IRO_BCOND:
        case IRO_CSEL: case IRO_CSINC: case IRO_CSINV: case IRO_CSNEG:
        case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI:
            return 1;
        default:
            return 0;
    }
}
static void set_flags_state(BE *be, const IRBlock *ir, int i) {
    be->fl = FL_HOST;
    if (!next_consumes_flags(ir, i)) materialize_flags(be);
}

/* ---- exits ---- */

static void icount_add(BE *be, u32 n) {
    if (!n) return;
    Emit *e = be->e;
    ei(e, enc_ldr(3, 16, 28, (unsigned)OFF_ICOUNT));
    ei(e, 0x91000000u | ((n & 0xfff) << 10) | (16 << 5) | 16);   /* add imm */
    if (n > 0xfff)
        ei(e, 0x91400000u | (((n >> 12) & 0xfff) << 10) | (16 << 5) | 16);
    ei(e, enc_str(3, 16, 28, (unsigned)OFF_ICOUNT));
}

static void exit_stub(BE *be, int slot, u64 target_pc, u32 icnt) {
    Emit *e = be->e;
    JBlock *b = be->b;
    icount_add(be, icnt);
    b->exit_pc[slot] = target_pc;
    b->exit_off[slot] = (u32)(e->rx - b->code);
    u8 *first = e->rw;
    emit_imm64(e, 16, target_pc);                 /* first insn is the patch */
    memcpy(&b->stub_word0[slot], first, 4);
    ei(e, enc_str(3, 16, 28, (unsigned)OFF_PC));
    u32 eid = ((u32)(b - be->env->arena) << 1) | (u32)slot;
    ei(e, enc_movz(0, 0, eid & 0xffff, 0));
    if (eid >> 16) ei(e, enc_movk(0, 0, eid >> 16, 1));
    b_to(e, be->env->epilogue_rx);
}

static void exit_plain(BE *be, u32 icnt) {
    icount_add(be, icnt);
    ei(be->e, enc_movn(0, 0, 0, 0));              /* w0 = EXIT_NONE */
    b_to(be->e, be->env->epilogue_rx);
}

void be_patch_chain(JitEnv *env, JBlock *b, int slot, const u8 *target_rx) {
    u8 *site_rw = env->cache_rw + (b->code - env->cache_rx) + b->exit_off[slot];
    const u8 *site_rx = b->code + b->exit_off[slot];
    u32 insn = enc_b(target_rx - site_rx);
    memcpy(site_rw, &insn, 4);
    b->patched[slot] = 1;
}
void be_unpatch_chain(JitEnv *env, JBlock *b, int slot) {
    u8 *site_rw = env->cache_rw + (b->code - env->cache_rx) + b->exit_off[slot];
    memcpy(site_rw, &b->stub_word0[slot], 4);     /* saved original word */
    b->patched[slot] = 0;
}

/* ---- thunks ---- */

int be_available(void) { return 1; }

void be_emit_thunks(Emit *e, JitEnv *env) {
    /* The allocator pool includes callee-saved x19-x26; the thunk must save
     * every register generated code can touch (x86 pushes its whole pool
     * the same way). */
    env->enter = (u32 (*)(JitEnv *, const u8 *))(uintptr_t)e->rx;
    ei(e, enc_ldstp64(0, 1, 29, 30, 31, -96));    /* stp x29,x30,[sp,#-96]! */
    ei(e, 0x910003FDu);                           /* mov x29, sp            */
    ei(e, enc_ldstp64(0, 0, 19, 20, 31, 16));
    ei(e, enc_ldstp64(0, 0, 21, 22, 31, 32));
    ei(e, enc_ldstp64(0, 0, 23, 24, 31, 48));
    ei(e, enc_ldstp64(0, 0, 25, 26, 31, 64));
    ei(e, enc_ldstp64(0, 0, 27, 28, 31, 80));
    ei(e, enc_mov(1, 27, 0));                     /* mov x27, x0            */
    ei(e, enc_ldr(3, 28, 0, (unsigned)offsetof(JitEnv, c)));
    ei(e, enc_br(1));                             /* br x1                  */

    env->epilogue_rx = e->rx;
    ei(e, enc_ldstp64(1, 0, 19, 20, 31, 16));
    ei(e, enc_ldstp64(1, 0, 21, 22, 31, 32));
    ei(e, enc_ldstp64(1, 0, 23, 24, 31, 48));
    ei(e, enc_ldstp64(1, 0, 25, 26, 31, 64));
    ei(e, enc_ldstp64(1, 0, 27, 28, 31, 80));
    ei(e, enc_ldstp64(1, 2, 29, 30, 31, 96));     /* ldp x29,x30,[sp],#96   */
    ei(e, 0xD65F03C0u);                           /* ret (w0 = exit id)     */
}

/* ---- block body ---- */

/* add/sub/logical shifted-register family, sf per w:
 *   op base | Rm<<16 | Rn<<5 | Rd */
static void alu3(BE *be, int w, u32 base, int d, int a, int b_) {
    int ha = ra_use(be, a);
    int hb = ra_use(be, b_);
    int hd = ra_def(be, d);
    ei(be->e, ((u32)w << 31) | base | ((u32)hb << 16) | ((u32)ha << 5) |
              (u32)hd);
}

/* Load a vreg's memory home into host reg h (scratch use around mem ops). */
static void ld_home(BE *be, int h, int v) {
    if (v == VREG_ZERO) { ei(be->e, enc_movz(1, (unsigned)h, 0, 0)); return; }
    s32 off = v_home(v);
    if (off >= 0) ei(be->e, enc_ldr(3, (unsigned)h, 28, (unsigned)off));
    else ei(be->e, enc_ldr(3, (unsigned)h, 27, (unsigned)v_spill(v)));
}

#define OFF_V(n) ((s32)(offsetof(CPU, v) + 16 * (n)))

/* size-log load/store, base reg, offset 0 (host access). szl 0..3 = 1..8B. */
static u32 enc_ldst0(unsigned szl, int load, unsigned rt, unsigned rn) {
    return ((u32)szl << 30) | (load ? 0x39400000u : 0x39000000u) |
           (rn << 5) | rt;
}
static u32 enc_ubfm(int sf, unsigned rd, unsigned rn, unsigned immr, unsigned imms) {
    return ((u32)sf << 31) | 0x53000000u | ((u32)sf << 22) | (immr << 16) |
           (imms << 10) | (rn << 5) | rd;
}
static u32 enc_sbfm(int sf, unsigned rd, unsigned rn, unsigned immr, unsigned imms) {
    return ((u32)sf << 31) | 0x13000000u | ((u32)sf << 22) | (immr << 16) |
           (imms << 10) | (rn << 5) | rd;
}
static u32 enc_bic(unsigned rd, unsigned rn, unsigned rm) {   /* Xn & ~Xm */
    return 0x8A200000u | (rm << 16) | (rn << 5) | rd;
}
static u32 enc_addr(unsigned rd, unsigned rn, unsigned rm) {  /* add Xd,Xn,Xm */
    return 0x8B000000u | (rm << 16) | (rn << 5) | rd;
}
static u32 enc_cmp(unsigned rn, unsigned rm) { return 0xEB000000u | (rm << 16) | (rn << 5) | 31; }
static u32 enc_tst(unsigned rn, unsigned rm) { return 0xEA000000u | (rm << 16) | (rn << 5) | 31; }
/* add/sub Xd,Xn,#imm12 (optionally <<12). Returns 0 if not encodable. */
static int enc_addsub_imm(Emit *e, int sub, unsigned rd, unsigned rn, u64 imm) {
    u32 base = sub ? 0xD1000000u : 0x91000000u;
    if ((imm & ~0xfffULL) == 0) { ei(e, base | ((u32)imm << 10) | (rn << 5) | rd); return 1; }
    if ((imm & ~0xfff000ULL) == 0) { ei(e, base | (1u << 22) | ((u32)(imm >> 12) << 10) | (rn << 5) | rd); return 1; }
    return 0;
}

/* Inline memory op (mirrors backend_x86_64.c): sync state, probe the D-TLB,
 * fast host access via x17, or an out-of-line helper. Operands read from /
 * results written to the CPU struct, so no host register crosses the op. */
static void emit_mem(BE *be, const IRBlock *ir, int i) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    int is_st = (o->op == IRO_ST || o->op == IRO_STV);
    int is_v  = (o->op == IRO_LDV || o->op == IRO_STV);
    unsigned desc = o->aux;
    unsigned rt = MDESC_RT(desc);
    unsigned szl = is_v ? MDESC_VSZL(desc) : (unsigned)o->cc;
    unsigned sz = 1u << szl;
    int need = is_st ? 2 : 1;

    sync_all(be);
    materialize_flags(be);
    drop_caller_saved(be);

    ld_home(be, 1, o->a);                         /* va -> x1 */
    if (o->imm) {
        s64 off = (s64)o->imm;
        u64 mag = off < 0 ? (u64)(-off) : (u64)off;
        if (!enc_addsub_imm(e, off < 0, 1, 1, mag)) {
            emit_imm64(e, 16, (u64)off);
            ei(e, enc_addr(1, 1, 16));
        }
    }
    ei(e, enc_ubfm(1, 16, 1, 12, 63));            /* lsr x16, x1, #12 (page) */
    ei(e, enc_ubfm(1, 17, 16, 0, 7));             /* ubfx x17, x16, #0, #8 */
    ei(e, enc_ubfm(1, 17, 17, (64 - 4) & 63, 63 - 4));   /* lsl x17, x17, #4 */
    ei(e, enc_ldr(3, 2, 27, (unsigned)offsetof(JitEnv, dtlb)));
    ei(e, enc_addr(17, 2, 17));                   /* x17 = dtlb + idx*16 */
    ei(e, enc_ldr(3, 2, 17, 0));                  /* tag = ent->page */
    ei(e, enc_cmp(2, 16));
    u8 *slow1 = bcond_fwd(e, 1);                  /* b.ne slow */
    ei(e, enc_ldr(3, 2, 17, 8));                  /* pte -> x2 */
    ei(e, enc_movz(1, 16, (unsigned)need, 0));
    ei(e, enc_tst(2, 16));
    u8 *slow2 = bcond_fwd(e, 0);                  /* b.eq slow (perm fail) */
    u8 *slow3 = NULL;
    if (sz > 1) {                                 /* page-cross gate */
        ei(e, enc_ubfm(1, 16, 1, 0, 11));         /* x16 = va & 0xfff */
        enc_addsub_imm(e, 0, 16, 16, sz);
        emit_imm64(e, 17, 0x1000);                /* x17 clobbered; recomputed below */
        ei(e, enc_cmp(16, 17));
        slow3 = bcond_fwd(e, 8);                  /* b.hi slow */
    }
    ei(e, enc_movz(1, 16, 7, 0));
    ei(e, enc_bic(2, 2, 16));                     /* x2 = pte & ~7 (host base) */
    ei(e, enc_ubfm(1, 16, 1, 0, 11));             /* x16 = va & 0xfff */
    ei(e, enc_addr(17, 2, 16));                   /* x17 = host ptr */

    /* ---- fast access (ptr = x17, data scratch = x16) ---- */
    if (!is_v) {
        if (is_st) {
            ld_home(be, 16, o->b);
            ei(e, enc_ldst0(szl, 0, 16, 17));
        } else {
            int sign = MDESC_SIGN(desc), is64 = MDESC_IS64(desc);
            ei(e, enc_ldst0(szl, 1, 16, 17));     /* zero-extended */
            if (sign) ei(e, enc_sbfm(is64, 16, 16, 0, sz * 8 - 1));
            if (rt != 31) {
                ei(e, enc_str(3, 16, 28, (unsigned)OFF_X(rt)));
                ra_unmap(be, (int)rt);
            }
        }
    } else {
        unsigned vd = rt, gs = szl > 3 ? 3 : szl;
        if (is_st) {
            ei(e, enc_ldr(3, 16, 28, (unsigned)OFF_V(vd)));
            ei(e, enc_ldst0(gs, 0, 16, 17));
            if (szl == 4) {
                ei(e, enc_ldr(3, 16, 28, (unsigned)OFF_V(vd) + 8));
                ei(e, enc_str(3, 16, 17, 8));
            }
        } else {
            ei(e, enc_ldst0(gs, 1, 16, 17));      /* zero-extended */
            ei(e, enc_str(3, 16, 28, (unsigned)OFF_V(vd)));
            if (szl == 4) {
                ei(e, enc_ldr(3, 16, 17, 8));
                ei(e, enc_str(3, 16, 28, (unsigned)OFF_V(vd) + 8));
            } else {
                ei(e, enc_movz(1, 16, 0, 0));
                ei(e, enc_str(3, 16, 28, (unsigned)OFF_V(vd) + 8));   /* clear high */
            }
        }
    }
    u8 *done = b_fwd(e);

    /* ---- slow path ---- */
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    if (slow3) fwd_here(e, slow3);
    ei(e, enc_mov(1, 0, 28));                     /* x0 = CPU* ; x1 = va */
    unsigned hoff;
    if (o->op == IRO_ST) {
        ld_home(be, 2, o->b);                     /* x2 = value */
        emit_imm64(e, 3, o->imm2pc);
        ei(e, enc_movz(0, 4, desc & 0xffff, 0));
        if (desc >> 16) ei(e, enc_movk(0, 4, desc >> 16, 1));
        hoff = (unsigned)offsetof(JitEnv, helper_st);
    } else {
        emit_imm64(e, 2, o->imm2pc);
        ei(e, enc_movz(0, 3, desc & 0xffff, 0));
        if (desc >> 16) ei(e, enc_movk(0, 3, desc >> 16, 1));
        hoff = o->op == IRO_LD ? (unsigned)offsetof(JitEnv, helper_ld)
             : o->op == IRO_LDV ? (unsigned)offsetof(JitEnv, helper_ldv)
                                : (unsigned)offsetof(JitEnv, helper_stv);
    }
    ei(e, enc_ldr(3, 16, 27, hoff));
    ei(e, enc_blr(16));
    u8 *ok = cbz_fwd(e, 0, 0);                    /* cbz w0, ok (no fault) */
    exit_plain(be, o->icnt);
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

    /* safepoint. c->pc must be restored to the block's start on the exit
     * path: a direct chain jump into this block bypassed the predecessor's
     * exit-stub pc write, so c->pc is stale on entry. */
    ei(e, enc_ldr(2, 16, 27, (unsigned)offsetof(JitEnv, interrupt)));
    u8 *cont = cbz_fwd(e, 0, 16);
    emit_imm64(e, 16, b->pc);
    ei(e, enc_str(3, 16, 28, (unsigned)OFF_PC));
    exit_plain(&be, 0);
    fwd_here(e, cont);

    for (int i = 0; i < ir->n && !e->overflow; )
        i += emit_op(&be, ir, i);

    return e->overflow ? -1 : 0;
}

static void emit_call1(BE *be, const IROp *o) {
    Emit *e = be->e;
    sync_all(be);
    materialize_flags(be);
    invalidate_all(be);
    ei(e, enc_mov(1, 0, 28));                     /* x0 = CPU* */
    emit_imm64(e, 1, o->imm);                     /* x1 = guest pc */
    ei(e, enc_movz(0, 2, o->aux & 0xffff, 0));    /* w2 = insn */
    ei(e, enc_movk(0, 2, o->aux >> 16, 1));
    ei(e, enc_ldr(3, 16, 27,
                  o->w ? (unsigned)offsetof(JitEnv, helper_exec1_ic)
                       : (unsigned)offsetof(JitEnv, helper_exec1)));
    ei(e, enc_blr(16));
    u8 *cont = cbz_fwd(e, 0, 0);                  /* cbz w0, cont */
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
            emit_imm64(e, (unsigned)hd, w ? o->imm : (u32)o->imm);
            break;
        }
        case IRO_MOV: {
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            ei(e, enc_mov(w, (unsigned)hd, (unsigned)ha));
            break;
        }
        case IRO_MOVK: {
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            if (hd != ha) ei(e, enc_mov(1, (unsigned)hd, (unsigned)ha));
            ei(e, enc_movk(w, (unsigned)hd,
                           (unsigned)((o->imm >> o->cc) & 0xffff),
                           (unsigned)(o->cc / 16)));
            break;
        }

        case IRO_ADD:  alu3(be, w, 0x0B000000u, o->dst, o->a, o->b); break;
        case IRO_SUB:  alu3(be, w, 0x4B000000u, o->dst, o->a, o->b); break;
        case IRO_AND:  alu3(be, w, 0x0A000000u, o->dst, o->a, o->b); break;
        case IRO_BIC:  alu3(be, w, 0x0A200000u, o->dst, o->a, o->b); break;
        case IRO_ORR:  alu3(be, w, 0x2A000000u, o->dst, o->a, o->b); break;
        case IRO_ORN:  alu3(be, w, 0x2A200000u, o->dst, o->a, o->b); break;
        case IRO_EOR:  alu3(be, w, 0x4A000000u, o->dst, o->a, o->b); break;
        case IRO_EON:  alu3(be, w, 0x4A200000u, o->dst, o->a, o->b); break;
        case IRO_ADDS:
            alu3(be, w, o->flags_dead ? 0x0B000000u : 0x2B000000u,
                 o->dst, o->a, o->b);
            if (!o->flags_dead) set_flags_state(be, ir, i);
            break;
        case IRO_SUBS:
            alu3(be, w, o->flags_dead ? 0x4B000000u : 0x6B000000u,
                 o->dst, o->a, o->b);
            if (!o->flags_dead) set_flags_state(be, ir, i);
            break;
        case IRO_ANDS:
            alu3(be, w, o->flags_dead ? 0x0A000000u : 0x6A000000u,
                 o->dst, o->a, o->b);
            if (!o->flags_dead) set_flags_state(be, ir, i);
            break;
        case IRO_BICS:
            alu3(be, w, o->flags_dead ? 0x0A200000u : 0x6A200000u,
                 o->dst, o->a, o->b);
            if (!o->flags_dead) set_flags_state(be, ir, i);
            break;

        case IRO_ADDI: case IRO_ADDIS: case IRO_SUBI: case IRO_SUBIS: {
            int S = (o->op == IRO_ADDIS || o->op == IRO_SUBIS) &&
                    !o->flags_dead;
            int sub = (o->op == IRO_SUBI || o->op == IRO_SUBIS);
            u64 imm = w ? o->imm : (u32)o->imm;
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            u32 base = sub ? (S ? 0x71000000u : 0x51000000u)
                           : (S ? 0x31000000u : 0x11000000u);
            if ((imm & ~0xfffULL) == 0) {
                ei(e, ((u32)w << 31) | base | ((u32)imm << 10) |
                      ((u32)ha << 5) | (u32)hd);
            } else if ((imm & ~0xfff000ULL) == 0) {
                ei(e, ((u32)w << 31) | base | (1u << 22) |
                      ((u32)(imm >> 12) << 10) | ((u32)ha << 5) | (u32)hd);
            } else {
                emit_imm64(e, 17, imm);
                u32 rbase = sub ? (S ? 0x6B000000u : 0x4B000000u)
                                : (S ? 0x2B000000u : 0x0B000000u);
                ei(e, ((u32)w << 31) | rbase | (17u << 16) |
                      ((u32)ha << 5) | (u32)hd);
            }
            if (S) set_flags_state(be, ir, i);
            break;
        }
        case IRO_ANDI: case IRO_ANDIS: case IRO_ORRI: case IRO_EORI: {
            int S = (o->op == IRO_ANDIS) && !o->flags_dead;
            u64 imm = w ? o->imm : (u32)o->imm;
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            emit_imm64(e, 17, imm);               /* wmask: reg form */
            u32 base = o->op == IRO_ORRI ? 0x2A000000u
                     : o->op == IRO_EORI ? 0x4A000000u
                     : S ? 0x6A000000u : 0x0A000000u;
            ei(e, ((u32)w << 31) | base | (17u << 16) | ((u32)ha << 5) |
                  (u32)hd);
            if (S) set_flags_state(be, ir, i);
            break;
        }

        case IRO_LSLI: case IRO_LSRI: case IRO_ASRI: {
            unsigned amt = (unsigned)o->imm & (w ? 63 : 31);
            unsigned width = w ? 64 : 32;
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            u32 bfm = (o->op == IRO_ASRI ? 0x13000000u : 0x53000000u) |
                      ((u32)w << 31) | ((u32)w << 22);
            unsigned immr, imms;
            if (o->op == IRO_LSLI) {
                immr = (width - amt) & (width - 1);
                imms = width - 1 - amt;
            } else {
                immr = amt;
                imms = width - 1;
            }
            ei(e, bfm | (immr << 16) | (imms << 10) | ((u32)ha << 5) |
                  (u32)hd);
            break;
        }
        case IRO_RORI: {
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            unsigned amt = (unsigned)o->imm & (w ? 63 : 31);
            ei(e, ((u32)w << 31) | 0x13800000u | ((u32)w << 22) |
                  ((u32)ha << 16) | (amt << 10) | ((u32)ha << 5) | (u32)hd);
            break;
        }
        case IRO_LSLV: case IRO_LSRV: case IRO_ASRV: case IRO_RORV: {
            static const u32 op2[] = { 0x2000, 0x2400, 0x2800, 0x2C00 };
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            int hd = ra_def(be, o->dst);
            ei(e, ((u32)w << 31) | 0x1AC00000u | op2[o->op - IRO_LSLV] |
                  ((u32)hb << 16) | ((u32)ha << 5) | (u32)hd);
            break;
        }
        case IRO_EXTR: {
            int ha = ra_use(be, o->a);            /* hi */
            int hb = ra_use(be, o->b);            /* lo */
            int hd = ra_def(be, o->dst);
            /* EXTR Rd, Rn, Rm, #lsb: Rn ([9:5]) is the HIGH half, Rm
             * ([20:16]) the LOW half: Rd = (Rn:Rm) >> lsb */
            ei(e, ((u32)w << 31) | 0x13800000u | ((u32)w << 22) |
                  ((u32)hb << 16) | (((u32)o->imm & 63) << 10) |
                  ((u32)ha << 5) | (u32)hd);
            break;
        }

        case IRO_MADD: case IRO_MSUB: {
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            int hr = (o->cc == VREG_ZERO) ? 31 : ra_use(be, o->cc);
            int hd = ra_def(be, o->dst);
            ei(e, ((u32)w << 31) | 0x1B000000u |
                  (o->op == IRO_MSUB ? 0x8000u : 0) | ((u32)hb << 16) |
                  ((u32)hr << 10) | ((u32)ha << 5) | (u32)hd);
            break;
        }
        case IRO_SMADDL: case IRO_SMSUBL: case IRO_UMADDL: case IRO_UMSUBL: {
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            int hr = (o->cc == VREG_ZERO) ? 31 : ra_use(be, o->cc);
            int hd = ra_def(be, o->dst);
            u32 base = (o->op == IRO_SMADDL || o->op == IRO_SMSUBL)
                           ? 0x9B200000u : 0x9BA00000u;
            if (o->op == IRO_SMSUBL || o->op == IRO_UMSUBL) base |= 0x8000u;
            ei(e, base | ((u32)hb << 16) | ((u32)hr << 10) | ((u32)ha << 5) |
                  (u32)hd);
            break;
        }
        case IRO_SMULH: case IRO_UMULH: {
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            int hd = ra_def(be, o->dst);
            ei(e, (o->op == IRO_SMULH ? 0x9B407C00u : 0x9BC07C00u) |
                  ((u32)hb << 16) | ((u32)ha << 5) | (u32)hd);
            break;
        }
        case IRO_UDIV: case IRO_SDIV: {
            int ha = ra_use(be, o->a);
            int hb = ra_use(be, o->b);
            int hd = ra_def(be, o->dst);
            ei(e, ((u32)w << 31) | 0x1AC00800u |
                  (o->op == IRO_SDIV ? 0x400u : 0) | ((u32)hb << 16) |
                  ((u32)ha << 5) | (u32)hd);
            break;
        }
        case IRO_CLZ: {
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            ei(e, ((u32)w << 31) | 0x5AC01000u | ((u32)ha << 5) | (u32)hd);
            break;
        }
        case IRO_REV64: {
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            ei(e, 0xDAC00C00u | ((u32)ha << 5) | (u32)hd);
            break;
        }
        case IRO_REV32: {
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            ei(e, 0x5AC00800u | ((u32)ha << 5) | (u32)hd);
            break;
        }

        case IRO_CSEL: case IRO_CSINC: case IRO_CSINV: case IRO_CSNEG: {
            flags_to_host(be);
            int ha = (o->a == VREG_ZERO) ? -1 : ra_use(be, o->a);
            int hb = (o->b == VREG_ZERO) ? -1 : ra_use(be, o->b);
            if (ha < 0) { ei(e, enc_movz(1, 16, 0, 0)); ha = 16; }
            if (hb < 0) { ei(e, enc_movz(1, 17, 0, 0)); hb = 17; }
            int hd = ra_def(be, o->dst);
            u32 base = o->op == IRO_CSEL ? 0x1A800000u
                     : o->op == IRO_CSINC ? 0x1A800400u
                     : o->op == IRO_CSINV ? 0x5A800000u : 0x5A800400u;
            ei(e, ((u32)w << 31) | base | ((u32)hb << 16) |
                  ((u32)(o->cc & 15) << 12) | ((u32)ha << 5) | (u32)hd);
            break;
        }
        case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI: {
            flags_to_host(be);
            int ha = ra_use(be, o->a);
            int is_imm = (o->op == IRO_CCMPI || o->op == IRO_CCMNI);
            int is_cmn = (o->op == IRO_CCMNR || o->op == IRO_CCMNI);
            /* guest nzcv-else value: convert PS_* word to the imm4 */
            u32 f = o->aux;
            u32 nzcv4 = ((f >> 31) & 1) << 3 | ((f >> 30) & 1) << 2 |
                        ((f >> 29) & 1) << 1 | ((f >> 28) & 1);
            u32 base = is_cmn ? 0x3A400000u : 0x7A400000u;
            if (is_imm) {
                ei(e, ((u32)w << 31) | base | 0x800u |
                      ((u32)(o->imm & 31) << 16) |
                      ((u32)(o->cc & 15) << 12) | ((u32)ha << 5) | nzcv4);
            } else {
                int hb = ra_use(be, o->b);
                ei(e, ((u32)w << 31) | base | ((u32)hb << 16) |
                      ((u32)(o->cc & 15) << 12) | ((u32)ha << 5) | nzcv4);
            }
            be->fl = FL_HOST;
            set_flags_state(be, ir, i);
            break;
        }

        /* ---- terminals ---- */
        case IRO_JMP:
            sync_all(be);
            materialize_flags(be);
            exit_stub(be, 0, o->imm, o->icnt);
            break;
        case IRO_BCOND: {
            sync_all(be);
            flags_to_host(be);
            materialize_flags(be);                /* mrs+str keeps NZCV */
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = bcond_fwd(e, o->cc & 15);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_CBZ: case IRO_CBNZ: {
            sync_all(be);
            materialize_flags(be);
            int ha = ra_use(be, o->a);
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = (o->op == IRO_CBZ) ? cbz_fwd(e, w, (unsigned)ha)
                                           : cbnz_fwd(e, w, (unsigned)ha);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_TBZ: case IRO_TBNZ: {
            sync_all(be);
            materialize_flags(be);
            int ha = ra_use(be, o->a);
            unsigned bit = o->cc;
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = e->rw;
            ei(e, ((u32)(bit >> 5) << 31) |
                  (o->op == IRO_TBZ ? 0x36000000u : 0x37000000u) |
                  ((u32)(bit & 31) << 19) | (u32)ha);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            {   /* patch tbz imm14 */
                u32 insn;
                memcpy(&insn, taken, 4);
                s64 off = (e->rw - taken) >> 2;
                insn |= ((u32)off & 0x3FFFu) << 5;
                memcpy(taken, &insn, 4);
            }
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_JMPIND: {
            sync_all(be);
            materialize_flags(be);
            int ha = ra_use(be, o->a);
            ei(e, enc_str(3, (unsigned)ha, 28, (unsigned)OFF_PC));
            icount_add(be, o->icnt);
            /* ubfx x16, ha, #2, #JC_BITS (UBFM immr=2, imms=2+bits-1) */
            ei(e, 0xD3400000u | (2u << 16) | ((2u + JIT_JC_BITS - 1) << 10) |
                  ((u32)ha << 5) | 16);
            /* add x16, x27, x16, lsl #4 (shifted-reg, imm6 in [15:10]) */
            ei(e, 0x8B000000u | (16u << 16) | (4u << 10) | (27u << 5) | 16);
            /* add x16, x16, #jcache_off */
            ei(e, 0x91000000u |
                  (((u32)offsetof(JitEnv, jcache) & 0xfff) << 10) |
                  (16u << 5) | 16);
            ei(e, enc_ldstp64(1, 0, 17, 16, 16, 0));   /* ldp x17,x16,[x16] */
            /* cmp x17, ha : SUBS xzr */
            ei(e, 0xEB000000u | ((u32)ha << 16) | (17u << 5) | 31);
            u8 *miss = bcond_fwd(e, 1);           /* b.ne miss */
            ei(e, enc_br(16));
            fwd_here(e, miss);
            ei(e, enc_movn(0, 0, 0, 0));
            b_to(e, be->env->epilogue_rx);
            break;
        }
        case IRO_LD: case IRO_ST: case IRO_LDV: case IRO_STV:
            emit_mem(be, ir, i);
            break;
        case IRO_CALL1:
            emit_call1(be, o);
            break;

        default:
            e->overflow = 1;
            break;
    }
    return 1;
}

void be_flush_icache(const u8 *rx, const u8 *rw, size_t len) {
    __builtin___clear_cache((char *)(uintptr_t)rw, (char *)(uintptr_t)(rw + len));
    if (rx != rw)
        __builtin___clear_cache((char *)(uintptr_t)rx,
                                (char *)(uintptr_t)(rx + len));
}

#endif /* __aarch64__ */
