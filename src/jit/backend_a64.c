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

#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

/* AT_HWCAP bits for FEAT_FP16 (half-precision arithmetic). Not all libc
 * headers predefine these, so provide the architectural values. */
#ifndef HWCAP_FPHP
#define HWCAP_FPHP    (1u << 9)   /* scalar half-precision FP */
#endif
#ifndef HWCAP_ASIMDHP
#define HWCAP_ASIMDHP (1u << 10)  /* SIMD half-precision FP */
#endif

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
    /* guest V-register cache: host v18-v29 (v0-v3/v16-v17 stay recipe
     * scratch; v8-v15 are AAPCS callee-saved and the thunks don't save
     * them) */
    s8  vv2h[32];
    u8  vh2v[32];               /* 32 = free */
    u8  vdirty[32];
    u32 vlru[32];
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
static u8 *tbz_fwd(Emit *e, unsigned rt, unsigned bit) {   /* bit < 32 */
    u8 *p = e->rw;
    ei(e, 0x36000000u | (bit << 19) | rt);
    return p;
}
static void fwd_here(Emit *e, u8 *p) {
    if (!p || e->overflow) return;
    u32 insn;
    memcpy(&insn, p, 4);
    s64 off = (e->rw - p) >> 2;
    if ((insn & 0x7C000000u) == 0x14000000u)        /* B */
        insn |= ((u32)off & 0x03FFFFFFu);
    else if ((insn & 0x7E000000u) == 0x36000000u)   /* TBZ/TBNZ: imm14 */
        insn |= (((u32)off & 0x3FFFu) << 5);
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

/* Offset of the emission cursor from the code-cache base, for the bus-fault
 * fixup table (see JFixup): a host SIGBUS inside an inline access resumes at
 * that access's slow path. */
static u32 cache_off(BE *be) {
    return (u32)(be->e->rx - be->env->cache_rx);
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
/* Map without defining: keeps (or gets) a clean state so a bail-path
 * slow_store_dirty never stores a not-yet-written value (fused mem runs
 * pre-map their load destinations outside the branch). */
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

static void vra_sync_all(BE *be);
static void vra_inval_all(BE *be);
static void sync_all(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && be->dirty[v]) { v_store(be, v); be->dirty[v] = 0; }
    vra_sync_all(be);
}
static void invalidate_all(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0) ra_unmap(be, v);
    vra_inval_all(be);
}

/* Caller-saved pool regs (x9-x15) don't survive a C call. A memory-op slow
 * path stores every dirty mapped vreg before its call (dirty bits kept: the
 * fast path never ran those stores) and reloads the caller-saved-mapped ones
 * after, so both paths converge on the same allocator state. The
 * callee-saved half (x19-x26) stays resident. */
static int is_caller_saved(int h) { return h >= 9 && h <= 15; }

/* V-register cache counterparts (defined after the q-load/store encoders). */
static void vra_sync_all(BE *be);
static void vra_inval_all(BE *be);
static void vra_slow_store_dirty(BE *be);
static void vra_slow_reload_all(BE *be);
static void vra_spill(BE *be, unsigned vn);
static void vra_flush(BE *be, unsigned vn);

static void slow_store_dirty(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && be->dirty[v]) v_store(be, v);
    vra_slow_store_dirty(be);
}
static void slow_reload_clobbered(BE *be) {
    for (int v = 0; v < VREG_N; v++)
        if (be->v2h[v] >= 0 && is_caller_saved(be->v2h[v]))
            v_load_into(be, v, be->v2h[v]);
    vra_slow_reload_all(be);                     /* v18-29: caller-saved */
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

/* What happens to the guest flags next? FLAGS_CONSUMED: a cc-consumer or
 * an exit reads them — keep them live in host NZCV. FLAGS_DEAD: an S-op
 * redefines them first through NZCV-transparent ops — skip the mrs/str.
 * FLAGS_UNKNOWN: materialize now. Every non-S ALU emission here is
 * NZCV-transparent (host adds/logicals/shifts/muls don't touch flags), so
 * the window only ends at ops that write NZCV or materialize on their own
 * (mem probes, atomics, helpers, the cmn/fcmp-using VOPs). */
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
            case IRO_NOP: case IRO_MOVI: case IRO_MOV: case IRO_MOVK:
            case IRO_CPULD: case IRO_CPUST:
            case IRO_ADD: case IRO_SUB: case IRO_ADDI: case IRO_SUBI:
            case IRO_AND: case IRO_BIC: case IRO_ORR: case IRO_ORN:
            case IRO_EOR: case IRO_EON:
            case IRO_ANDI: case IRO_ORRI: case IRO_EORI:
            case IRO_LSLI: case IRO_LSRI: case IRO_ASRI: case IRO_RORI:
            case IRO_LSLV: case IRO_LSRV: case IRO_ASRV: case IRO_RORV:
            case IRO_EXTR: case IRO_MADD: case IRO_MSUB:
            case IRO_SMADDL: case IRO_SMSUBL: case IRO_UMADDL:
            case IRO_UMSUBL: case IRO_SMULH: case IRO_UMULH:
            case IRO_UDIV: case IRO_SDIV:
            case IRO_CLZ: case IRO_REV64: case IRO_REV32: case IRO_RBIT:
                continue;                        /* NZCV-transparent */
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
static void set_flags_state(BE *be, const IRBlock *ir, int i) {
    be->fl = FL_HOST;
    if (flags_next_use(ir, i) == FLAGS_UNKNOWN) materialize_flags(be);
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
/* AND Xd, Xn, #imm (64-bit logical immediate, caller supplies immr/imms:
 * mask = ROR(ones(imms+1), immr) with N=1). */
static u32 enc_andi64(unsigned rd, unsigned rn, unsigned immr, unsigned imms) {
    return 0x92400000u | (immr << 16) | (imms << 10) | (rn << 5) | rd;
}
/* size-log load/store, register offset: [Xn, Xm] (option=LSL #0). */
static u32 enc_ldstr(unsigned szl, int load, unsigned rt, unsigned rn,
                     unsigned rm) {
    return ((u32)szl << 30) | (load ? 0x38606800u : 0x38206800u) |
           (rm << 16) | (rn << 5) | rt;
}
static u32 enc_addr(unsigned rd, unsigned rn, unsigned rm) {  /* add Xd,Xn,Xm */
    return 0x8B000000u | (rm << 16) | (rn << 5) | rd;
}
static u32 enc_cmp(unsigned rn, unsigned rm) { return 0xEB000000u | (rm << 16) | (rn << 5) | 31; }
/* add/sub Xd,Xn,#imm12 (optionally <<12). Returns 0 if not encodable. */
static int enc_addsub_imm(Emit *e, int sub, unsigned rd, unsigned rn, u64 imm) {
    u32 base = sub ? 0xD1000000u : 0x91000000u;
    if ((imm & ~0xfffULL) == 0) { ei(e, base | ((u32)imm << 10) | (rn << 5) | rd); return 1; }
    if ((imm & ~0xfff000ULL) == 0) { ei(e, base | (1u << 22) | ((u32)(imm >> 12) << 10) | (rn << 5) | rd); return 1; }
    return 0;
}

/* Inline memory op (mirrors backend_x86_64.c). Fast path = probe + access
 * only: operands and results live in allocated host registers and no guest
 * state is written. The slow branch carries the whole cost: it stores every
 * dirty mapped vreg (keeping the dirty bits — the fast path never ran those
 * stores), calls the helper, and reloads the caller-saved-mapped vregs so
 * both paths converge on the allocator state emission continues with. Loads
 * converge with the extended value in x16; one post-merge ra_def commits it. */
static void emit_mem(BE *be, const IRBlock *ir, int i) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    int is_st = (o->op == IRO_ST || o->op == IRO_STV);
    int is_v  = (o->op == IRO_LDV || o->op == IRO_STV);
    unsigned desc = o->aux;
    unsigned szl = is_v ? MDESC_VSZL(desc) : (unsigned)o->cc;
    unsigned sz = 1u << szl;
    int need = is_st ? 2 : 1;

    /* Vector mem ops work on c->v[] directly: LDV overwrites the register
     * (spill first so a fault still sees the old value, then drop the
     * stale mapping), STV reads it (make memory current, keep it). */
    if (o->op == IRO_LDV) vra_spill(be, MDESC_RT(desc));
    else if (o->op == IRO_STV) vra_flush(be, MDESC_RT(desc));

    materialize_flags(be);                        /* the probe needs NZCV */
    int hb = -1;
    if (o->op == IRO_ST) hb = ra_use(be, o->b);   /* store operand */
    int ha = ra_use(be, o->a);                    /* base */

    /* va = base + offset -> x1 (scratch; also the slow call's arg1) */
    if (o->imm == 0) {
        ei(e, enc_mov(1, 1, (unsigned)ha));
    } else {
        s64 off = (s64)o->imm;
        u64 mag = off < 0 ? (u64)(-off) : (u64)off;
        if (!enc_addsub_imm(e, off < 0, 1, (unsigned)ha, mag)) {
            emit_imm64(e, 16, (u64)off);
            ei(e, enc_addr(1, (unsigned)ha, 16));
        }
    }

    u8 *slow0 = NULL, *slow1 = NULL, *slow2 = NULL;
    if (UNLIKELY(be->env->slowmem)) {
        slow0 = b_fwd(e);                         /* bisection: helper always */
        goto fast;
    }
    /* The tag compare uses the LAST byte's page while the index (and the
     * stored tag) come from the first byte's: a page-crossing access
     * mismatches and falls to the slow helper — no separate cross gate.
     * (TBI-tagged VAs mismatch the stripped stored tag the same way.) */
    if (sz > 1) {
        enc_addsub_imm(e, 0, 16, 1, sz - 1);      /* x16 = va + sz-1 */
        ei(e, enc_ubfm(1, 16, 16, 12, 63));       /* lsr x16, x16, #12 */
    } else {
        ei(e, enc_ubfm(1, 16, 1, 12, 63));        /* lsr x16, x1, #12 */
    }
    ei(e, enc_ubfm(1, 17, 1, 8, 63));             /* lsr x17, x1, #8 */
    ei(e, enc_andi64(17, 17,                      /* and x17,x17,#(idxmask<<4):
                                                   * ROR(ones(idxbits), 60) */
                     (64 - 4) & 63,
                     (unsigned)__builtin_ctz(A64_DTLB_ENTRIES) - 1));
    ei(e, enc_ldr(3, 2, 27, (unsigned)offsetof(JitEnv, dtlb)));
    ei(e, enc_addr(17, 2, 17));                   /* x17 = &dtlb[idx] */
    ei(e, enc_ldr(3, 2, 17, 0));                  /* tag = ent->page */
    ei(e, enc_cmp(2, 16));
    slow1 = bcond_fwd(e, 1);                      /* b.ne slow */
    ei(e, enc_ldr(3, 2, 17, 8));                  /* pte -> x2 */
    slow2 = tbz_fwd(e, 2, need == 2 ? 1 : 0);     /* perm bit clear -> slow */
    ei(e, enc_andi64(2, 2, 61, 60));              /* and x2, x2, #~7 (host) */
    ei(e, enc_andi64(16, 1, 0, 11));              /* and x16, x1, #0xfff */

fast:;
    u32 fix_fast = cache_off(be);
    /* ---- fast access (base = x2, page offset = x16; loads -> x16) ---- */
    if (!is_v) {
        if (is_st) {
            ei(e, enc_ldstr(szl, 0, (unsigned)hb, 2, 16));
        } else {
            int sign = MDESC_SIGN(desc), is64 = MDESC_IS64(desc);
            ei(e, enc_ldstr(szl, 1, 16, 2, 16));  /* zero-extended */
            if (sign) ei(e, enc_sbfm(is64, 16, 16, 0, sz * 8 - 1));
        }
    } else {
        unsigned vd = MDESC_RT(desc), gs = szl > 3 ? 3 : szl;
        ei(e, enc_addr(17, 2, 16));               /* x17 = host ptr */
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
    fwd_here(e, slow0);
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    be_fixup_add(be->env, fix_fast, cache_off(be));
    slow_store_dirty(be);                         /* dirty bits kept: above */
    unsigned hoff;
    if (o->op == IRO_ST) {
        ei(e, enc_mov(1, 2, (unsigned)hb));       /* x2 = value (hb: pool) */
        ei(e, enc_mov(1, 0, 28));                 /* x0 = CPU* ; x1 = va */
        emit_imm64(e, 3, o->imm2pc);
        ei(e, enc_movz(0, 4, desc & 0xffff, 0));
        if (desc >> 16) ei(e, enc_movk(0, 4, desc >> 16, 1));
        hoff = (unsigned)offsetof(JitEnv, helper_st);
    } else {
        ei(e, enc_mov(1, 0, 28));                 /* x0 = CPU* ; x1 = va */
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
    exit_plain(be, o->icnt);                      /* all dirty state stored */
    fwd_here(e, ok);
    slow_reload_clobbered(be);                    /* helper ate x9-x15 */
    if (o->op == IRO_LD && o->dst != VREG_ZERO)
        ld_home(be, 16, o->dst);                  /* helper committed to home */
    fwd_here(e, done);

    /* ---- merge: commit a load to its register ---- */
    if (o->op == IRO_LD && o->dst != VREG_ZERO) {
        int hd = ra_def(be, o->dst);
        ei(e, enc_mov(1, (unsigned)hd, 16));
    }
    be->fl = FL_MEM;
}

/* ---- fused memory runs (probe sharing; mirrors backend_x86_64.c) ---- */

static int fuse_enabled(void) {
    static int v = -1;
    if (v < 0) v = getenv("A64_JIT_NOFUSE") == NULL;
    return v;
}

#define FUSE_VA_SLOT ((unsigned)(offsetof(JitEnv, tmp_spill) + 24))

/* k same-base constant-offset accesses behind ONE span-checked probe. The
 * bail path re-runs every access through its helper in program order, each
 * with its own baked pc and fault exit; va0 survives the calls in a JitEnv
 * spill slot. */
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

    materialize_flags(be);                        /* the probe needs NZCV */
    int ha = ra_use(be, o->a);
    for (int t = 0; t < k; t++) {
        const IROp *p = &ir->ops[i + t];
        if (is_st) hb[t] = ra_use(be, p->b);
        else hd[t] = (p->dst == VREG_ZERO) ? -1 : ra_map_clean(be, p->dst);
    }

    /* x1 = va0 = base + lo */
    if (lo == 0) {
        ei(e, enc_mov(1, 1, (unsigned)ha));
    } else {
        u64 mag = lo < 0 ? (u64)(-lo) : (u64)lo;
        if (!enc_addsub_imm(e, lo < 0, 1, (unsigned)ha, mag)) {
            emit_imm64(e, 16, (u64)lo);
            ei(e, enc_addr(1, (unsigned)ha, 16));
        }
    }

    u8 *slow0 = NULL, *slow1 = NULL, *slow2 = NULL;
    if (UNLIKELY(be->env->slowmem)) {
        slow0 = b_fwd(e);
        goto fast;
    }
    /* span-checked probe: compare the run's last byte's page against the
     * tag stored for va0's page — any crossing of the span mismatches */
    enc_addsub_imm(e, 0, 16, 1, (u64)(hi - lo - 1));
    ei(e, enc_ubfm(1, 16, 16, 12, 63));           /* lsr x16, x16, #12 */
    ei(e, enc_ubfm(1, 17, 1, 8, 63));
    ei(e, enc_andi64(17, 17, (64 - 4) & 63,
                     (unsigned)__builtin_ctz(A64_DTLB_ENTRIES) - 1));
    ei(e, enc_ldr(3, 2, 27, (unsigned)offsetof(JitEnv, dtlb)));
    ei(e, enc_addr(17, 2, 17));
    ei(e, enc_ldr(3, 2, 17, 0));
    ei(e, enc_cmp(2, 16));
    slow1 = bcond_fwd(e, 1);
    ei(e, enc_ldr(3, 2, 17, 8));
    slow2 = tbz_fwd(e, 2, need == 2 ? 1 : 0);
    ei(e, enc_andi64(2, 2, 61, 60));              /* host backing base */
    ei(e, enc_andi64(16, 1, 0, 11));              /* pageoff of va0 */
    ei(e, enc_addr(17, 2, 16));                   /* x17 = host ptr va0 */

fast:;
    u32 fix_fast = cache_off(be);
    for (int t = 0; t < k; t++) {
        const IROp *p = &ir->ops[i + t];
        u64 d = (u64)((s64)p->imm - lo);
        unsigned szl = p->cc;
        unsigned addr = 17;
        if (d) { enc_addsub_imm(e, 0, 16, 17, d); addr = 16; }
        if (is_st) {
            ei(e, enc_ldst0(szl, 0, (unsigned)hb[t], addr));
        } else {
            unsigned rt = hd[t] < 0 ? 16u : (unsigned)hd[t];
            int sign = MDESC_SIGN(p->aux), is64 = MDESC_IS64(p->aux);
            ei(e, enc_ldst0(szl, 1, rt, addr));   /* zero-extended */
            if (sign) ei(e, enc_sbfm(is64, rt, rt, 0, (1u << szl) * 8 - 1));
        }
    }
    u8 *done = b_fwd(e);

    /* ---- bail: the helpers, in program order ---- */
    fwd_here(e, slow0);
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    be_fixup_add(be->env, fix_fast, cache_off(be));
    slow_store_dirty(be);
    ei(e, enc_str(3, 1, 27, FUSE_VA_SLOT));
    for (int t = 0; t < k; t++) {
        const IROp *p = &ir->ops[i + t];
        u64 d = (u64)((s64)p->imm - lo);
        ei(e, enc_ldr(3, 1, 27, FUSE_VA_SLOT));
        if (d) enc_addsub_imm(e, 0, 1, 1, d);
        ei(e, enc_mov(1, 0, 28));                 /* x0 = CPU* */
        if (is_st) {
            ld_home(be, 2, p->b);                 /* homes are current */
            emit_imm64(e, 3, p->imm2pc);
            ei(e, enc_movz(0, 4, p->aux & 0xffff, 0));
            if (p->aux >> 16) ei(e, enc_movk(0, 4, p->aux >> 16, 1));
        } else {
            emit_imm64(e, 2, p->imm2pc);
            ei(e, enc_movz(0, 3, p->aux & 0xffff, 0));
            if (p->aux >> 16) ei(e, enc_movk(0, 3, p->aux >> 16, 1));
        }
        ei(e, enc_ldr(3, 16, 27,
                      is_st ? (unsigned)offsetof(JitEnv, helper_st)
                            : (unsigned)offsetof(JitEnv, helper_ld)));
        ei(e, enc_blr(16));
        u8 *okk = cbz_fwd(e, 0, 0);
        exit_plain(be, p->icnt);
        fwd_here(e, okk);
    }
    slow_reload_clobbered(be);
    if (!is_st)
        for (int t = 0; t < k; t++)               /* helpers committed home */
            if (hd[t] >= 0)
                v_load_into(be, ir->ops[i + t].dst, hd[t]);
    fwd_here(e, done);

    if (!is_st)
        for (int t = 0; t < k; t++)
            if (hd[t] >= 0) be->dirty[ir->ops[i + t].dst] = 1;
    be->fl = FL_MEM;
}

/* ---- inline vector / scalar FP (IRO_VOP; exec_fpsimd.c is the reference).
 * Same-ISA host: whitelisted classes re-emit the guest word itself with the
 * vector register fields renumbered onto host v0-v2 (loaded from / stored
 * back to c->v[]), so semantics are the guest's by construction. GPR-linked
 * forms substitute x16 into the Rn/Rd field. ---- */

/* FEAT_FP16 (native half-precision arith/convert) probe. Gates the FP16
 * classes: without it, half encodings stay interpreter helpers. Both HWCAP
 * bits (scalar FPHP + SIMD ASIMDHP) come together on real FEAT_FP16 cores.
 * A64_JIT_NOFP16 forces it off, exercising the helper fallback. */
static int cpu_has_fp16(void) {
    static int v = -1;
    if (v < 0) {
        unsigned long hw = getauxval(AT_HWCAP);
        v = ((hw & (HWCAP_FPHP | HWCAP_ASIMDHP)) == (HWCAP_FPHP | HWCAP_ASIMDHP))
            && getenv("A64_JIT_NOFP16") == NULL;
    }
    return v;
}

int be_vop_ok(unsigned vclass, u32 insn) {
    switch (vclass) {
        case VC_BITW: case VC_ADDSUB: case VC_CM3: case VC_SHIFTI:
        case VC_MINMAX: case VC_MUL3: case VC_PAIRI: case VC_2MISC:
        case VC_ACROSS: case VC_VF3S: case VC_VFCM:
        case VC_MOVI: case VC_COPY: case VC_F1: case VC_F3:
        case VC_FMOVG:
        case VC_CVTIF: case VC_CVTFI: case VC_FCVT:
        case VC_S3S: case VC_SSHIFTI:
            return 1;
        case VC_FCVTH:                           /* half<->s/d converts: base ISA */
            return 1;
        case VC_FCMP: case VC_FCCMP: case VC_FCSEL: case VC_FMOVI:
            /* half forms use FEAT_FP16 instructions (native replay); s/d base. */
            return (((insn >> 22) & 3) == 3) ? cpu_has_fp16() : 1;
        case VC_H1: case VC_H3:                  /* scalar half 1/3-source arith */
            return cpu_has_fp16();
        case VC_H2: {                            /* half 2-src; MAX/MIN decline */
            unsigned opc = (insn >> 12) & 0xf;
            if (opc >= 4 && opc <= 7) return 0;
            return cpu_has_fp16();
        }
        case VC_VH3: case VC_VHCM: case VC_VH2M: /* vector half: FEAT_FP16 */
        case VC_VHMULX: case VC_VHEST:           /* FMULX / FRECPE / FRSQRTE */
            return cpu_has_fp16();
        case VC_F2: {
            /* FMAX/FMIN/FMAXNM/FMINNM (opc 4-7): keep the interpreter helper,
             * whose fop_d/fop_s carry ARM's NaN propagation and +0/-0 ordering
             * that a bare fmax/fmin instruction does not. */
            unsigned opc = (insn >> 12) & 0xf;
            return opc <= 3 || opc == 8;
        }
        default:
            return 0;
    }
}

static u32 enc_ldq(unsigned qt, unsigned rn, unsigned off) {   /* LDR Qt */
    return 0x3DC00000u | ((off / 16) << 10) | (rn << 5) | qt;
}
static u32 enc_stq(unsigned qt, unsigned rn, unsigned off) {   /* STR Qt */
    return 0x3D800000u | ((off / 16) << 10) | (rn << 5) | qt;
}

/* ---- guest V-register cache ----
 * Block-local LRU cache of guest V registers in host v18-v29. The replay
 * path fetches operands with vop_src (a 16B register move from the cached
 * copy, or the old LDR Q under A64_JIT_NOVRA) and commits the replayed
 * result from v2 with vop_dst; the GPR-composed recipes (MOVI/FMOVI/
 * FMOVG) spill the named registers and run unchanged. All pool registers
 * are caller-saved, so helper-calling slow paths store the dirty set and
 * reload every mapped register (slow_store_dirty / slow_reload_clobbered
 * carry both files). */
#define VXPOOL_LO 18
#define VXPOOL_HI 29

static int vra_enabled(void) {
    static int v = -1;
    if (v < 0) v = getenv("A64_JIT_NOVRA") == NULL;
    return v;
}
static u32 enc_vmov16(unsigned vd, unsigned vn) {   /* mov vd.16b, vn.16b */
    return 0x4EA01C00u | (vn << 16) | (vn << 5) | vd;
}
static int vra_alloc(BE *be) {
    int best = -1;
    u32 oldest = ~0u;
    for (int h = VXPOOL_LO; h <= VXPOOL_HI; h++) {
        if (be->vh2v[h] == 32) return h;
        if (be->vlru[h] < oldest) { oldest = be->vlru[h]; best = h; }
    }
    unsigned v = be->vh2v[best];
    if (be->vdirty[v]) ei(be->e, enc_stq((unsigned)best, 28,
                                         (unsigned)OFF_V(v)));
    be->vv2h[v] = -1;
    be->vdirty[v] = 0;
    be->vh2v[best] = 32;
    return best;
}
static int vra_use(BE *be, unsigned vn) {
    int h = be->vv2h[vn];
    if (h < 0) {
        h = vra_alloc(be);
        ei(be->e, enc_ldq((unsigned)h, 28, (unsigned)OFF_V(vn)));
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
static void vra_flush(BE *be, unsigned vn) {     /* memory current, keep */
    if (be->vv2h[vn] >= 0 && be->vdirty[vn]) {
        ei(be->e, enc_stq((unsigned)be->vv2h[vn], 28, (unsigned)OFF_V(vn)));
        be->vdirty[vn] = 0;
    }
}
static void vra_spill(BE *be, unsigned vn) {     /* memory current, unmap */
    int h = be->vv2h[vn];
    if (h < 0) return;
    if (be->vdirty[vn]) ei(be->e, enc_stq((unsigned)h, 28,
                                          (unsigned)OFF_V(vn)));
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
        if (be->vv2h[v] >= 0 && be->vdirty[v])
            ei(be->e, enc_stq((unsigned)be->vv2h[v], 28,
                              (unsigned)OFF_V(v)));
}
static void vra_slow_reload_all(BE *be) {
    for (unsigned v = 0; v < 32; v++)
        if (be->vv2h[v] >= 0)
            ei(be->e, enc_ldq((unsigned)be->vv2h[v], 28,
                              (unsigned)OFF_V(v)));
}

/* Replay operand fetch: host v`scratch` = guest Vn. */
static void vop_src(BE *be, unsigned scratch, unsigned vn) {
    if (!vra_enabled()) {
        ei(be->e, enc_ldq(scratch, 28, (unsigned)OFF_V(vn)));
        return;
    }
    ei(be->e, enc_vmov16(scratch, (unsigned)vra_use(be, vn)));
}
/* Replay result commit: guest Vd = host v`scratch` (the replay always
 * produces the full architectural Vd there). */
static void vop_dst(BE *be, unsigned scratch, unsigned vn) {
    if (!vra_enabled()) {
        ei(be->e, enc_stq(scratch, 28, (unsigned)OFF_V(vn)));
        return;
    }
    ei(be->e, enc_vmov16((unsigned)vra_def(be, vn), scratch));
}

/* NaN-result fallback for the self-counting scalar-FP classes (VC_F2 arith,
 * VC_F3): a NaN result means NaN inputs or an invalid operation — cases
 * where the result bits depend on the compiler's operand ordering in the
 * interpreter — so discard and re-run the insn via jit_exec1 (which counts
 * the insn and handles events). Mirrors emit_atomic's slow path. */
/* res >= 0: the slow arm converges with the interpreter's committed
 * c->v[rd] reloaded into host v`res`, so a post-merge vop_dst commits the
 * same value on both paths. */
static void vop_slowpath(BE *be, const IROp *o, u8 *slow, int res) {
    Emit *e = be->e;
    u8 *done = b_fwd(e);
    fwd_here(e, slow);
    slow_store_dirty(be);
    ei(e, enc_mov(1, 0, 28));                    /* jit_exec1(c, pc, insn) */
    emit_imm64(e, 1, o->imm2pc);
    ei(e, enc_movz(0, 2, (u32)o->imm & 0xffff, 0));
    ei(e, enc_movk(0, 2, ((u32)o->imm >> 16) & 0xffff, 1));
    ei(e, enc_ldr(3, 16, 27, (unsigned)offsetof(JitEnv, helper_exec1)));
    ei(e, enc_blr(16));
    u8 *ok = cbz_fwd(e, 0, 0);
    exit_plain(be, o->icnt);
    fwd_here(e, ok);
    slow_reload_clobbered(be);
    if (res >= 0)
        ei(e, enc_ldq((unsigned)res, 28, (unsigned)OFF_V((u32)o->imm & 31)));
    fwd_here(e, done);
}

static void emit_vop(BE *be, const IROp *o) {
    Emit *e = be->e;
    u32 insn = (u32)o->imm;
    unsigned rd = insn & 31, rn = (insn >> 5) & 31, rm = (insn >> 16) & 31;
    unsigned vclass = VC(o->aux);

    /* the GPR-composed recipes below read/write c->v[] directly */
    if (vclass == VC_MOVI) vra_spill(be, VMOVI_RD(o->aux));
    else if (vclass == VC_FMOVI) vra_spill(be, (o->aux >> 8) & 31);
    else if (vclass == VC_FMOVG) { vra_spill(be, rn); vra_spill(be, rd); }

    switch (vclass) {
        case VC_MOVI: {                          /* pre-expanded pattern */
            unsigned vd = VMOVI_RD(o->aux), q = VMOVI_Q(o->aux);
            unsigned kind = VMOVI_KIND(o->aux);
            emit_imm64(e, 16, o->imm);
            if (kind == 0) {                     /* plain write */
                ei(e, enc_str(3, 16, 28, (unsigned)OFF_V(vd)));
                if (q) ei(e, enc_str(3, 16, 28, (unsigned)OFF_V(vd) + 8));
                else { ei(e, enc_movz(1, 17, 0, 0));
                       ei(e, enc_str(3, 17, 28, (unsigned)OFF_V(vd) + 8)); }
            } else {                             /* ORR (1) / BIC (2) */
                ei(e, enc_ldr(3, 17, 28, (unsigned)OFF_V(vd)));
                ei(e, kind == 2 ? enc_bic(17, 17, 16) : enc_orr(1, 17, 17, 16));
                ei(e, enc_str(3, 17, 28, (unsigned)OFF_V(vd)));
                if (q) {
                    ei(e, enc_ldr(3, 17, 28, (unsigned)OFF_V(vd) + 8));
                    ei(e, kind == 2 ? enc_bic(17, 17, 16)
                                    : enc_orr(1, 17, 17, 16));
                    ei(e, enc_str(3, 17, 28, (unsigned)OFF_V(vd) + 8));
                } else {
                    ei(e, enc_movz(1, 17, 0, 0));
                    ei(e, enc_str(3, 17, 28, (unsigned)OFF_V(vd) + 8));
                }
            }
            break;
        }
        case VC_FMOVI: {                         /* scalar FMOV #imm */
            unsigned vd = (o->aux >> 8) & 31;
            emit_imm64(e, 16, o->imm);
            ei(e, enc_str(3, 16, 28, (unsigned)OFF_V(vd)));
            ei(e, enc_movz(1, 17, 0, 0));
            ei(e, enc_str(3, 17, 28, (unsigned)OFF_V(vd) + 8));
            break;
        }
        case VC_FMOVG: {                         /* gpr <-> fpr bit moves */
            unsigned sf = insn >> 31;
            unsigned opcode = (insn >> 16) & 7;
            int top = (sf == 1 && ((insn >> 22) & 3) == 2 &&
                       ((insn >> 19) & 3) == 1);
            if (opcode == 6) {                   /* to gpr */
                if (o->dst == VREG_ZERO) break;
                if (top)      ei(e, enc_ldr(3, 16, 28, (unsigned)OFF_V(rn) + 8));
                else if (sf)  ei(e, enc_ldr(3, 16, 28, (unsigned)OFF_V(rn)));
                else          ei(e, enc_ldr(2, 16, 28, (unsigned)OFF_V(rn)));
                int hd = ra_def(be, o->dst);
                ei(e, enc_mov(1, (unsigned)hd, 16));
            } else {                             /* from gpr */
                int hsrc = ra_use(be, o->a);
                if (top) {
                    ei(e, enc_str(3, (unsigned)hsrc, 28, (unsigned)OFF_V(rd) + 8));
                } else {
                    if (sf) ei(e, enc_str(3, (unsigned)hsrc, 28, (unsigned)OFF_V(rd)));
                    else {
                        ei(e, enc_mov(0, 16, (unsigned)hsrc));   /* zext32 */
                        ei(e, enc_str(3, 16, 28, (unsigned)OFF_V(rd)));
                    }
                    ei(e, enc_movz(1, 16, 0, 0));
                    ei(e, enc_str(3, 16, 28, (unsigned)OFF_V(rd) + 8));
                }
            }
            break;
        }
        case VC_VF3S: {
            /* Vector FP three-same arithmetic, self-counting: replay onto
             * v0/v1 (FMLA/FMLS accumulate into a preloaded v2), then check
             * the result lanes for NaN — same rationale as VC_F2/F3: a NaN
             * result exposes the interpreter's compiler-chosen NaN operand
             * priority, so re-run those in the interpreter. */
            unsigned Q = (insn >> 30) & 1, sz = (insn >> 22) & 1;
            /* FMLA/FMLS (opc3 0x19) do not currently reach here — the
             * frontend leaves them on the helper for the x86 backend's sake,
             * whose only option is an unfused mul+add. Native replay makes
             * them correct on this host, so the accumulate path is kept
             * ready rather than deleted. */
            int mla = (((insn >> 11) & 0x1f) == 0x19);
            materialize_flags(be);               /* cmn below */
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            if (mla) vop_src(be, 2, rd);
            ei(e, (insn & ~((0x1Fu << 5) | (0x1Fu << 16) | 0x1Fu)) |
                  (1u << 16) | (0u << 5) | 2);
            /* v16 = per-lane (v2 == v2): NaN lanes -> 0 */
            ei(e, 0x0E20E400u | ((u32)Q << 30) | ((u32)sz << 22) |
                  (2u << 16) | (2u << 5) | 16);
            ei(e, 0x9E660000u | (16u << 5) | 16);     /* fmov x16, d16 */
            if (Q) {
                ei(e, 0x9EAE0000u | (16u << 5) | 17); /* fmov x17, v16.d[1] */
                ei(e, 0x8A110210u);                   /* and x16, x16, x17 */
            }
            ei(e, 0xB100041Fu | (16u << 5));          /* cmn x16, #1 */
            u8 *slow = bcond_fwd(e, 1);               /* b.ne: NaN lane */
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        case VC_F2: case VC_F3: {
            /* Scalar FP arithmetic, self-counting. The interpreter computes
             * these as C expressions whose both-NaN operand priority (and,
             * for the FMA family, gcc's CSE of n*m across the four forms —
             * which defeats -ffp-contract) is a codegen artifact, so:
             * compute UNFUSED in any order and NaN-gate the result; a NaN
             * re-runs the insn in the interpreter (vop_slowpath). */
            unsigned ft = (insn >> 22) & 1;      /* 0 = S, 1 = D */
            u32 f = ft << 22;
            materialize_flags(be);               /* fcmp below */
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            if (vclass == VC_F3) {
                unsigned ra = (insn >> 10) & 31;
                int o1 = (insn >> 21) & 1, o0 = (insn >> 15) & 1;
                vop_src(be, 3, ra);
                ei(e, 0x1E200800u | f | (1u << 16) | (0u << 5) | 2);  /* fmul */
                if (o1)                                   /* fneg a */
                    ei(e, 0x1E214000u | f | (3u << 5) | 3);
                /* v2 = a +- n*m (fadd/fsub v2, v3, v2) */
                ei(e, (o0 == o1 ? 0x1E202800u : 0x1E203800u) | f |
                      (2u << 16) | (3u << 5) | 2);
            } else {
                /* replay the 2-source op itself on v0/v1 -> v2 */
                u32 w2 = (insn & ~((0x1Fu << 5) | (0x1Fu << 16) | 0x1Fu)) |
                         (1u << 16) | (0u << 5) | 2;
                ei(e, w2);
            }
            ei(e, 0x1E202008u | f | (2u << 16) | (2u << 5));  /* fcmp v2,v2 */
            u8 *slow = bcond_fwd(e, 6);          /* b.vs: NaN result */
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        case VC_FCVTH: {
            /* FP16 precision converts (scalar FCVT h<->s/d, vector FCVTL/
             * FCVTN); self-counting, NaN-gated. The interpreter's portable
             * narrow routine canonicalizes NaN payloads where native fcvt
             * preserves them, so a NaN operand re-runs in the interpreter:
             * check the single/double side (result for widen, source for
             * narrow), which is what a bare fcmp/fcmeq can see. */
            int scalar = (insn >> 28) & 1;
            u8 *slow;
            materialize_flags(be);                       /* fcmp/cmn clobber NZCV */
            vop_src(be, 0, rn);                          /* v0 = Vn */
            /* renumber the guest fcvt: Rn -> v0, Rd -> v2 (imm/opcode fields,
             * incl. the two-misc Rm slot, stay put) */
            u32 w = (insn & ~((0x1Fu << 5) | 0x1Fu)) | (0u << 5) | 2;
            if (scalar) {
                unsigned ftype = (insn >> 22) & 3, opc = (insn >> 15) & 0x3f;
                int widen = (opc == 0x4 || opc == 0x5);
                ei(e, w);                                /* v2 = fcvt result */
                unsigned creg = widen ? 2u : 0u;
                unsigned cft  = widen ? (opc == 0x5 ? 1u : 0u) : (ftype & 1u);
                ei(e, 0x1E202008u | (cft << 22) | (creg << 5));  /* fcmp reg,#0 */
                slow = bcond_fwd(e, 6);                  /* b.vs: NaN */
            } else {
                unsigned Q = (insn >> 30) & 1, opc = (insn >> 12) & 0x1f;
                int widen = (opc == 0x17);               /* FCVTL(2) */
                if (!widen && Q) vop_src(be, 2, rd);     /* FCVTN2 keeps low 64 */
                ei(e, w);                                /* v2 = fcvtl/fcvtn */
                unsigned creg = widen ? 2u : 0u;         /* both are .4s (128b) */
                /* fcmeq v16.4s, creg, creg : NaN lanes -> 0, then AND both
                 * 64-bit halves and test against all-ones. */
                ei(e, 0x0E20E400u | (1u << 30) | (creg << 16) | (creg << 5) | 16);
                ei(e, 0x9E660000u | (16u << 5) | 16);    /* fmov x16, d16 */
                ei(e, 0x9EAE0000u | (16u << 5) | 17);    /* fmov x17, v16.d[1] */
                ei(e, 0x8A110210u);                      /* and x16, x16, x17 */
                ei(e, 0xB100041Fu | (16u << 5));         /* cmn x16, #1 */
                slow = bcond_fwd(e, 1);                  /* b.ne: NaN lane */
            }
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        case VC_H1: {   /* scalar half 1-source (self-counting). FMOV is a bit
                         * copy (native fmov h matches, no gate); FABS/FNEG/
                         * FSQRT replay native + NaN gate (interp canonicalizes). */
            unsigned opc = (insn >> 15) & 0x3f;
            vop_src(be, 0, rn);                          /* v0 = Vn */
            u32 w = (insn & ~((0x1Fu << 5) | 0x1Fu)) | (0u << 5) | 2;
            if (opc == 0x0) {                            /* FMOV: no gate */
                ei(e, w);                                /* fmov h2, h0 */
                icount_add(be, 1);
                vop_dst(be, 2, rd);
                break;
            }
            materialize_flags(be);
            ei(e, w);                                    /* fabs/fneg/fsqrt h2,h0 */
            ei(e, 0x1EE02008u | (2u << 5));              /* fcmp h2, #0 : NaN? */
            u8 *slow = bcond_fwd(e, 6);                  /* b.vs */
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        case VC_H2: {   /* scalar half 2-source arith: replay native + NaN gate
                         * (single ops, so native half == the interpreter's
                         * double). FMAX/FMIN(NM) declined by be_vop_ok. */
            materialize_flags(be);
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            u32 w = (insn & ~((0x1Fu << 5) | (0x1Fu << 16) | 0x1Fu)) |
                    (1u << 16) | (0u << 5) | 2;
            ei(e, w);                                    /* fadd/.../fnmul h2,h0,h1 */
            ei(e, 0x1EE02008u | (2u << 5));              /* fcmp h2, #0 : NaN? */
            u8 *slow = bcond_fwd(e, 6);
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        case VC_H3: {   /* half FMADD family. The interpreter computes in double
                         * and narrows once via f64_to_f16 -- a native half FMA
                         * would differ (a tiny addend below double's ULP), so
                         * mirror it: widen exact to double, double FMA, fcvt
                         * h,d (single narrow). NaN-gated. */
            unsigned ra = (insn >> 10) & 31;
            int o1 = (insn >> 21) & 1, o0 = (insn >> 15) & 1;
            materialize_flags(be);
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            vop_src(be, 3, ra);
            ei(e, 0x1EE2C000u | (0u << 5) | 0);          /* fcvt d0, h0 */
            ei(e, 0x1EE2C000u | (1u << 5) | 1);          /* fcvt d1, h1 */
            ei(e, 0x1EE2C000u | (3u << 5) | 3);          /* fcvt d3, h3 */
            ei(e, 0x1F400000u | ((u32)o1 << 21) | (1u << 16) |
                  ((u32)o0 << 15) | (3u << 10) | (0u << 5) | 2);  /* fmadd d2 */
            ei(e, 0x1E602008u | (2u << 5));              /* fcmp d2, #0 : NaN? */
            u8 *slow = bcond_fwd(e, 6);
            ei(e, 0x1E63C000u | (2u << 5) | 2);          /* fcvt h2, d2 */
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        case VC_VH3: case VC_VHMULX: {  /* vector half three-same arith / FMULX:
                          * replay native + NaN gate. Single ops (and FMULX's
                          * 0*inf->2 special case) match the interpreter. */
            unsigned Q = (insn >> 30) & 1;
            materialize_flags(be);
            vop_src(be, 0, rn);
            vop_src(be, 1, rm);
            u32 w = (insn & ~((0x1Fu << 5) | (0x1Fu << 16) | 0x1Fu)) |
                    (1u << 16) | (0u << 5) | 2;
            ei(e, w);                                    /* v2 = fadd/.../fmulx */
            ei(e, 0x0E402400u | ((u32)Q << 30) | (2u << 16) | (2u << 5) | 16);
            ei(e, 0x9E660000u | (16u << 5) | 16);        /* fmov x16, d16 */
            if (Q) { ei(e, 0x9EAE0000u | (16u << 5) | 17); ei(e, 0x8A110210u); }
            ei(e, 0xB100041Fu | (16u << 5));             /* cmn x16, #1 */
            u8 *slow = bcond_fwd(e, 1);                  /* b.ne: NaN lane */
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        case VC_VH2M: {   /* vector half two-reg misc: FABS/FNEG/FSQRT (replay
                           * + NaN gate) or FCMxx#0 (replay, mask, no gate). */
            unsigned Q = (insn >> 30) & 1;
            unsigned key = (((insn >> 29) & 1) << 6) | (((insn >> 23) & 1) << 5) |
                           ((insn >> 12) & 0x1f);
            int is_cmp = (key == 0x2c || key == 0x6c || key == 0x2d ||
                          key == 0x6d || key == 0x2e);
            vop_src(be, 0, rn);
            u32 w = (insn & ~((0x1Fu << 5) | 0x1Fu)) | (0u << 5) | 2;
            if (is_cmp) {                                /* FCMxx#0: no gate */
                ei(e, w);                                /* v2 = fcmxx v0,#0 */
                icount_add(be, 1);
                vop_dst(be, 2, rd);
                break;
            }
            materialize_flags(be);
            ei(e, w);                                    /* v2 = fabs/fneg/fsqrt */
            ei(e, 0x0E402400u | ((u32)Q << 30) | (2u << 16) | (2u << 5) | 16);
            ei(e, 0x9E660000u | (16u << 5) | 16);
            if (Q) { ei(e, 0x9EAE0000u | (16u << 5) | 17); ei(e, 0x8A110210u); }
            ei(e, 0xB100041Fu | (16u << 5));
            u8 *slow = bcond_fwd(e, 1);
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        case VC_VHEST: {  /* vector half FRECPE/FRSQRTE: replay native estimate
                           * + result NaN gate (the interpreter returns a
                           * canonical NaN for NaN/negative inputs; finite
                           * estimates are the architected table). */
            unsigned Q = (insn >> 30) & 1;
            materialize_flags(be);
            vop_src(be, 0, rn);
            u32 w = (insn & ~((0x1Fu << 5) | 0x1Fu)) | (0u << 5) | 2;
            ei(e, w);                                    /* v2 = frecpe/frsqrte v0 */
            ei(e, 0x0E402400u | ((u32)Q << 30) | (2u << 16) | (2u << 5) | 16);
            ei(e, 0x9E660000u | (16u << 5) | 16);        /* fmov x16, d16 */
            if (Q) { ei(e, 0x9EAE0000u | (16u << 5) | 17); ei(e, 0x8A110210u); }
            ei(e, 0xB100041Fu | (16u << 5));             /* cmn x16, #1 */
            u8 *slow = bcond_fwd(e, 1);
            icount_add(be, 1);
            vop_slowpath(be, o, slow, 2);
            vop_dst(be, 2, rd);
            break;
        }
        default: {
            /* Renumber-and-replay. Vector sources -> v0 (Rn), v1 (Rm);
             * Vd preloaded into the result reg v2 for the read-modify
             * forms (BSL/BIT/BIF, INS). GPR-linked forms use x16. */
            unsigned opc3 = (insn >> 11) & 0x1f;
            int has_rm = (vclass == VC_BITW || vclass == VC_ADDSUB ||
                          vclass == VC_CM3 || vclass == VC_MINMAX ||
                          vclass == VC_MUL3 || vclass == VC_PAIRI ||
                          vclass == VC_VFCM || vclass == VC_VHCM ||
                          vclass == VC_S3S ||
                          vclass == VC_FCSEL || vclass == VC_FCCMP ||
                          (vclass == VC_FCMP && !((insn >> 3) & 1)));
            int reads_rd = (vclass == VC_BITW && ((insn >> 29) & 1) &&
                            ((insn >> 22) & 3) != 0)     /* BSL/BIT/BIF */
                        || (vclass == VC_COPY && ((insn >> 29) & 1))   /* INS(elem) */
                        || (vclass == VC_COPY && ((insn >> 11) & 0xf) == 3
                            && !((insn >> 29) & 1))      /* INS(general) */
                        || (vclass == VC_2MISC && ((insn >> 12) & 0x1f) == 0x12
                            && ((insn >> 30) & 1))       /* XTN2 keeps low */
                        || (vclass == VC_SHIFTI && opc3 == 0x10
                            && ((insn >> 30) & 1))       /* SHRN2 keeps low */
                        || ((vclass == VC_SHIFTI || vclass == VC_SSHIFTI)
                            && opc3 == 0x02);            /* S/USRA accumulate */
            int gpr_src = (vclass == VC_CVTIF) ||
                          (vclass == VC_COPY &&
                           !((insn >> 29) & 1) &&
                           (((insn >> 11) & 0xf) == 1 ||   /* DUP (general) */
                            ((insn >> 11) & 0xf) == 3));   /* INS (general) */
            int gpr_dst = (vclass == VC_CVTFI) ||
                          (vclass == VC_COPY &&
                           !((insn >> 29) & 1) &&
                           (((insn >> 11) & 0xf) == 5 ||   /* SMOV */
                            ((insn >> 11) & 0xf) == 7));   /* UMOV */
            (void)opc3;

            if (vclass == VC_FCSEL) flags_to_host(be);
            if (vclass == VC_FCCMP) flags_to_host(be);   /* reads + writes */
            if (vclass == VC_FCMP) materialize_flags(be);   /* fcmp clobbers */
            u32 w = insn & ~0x1Fu;               /* clear Rd */
            if (gpr_dst) {
                if (o->dst == VREG_ZERO) break;
                vop_src(be, 0, rn);
                w = (w & ~(0x1Fu << 5)) | (0u << 5) | 16;    /* Rn=v0, Rd=x16 */
                ei(e, w);
                int hd = ra_def(be, o->dst);
                ei(e, enc_mov(1, (unsigned)hd, 16));
                break;
            }
            if (gpr_src) {
                int hsrc = ra_use(be, o->a);
                ei(e, enc_mov(1, 16, (unsigned)hsrc));
                w = (w & ~(0x1Fu << 5)) | (16u << 5) | 2;    /* Rn=x16, Rd=v2 */
                if (reads_rd)                    /* INS (general) */
                    vop_src(be, 2, rd);
                ei(e, w);
                vop_dst(be, 2, rd);
                break;
            }
            /* vector-only (or FCMP, which writes NZCV instead of Vd) */
            vop_src(be, 0, rn);
            if (has_rm) vop_src(be, 1, rm);
            if (reads_rd) vop_src(be, 2, rd);
            w = (w & ~((0x1Fu << 5) | (0x1Fu << 16))) | (0u << 5) | 2;
            if (has_rm) w |= 1u << 16;
            else        w |= (insn & (0x1Fu << 16));   /* keep imm fields */
            if (vclass == VC_SHIFTI || vclass == VC_SSHIFTI)
                /* bits 22:16 are immh:immb */
                w = (insn & ~((0x1Fu << 5) | 0x1Fu)) | (0u << 5) | 2;
            if (vclass == VC_FCMP || vclass == VC_FCCMP) {
                w = (insn & ~((0x1Fu << 5) | (0x1Fu << 16))) | (0u << 5);
                if (vclass == VC_FCCMP || !((insn >> 3) & 1))
                    w |= 1u << 16;               /* Rm=v1 */
                ei(e, w);                        /* host NZCV = result */
                ei(e, 0xD53B4200u | 16);         /* mrs x16, nzcv */
                ei(e, enc_str(2, 16, 28, (unsigned)OFF_NZCV));
                be->fl = FL_MEM;
                break;
            }
            ei(e, w);
            vop_dst(be, 2, rd);
            break;
        }
    }
}

/* ---- inline atomics (IRO_ATOMIC; decode.c ldst_exclusive/ldst_atomic are
 * the reference) ---- */

static void cbnz_to(Emit *e, int w, unsigned rt, const u8 *target) {
    s64 off = target - e->rx;
    ei(e, ((u32)w << 31) | 0x35000000u |
          ((((u32)(off >> 2)) & 0x7FFFFu) << 5) | rt);
}
/* exclusives/ordered encodings, size-suffixed, [Xn] addressing */
static u32 enc_ldaxr(unsigned szl, unsigned rt, unsigned rn) {
    return ((u32)szl << 30) | 0x085FFC00u | (rn << 5) | rt;
}
static u32 enc_stlxr(unsigned szl, unsigned rs, unsigned rt, unsigned rn) {
    return ((u32)szl << 30) | 0x0800FC00u | (rs << 16) | (rn << 5) | rt;
}
static u32 enc_ldar(unsigned szl, unsigned rt, unsigned rn) {
    return ((u32)szl << 30) | 0x08DFFC00u | (rn << 5) | rt;
}
static u32 enc_stlr(unsigned szl, unsigned rt, unsigned rn) {
    return ((u32)szl << 30) | 0x089FFC00u | (rn << 5) | rt;
}
static u32 enc_eor(unsigned rd, unsigned rn, unsigned rm) {   /* 64-bit */
    return 0xCA000000u | (rm << 16) | (rn << 5) | rd;
}
static u32 enc_ldrb_off(unsigned rt, unsigned rn, unsigned off) {
    return 0x39400000u | (off << 10) | (rn << 5) | rt;
}
static u32 enc_strb_off(unsigned rt, unsigned rn, unsigned off) {
    return 0x39000000u | (off << 10) | (rn << 5) | rt;
}

#define OFF_EXCL_VALID ((unsigned)offsetof(CPU, excl_valid))
#define OFF_EXCL_ADDR  ((unsigned)offsetof(CPU, excl_addr))
#define OFF_EXCL_SIZE  ((unsigned)offsetof(CPU, excl_size))
#define OFF_EXCL_VAL   ((unsigned)offsetof(CPU, excl_val))

/* One IRO_ATOMIC (mirrors backend_x86_64.c). Fast path: align gate + probe
 * + ldaxr/stlxr sequence; result converges in x16. Slow path re-runs the
 * insn via jit_exec1 (self-counting; the fast path bumps icount inline). */
static void emit_atomic(BE *be, const IRBlock *ir, int i) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    unsigned kind = AT_KIND(o->aux), szl = AT_SZL(o->aux);
    unsigned sz = 1u << szl;
    int is_load_kind = (kind == AT_LDX || kind == AT_LDAR);
    int need = is_load_kind ? 1 : 2;
    int uses_b = !(kind == AT_LDX || kind == AT_LDAR);

    materialize_flags(be);
    int hb = uses_b ? ra_use(be, o->b) : -1;
    int hs = (kind == AT_CAS) ? ra_use(be, o->cc) : -1;
    int ha = ra_use(be, o->a);
    ei(e, enc_mov(1, 1, (unsigned)ha));           /* x1 = va */

    u8 *slow0 = NULL, *slow1 = NULL, *slow2 = NULL, *slow3 = NULL;
    if (UNLIKELY(be->env->slowmem)) {
        slow0 = b_fwd(e);
    } else {
        if (sz > 1) {                             /* alignment gate */
            ei(e, enc_andi64(16, 1, 0, szl - 1)); /* and x16, x1, #sz-1 */
            slow1 = cbnz_fwd(e, 1, 16);
        }
        ei(e, enc_ubfm(1, 16, 1, 12, 63));        /* page (aligned: no cross) */
        ei(e, enc_ubfm(1, 17, 1, 8, 63));
        ei(e, enc_andi64(17, 17, (64 - 4) & 63,
                         (unsigned)__builtin_ctz(A64_DTLB_ENTRIES) - 1));
        ei(e, enc_ldr(3, 2, 27, (unsigned)offsetof(JitEnv, dtlb)));
        ei(e, enc_addr(17, 2, 17));
        ei(e, enc_ldr(3, 2, 17, 0));
        ei(e, enc_cmp(2, 16));
        slow2 = bcond_fwd(e, 1);                  /* b.ne slow */
        ei(e, enc_ldr(3, 2, 17, 8));
        slow3 = tbz_fwd(e, 2, need == 2 ? 1 : 0);
        ei(e, enc_andi64(2, 2, 61, 60));          /* host base */
        ei(e, enc_andi64(16, 1, 0, 11));          /* page offset */
        ei(e, enc_addr(17, 2, 16));               /* x17 = host ptr */
    }

    u32 fix_fast = cache_off(be);
    icount_add(be, 1);                            /* retires from here (x16) */

    switch (kind) {
        case AT_LDX:
            ei(e, enc_ldst0(szl, 1, 16, 17));     /* zero-extended load */
            ei(e, enc_str(3, 1, 28, OFF_EXCL_ADDR));
            ei(e, enc_movz(1, 2, sz, 0));
            ei(e, enc_str(3, 2, 28, OFF_EXCL_SIZE));
            ei(e, enc_str(3, 16, 28, OFF_EXCL_VAL));
            ei(e, enc_movz(0, 2, 1, 0));
            ei(e, enc_strb_off(2, 28, OFF_EXCL_VALID));
            if (AT_ACQ(o->aux)) ei(e, 0xD50339BFu);   /* dmb ishld */
            break;
        case AT_STX: {
            ei(e, enc_ldrb_off(16, 28, OFF_EXCL_VALID));
            u8 *f1 = cbz_fwd(e, 0, 16);
            ei(e, enc_ldr(3, 16, 28, OFF_EXCL_ADDR));
            ei(e, enc_eor(16, 16, 1));
            u8 *f2 = cbnz_fwd(e, 1, 16);
            ei(e, enc_ldr(3, 16, 28, OFF_EXCL_SIZE));
            ei(e, 0xF100001Fu | ((u32)sz << 10) | (16u << 5));  /* cmp x16,#sz */
            u8 *f3 = bcond_fwd(e, 1);             /* b.ne fail */
            ei(e, enc_ldr(3, 2, 28, OFF_EXCL_VAL));   /* expected */
            const u8 *loop = e->rx;
            ei(e, enc_ldaxr(szl, 16, 17));
            ei(e, enc_cmp(16, 2));
            u8 *f4 = bcond_fwd(e, 1);             /* memory changed: fail */
            ei(e, enc_stlxr(szl, 16, (unsigned)hb, 17));
            cbnz_to(e, 0, 16, loop);
            ei(e, enc_movz(1, 16, 0, 0));         /* success: status 0 */
            u8 *join = b_fwd(e);
            fwd_here(e, f1); fwd_here(e, f2); fwd_here(e, f3); fwd_here(e, f4);
            ei(e, enc_movz(1, 16, 1, 0));         /* status 1 */
            fwd_here(e, join);
            ei(e, enc_strb_off(31, 28, OFF_EXCL_VALID));   /* strb wzr */
            break;
        }
        case AT_LDAR:
            ei(e, enc_ldar(szl, 16, 17));
            break;
        case AT_STLR:
            ei(e, enc_stlr(szl, (unsigned)hb, 17));
            break;
        case AT_SWP: {
            const u8 *loop = e->rx;
            ei(e, enc_ldaxr(szl, 16, 17));
            ei(e, enc_stlxr(szl, 2, (unsigned)hb, 17));
            cbnz_to(e, 0, 2, loop);
            break;
        }
        case AT_LDADD: case AT_LDCLR: case AT_LDEOR: case AT_LDSET: {
            const u8 *loop = e->rx;
            ei(e, enc_ldaxr(szl, 16, 17));
            switch (kind) {
                case AT_LDADD: ei(e, enc_addr(2, 16, (unsigned)hb)); break;
                case AT_LDCLR: ei(e, enc_bic(2, 16, (unsigned)hb)); break;
                case AT_LDEOR: ei(e, enc_eor(2, 16, (unsigned)hb)); break;
                default:       ei(e, enc_orr(1, 2, 16, (unsigned)hb)); break;
            }
            ei(e, enc_stlxr(szl, 1, 2, 17));      /* status in w1 (va dead) */
            cbnz_to(e, 0, 1, loop);
            break;
        }
        case AT_LDSMAX: case AT_LDSMIN: case AT_LDUMAX: case AT_LDUMIN: {
            /* ldaxr/stlxr loop; new value = compare-select of old vs operand
             * at the access width/signedness (decode.c LSE_RMW cases 4-7).
             * Sub-word compares run on sign/zero-extended copies in x1/x2;
             * csel then picks between the raw registers (same low bytes). */
            int sgn = (kind == AT_LDSMAX || kind == AT_LDSMIN);
            int mx = (kind == AT_LDSMAX || kind == AT_LDUMAX);
            unsigned cond = sgn ? (mx ? 0xCu : 0xBu)       /* GT / LT */
                                : (mx ? 0x8u : 0x3u);      /* HI / LO */
            const u8 *loop = e->rx;
            ei(e, enc_ldaxr(szl, 16, 17));        /* x16 = old (zext) */
            unsigned co = 16, cb = (unsigned)hb;
            if (szl < 3) {
                if (sgn) {                        /* sxt{b,h,w} x2/x1 */
                    u32 imms = (8u << szl) - 1;
                    ei(e, 0x93400000u | (imms << 10) | (16u << 5) | 2);
                    ei(e, 0x93400000u | (imms << 10) | ((u32)hb << 5) | 1);
                    co = 2; cb = 1;
                } else {                          /* truncate the operand */
                    ei(e, enc_andi64(1, (unsigned)hb, 0, sz * 8 - 1));
                    cb = 1;
                }
            }
            ei(e, enc_cmp(co, cb));
            ei(e, 0x9A800000u | ((u32)hb << 16) | (cond << 12) |   /* csel */
                  (16u << 5) | 2);                /* x2 = old wins ? x16 : hb */
            ei(e, enc_stlxr(szl, 1, 2, 17));
            cbnz_to(e, 0, 1, loop);
            break;
        }
        case AT_CAS: {
            unsigned hexp = (unsigned)hs;
            if (szl < 3) {                        /* compare truncated */
                ei(e, enc_andi64(2, (unsigned)hs, 0, sz * 8 - 1));
                hexp = 2;
            }
            const u8 *loop = e->rx;
            ei(e, enc_ldaxr(szl, 16, 17));
            ei(e, enc_cmp(16, hexp));
            u8 *out = bcond_fwd(e, 1);            /* b.ne: no store */
            ei(e, enc_stlxr(szl, 1, (unsigned)hb, 17));
            cbnz_to(e, 0, 1, loop);
            fwd_here(e, out);
            break;
        }
    }
    u8 *done = b_fwd(e);

    /* ---- slow path: re-run the insn in the interpreter ---- */
    fwd_here(e, slow0);
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    fwd_here(e, slow3);
    be_fixup_add(be->env, fix_fast, cache_off(be));
    slow_store_dirty(be);
    ei(e, enc_mov(1, 0, 28));                     /* jit_exec1(c, pc, insn) */
    emit_imm64(e, 1, o->imm2pc);
    ei(e, enc_movz(0, 2, (u32)o->imm & 0xffff, 0));
    ei(e, enc_movk(0, 2, ((u32)o->imm >> 16) & 0xffff, 1));
    ei(e, enc_ldr(3, 16, 27, (unsigned)offsetof(JitEnv, helper_exec1)));
    ei(e, enc_blr(16));
    u8 *ok = cbz_fwd(e, 0, 0);
    exit_plain(be, o->icnt);
    fwd_here(e, ok);
    slow_reload_clobbered(be);
    if (o->dst != VREG_ZERO)
        ld_home(be, 16, o->dst);
    fwd_here(e, done);

    if (o->dst != VREG_ZERO) {
        int hd = ra_def(be, o->dst);
        ei(e, enc_mov(1, (unsigned)hd, 16));
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
    for (int h = 0; h < 32; h++) be.vh2v[h] = 32;
    be.fl = FL_MEM;
    b->exit_pc[0] = b->exit_pc[1] = ~0ULL;
    b->exit_off[0] = b->exit_off[1] = 0;
    b->patched[0] = b->patched[1] = 0;
    b->in_head = ~0u;

    /* safepoint: hot entry is ldr+cbnz, the exit body sits after the
     * block's last op (cold). c->pc must be restored to the block's start
     * on that path: a direct chain jump into this block bypassed the
     * predecessor's exit-stub pc write, so c->pc is stale on entry. */
    ei(e, enc_ldr(2, 16, 27, (unsigned)offsetof(JitEnv, interrupt)));
    u8 *cold = cbnz_fwd(e, 0, 16);

    for (int i = 0; i < ir->n && !e->overflow; )
        i += emit_op(&be, ir, i);

    if (e->overflow) return -1;
    fwd_here(e, cold);
    emit_imm64(e, 16, b->pc);
    ei(e, enc_str(3, 16, 28, (unsigned)OFF_PC));
    exit_plain(&be, 0);
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
        case IRO_ADC: case IRO_ADCS: case IRO_SBC: case IRO_SBCS: {
            /* Native adc/sbc; guest C must be in host NZCV first. The non-S
             * (and flags-dead) forms leave host NZCV untouched, so the lazy
             * flag state is unaffected. */
            static const u32 base[4] = { 0x1A000000u, 0x3A000000u,
                                         0x5A000000u, 0x7A000000u };
            int S = (o->op == IRO_ADCS || o->op == IRO_SBCS) &&
                    !o->flags_dead;
            int sbc = (o->op == IRO_SBC || o->op == IRO_SBCS);
            if (o->flags_dead && o->dst == VREG_ZERO) break;   /* fully dead */
            flags_to_host(be);
            alu3(be, w, base[(sbc << 1) | S], o->dst, o->a, o->b);
            if (S) set_flags_state(be, ir, i);
            break;
        }
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
        case IRO_RBIT: {
            int ha = ra_use(be, o->a);
            int hd = ra_def(be, o->dst);
            ei(e, ((u32)w << 31) | 0x5AC00000u | ((u32)ha << 5) | (u32)hd);
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
            emit_vop(be, o);
            break;
        case IRO_CALL1:
            emit_call1(be, o);
            break;

        case IRO_CPULD: {                        /* dst = *(u64*)(CPU+imm) */
            int hd = ra_def(be, o->dst);
            ei(e, enc_ldr(3, (unsigned)hd, 28, (unsigned)o->imm));
            break;
        }
        case IRO_CPUST: {
            int ha = ra_use(be, o->a);
            ei(e, enc_str(3, (unsigned)ha, 28, (unsigned)o->imm));
            break;
        }
        case IRO_FENCE:
            ei(e, 0xD5033BBFu);                  /* dmb ish */
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
