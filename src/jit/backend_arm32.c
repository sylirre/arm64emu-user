/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* ARM32 (armv7-a, ARM state) code generator — the second ILP32 backend.
 *
 * The model is `backend_x86_32.c`'s: a guest 64-bit value does not fit a host
 * register, so the unit of allocation is a HALF — vreg v contributes HV(v,0)
 * (its low word) and HV(v,1) (its high word), each independently resident in a
 * host register, live only in its CPU-struct home, or *known zero* with a stale
 * home (what every 32-bit-wide guest write leaves behind, which is most of
 * them). Only destinations are allocated; a source is read wherever its value
 * already is. Read that file's header for why, and for the two hazards the model
 * creates (a destination that is also a source; allocator action inside a
 * conditional region).
 *
 * What is different here is all in the host's favour:
 *
 *   r10        = CPU*        pinned
 *   r11        = JitEnv*     pinned — ARM has no absolute addressing mode, so
 *                            unlike i686 this one has to live in a register
 *   r0-r3, r12 = scratch, never allocated (r0-r3 are also the AAPCS argument
 *                registers and the return pair)
 *   r4-r8      = allocatable pool. All five are callee-saved, so nothing needs
 *                reloading after a helper call — the i686 backend's
 *                reload_clobbered has no counterpart here.
 *   r9         = left alone (platform register under some ABIs)
 *   sp         = a fixed frame, never moved by generated code
 *
 * **Flags are nearly free.** `mrs Rd, APSR` yields N/Z/C/V *already in the
 * guest's own bit positions* (31..28), and `msr APSR_nzcvq, Rn` puts a word
 * back, so materializing `c->nzcv` is three instructions instead of i686's
 * seven, and a guest condition needs no derivation at all: the AArch64
 * condition encoding IS the ARM32 one, so the guest's 4-bit code goes straight
 * into the instruction (only NV, which ARM32 does not have, folds to AL). That
 * is the same trick `backend_a64.c` uses. Only a 64-bit Z needs work, because
 * the host's Z describes the high word alone.
 *
 * `adds`/`adc` and `subs`/`sbc` are the pair model expressed directly, `ubfx`
 * extracts the D-TLB index in one instruction, and conditional execution
 * (`cmpeq`, `orreq`, `ldreq`) removes the branches i686 needs for a 64-bit
 * compare or a CSEL.
 *
 * Not inlined here yet: memory accesses go through the same
 * jit_ld/jit_st/jit_ldv/jit_stv helpers the other backends fall back to (so
 * there are no bus-fault fixups to register — generated code never dereferences
 * guest memory itself), all FP/SIMD (be_vop_ok declines every class), and the
 * atomics, which re-run the whole instruction through jit_exec1. */
#include "ir.h"

#ifdef __arm__

#include <stdlib.h>
#include <string.h>

_Static_assert(A64_HOST_ILP32, "this backend is an ILP32 one");
/* Half indices assume a little-endian host: HV(v,0) is at the low address of
 * the guest register's home. */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "LE host assumed");

enum { R0 = 0, R1, R2, R3, R4, R5, R6, R7,
       R8, R9, R10, R11, R12, SP_, LR_, PC_, HREG_N };
#define RCPU R10
#define RENV R11

/* Allocatable pool. Every one is callee-saved, which is why a helper call needs
 * no reload afterwards. */
static const u8 pool[] = { R4, R5, R6, R7, R8 };
#define POOL_N ((int)sizeof pool)

/* ARM condition field values. The guest's 4-bit condition codes are these
 * same values, which is what makes cond_setup trivial. */
enum { CC_EQ = 0, CC_NE, CC_CS, CC_CC, CC_MI, CC_PL, CC_VS, CC_VC,
       CC_HI, CC_LS, CC_GE, CC_LT, CC_GT, CC_LE, CC_AL };
#define COND(c) ((u32)(c) << 28)
#define AL COND(CC_AL)

/* data-processing opcodes (bits 24..21) */
enum { OP_AND = 0, OP_EOR, OP_SUB, OP_RSB, OP_ADD, OP_ADC, OP_SBC, OP_RSC,
       OP_TST, OP_TEQ, OP_CMP, OP_CMN, OP_ORR, OP_MOV, OP_BIC, OP_MVN };
/* shift types (bits 6..5) */
enum { SH_LSL = 0, SH_LSR, SH_ASR, SH_ROR };

#define OFF_X(n)   ((s32)(offsetof(CPU, x) + 8 * (n)))
#define OFF_SP     ((s32)offsetof(CPU, sp_el))
#define OFF_PC     ((s32)offsetof(CPU, pc))
#define OFF_NZCV   ((s32)offsetof(CPU, nzcv))
#define OFF_ICOUNT ((s32)offsetof(CPU, icount))
#define OFF_V(n)   ((s32)(offsetof(CPU, v) + 16 * (n)))
/* Every CPU/JitEnv field generated code reaches uses an LDR/STR imm12. */
_Static_assert(OFF_ICOUNT + 4 < 4096 && OFF_V(31) + 12 < 4096,
               "CPU fields must stay in LDR imm12 reach");
_Static_assert(offsetof(JitEnv, jcache) + 8 < 4096,
               "the jump cache must stay in LDR imm12 reach of RENV");

/* ---- the fixed frame ----
 * Carved out once by the enter thunk; generated code never moves sp, so the
 * outgoing stack arguments live at [sp+k] with no push/pop, and AAPCS's 8-byte
 * alignment at a call holds by construction.
 *   [sp +  0 .. 23]  outgoing stack arguments (jit_st needs 20: val, pc, desc)
 *   [sp + 24 .. 55]  eight scratch words
 * 60 is 4 mod 8, which is exactly what turns the thunk's post-push sp (also
 * 4 mod 8, after nine registers) back into 0 mod 8. */
#define FR_ARG(n)  (4 * (n))
#define FR_S(n)    (24 + 4 * (n))
#define FR_SIZE    60
_Static_assert(FR_SIZE % 8 == 4, "frame size must realign sp at a call");
_Static_assert(FR_S(7) + 4 <= FR_SIZE, "frame too small");

typedef struct BE {
    Emit *e;
    JitEnv *env;
    JBlock *b;
#define NHV (2 * VREG_N)
#define HV(v, hi) (2 * (v) + (hi))
    s8  h[NHV];                 /* host register holding this half, or -1 */
    u8  zero[NHV];              /* 1 = value is 0 and the home is stale */
    u8  dirty[NHV];             /* h >= 0 and the home is stale */
    u8  r2v[HREG_N];            /* half in this host register, or NHV */
    u8  locked[HREG_N];         /* in use by the op being emitted */
    u32 lru[HREG_N];
    u32 stamp;
} BE;

/* ---- raw emission ---- */

static void ei(Emit *e, u32 insn) {             /* one A32 instruction */
    if (UNLIKELY(e->rw + 4 > e->rw_end)) { e->overflow = 1; return; }
    memcpy(e->rw, &insn, 4);
    e->rw += 4; e->rx += 4;
}

/* ARM data-processing immediates are an 8-bit value rotated right by an even
 * amount. Returns the 12-bit operand2 field, or -1 if the constant needs
 * movw/movt instead. */
static int dp_imm(u32 v) {
    for (int rot = 0; rot < 16; rot++) {
        unsigned sh = (unsigned)(2 * rot);
        u32 c = sh ? ((v << sh) | (v >> (32 - sh))) : v;
        if (c <= 0xff) return (rot << 8) | (int)c;
    }
    return -1;
}
/* dst = Rn OP Rm shifted */
static void dp_r(Emit *e, u32 cond, int op, int s, int rd, int rn, int rm,
                 int stype, unsigned samt) {
    ei(e, COND(cond) | ((u32)op << 21) | ((u32)s << 20) | ((u32)rn << 16) |
          ((u32)rd << 12) | ((samt & 31) << 7) | ((u32)stype << 5) | (u32)rm);
}
/* dst = Rn OP #imm (imm must be dp_imm-encodable) */
static void dp_i(Emit *e, u32 cond, int op, int s, int rd, int rn, int imm12) {
    ei(e, COND(cond) | (1u << 25) | ((u32)op << 21) | ((u32)s << 20) |
          ((u32)rn << 16) | ((u32)rd << 12) | (u32)imm12);
}
/* dst = Rn OP (Rm shifted by Rs) */
static void dp_rs(Emit *e, u32 cond, int op, int s, int rd, int rn, int rm,
                  int stype, int rs) {
    ei(e, COND(cond) | ((u32)op << 21) | ((u32)s << 20) | ((u32)rn << 16) |
          ((u32)rd << 12) | ((u32)rs << 8) | ((u32)stype << 5) | (1u << 4) |
          (u32)rm);
}

static void mov_rr(Emit *e, int rd, int rm) {
    if (rd != rm) dp_r(e, CC_AL, OP_MOV, 0, rd, 0, rm, SH_LSL, 0);
}
static void movw(Emit *e, int rd, u32 i16) {
    ei(e, AL | 0x03000000u | ((i16 >> 12) << 16) | ((u32)rd << 12) | (i16 & 0xfff));
}
static void movt(Emit *e, int rd, u32 i16) {
    ei(e, AL | 0x03400000u | ((i16 >> 12) << 16) | ((u32)rd << 12) | (i16 & 0xfff));
}
/* Any 32-bit constant: one data-processing immediate where it fits (either
 * sense), else movw plus movt. */
static void mov_ri(Emit *e, int rd, u32 v) {
    int i = dp_imm(v);
    if (i >= 0) { dp_i(e, CC_AL, OP_MOV, 0, rd, 0, i); return; }
    i = dp_imm(~v);
    if (i >= 0) { dp_i(e, CC_AL, OP_MVN, 0, rd, 0, i); return; }
    movw(e, rd, v & 0xffff);
    if (v >> 16) movt(e, rd, v >> 16);
}
/* rd = rn OP value, materializing the value into `scratch` when it is not an
 * encodable immediate. */
static void alu_ri_s(Emit *e, int op, int s, int rd, int rn, u32 v, int scratch) {
    int i = dp_imm(v);
    if (i >= 0) { dp_i(e, CC_AL, op, s, rd, rn, i); return; }
    mov_ri(e, scratch, v);
    dp_r(e, CC_AL, op, s, rd, rn, scratch, SH_LSL, 0);
}

/* LDR/STR Rd, [Rn, #±imm12] */
static void ls_i(Emit *e, int load, int byte, int rd, int rn, s32 off) {
    u32 u = off >= 0 ? 1u : 0u;
    u32 a = (u32)(off >= 0 ? off : -off);
    if (UNLIKELY(a > 0xfff)) { e->overflow = 1; return; }   /* never truncate */
    ei(e, AL | (1u << 26) | (1u << 24) | (u << 23) | ((u32)byte << 22) |
          ((u32)load << 20) | ((u32)rn << 16) | ((u32)rd << 12) | (a & 0xfff));
}
static void ld_r(Emit *e, int rd, int rn, s32 off) { ls_i(e, 1, 0, rd, rn, off); }
static void st_r(Emit *e, int rd, int rn, s32 off) { ls_i(e, 0, 0, rd, rn, off); }

static void ubfx(Emit *e, int rd, int rn, unsigned lsb, unsigned width) {
    ei(e, AL | 0x07E00050u | ((width - 1) << 16) | ((u32)rd << 12) |
          (lsb << 7) | (u32)rn);
}
static void mrs_apsr(Emit *e, int rd) { ei(e, AL | 0x010F0000u | ((u32)rd << 12)); }
static void msr_apsr(Emit *e, int rn) { ei(e, AL | 0x0128F000u | (u32)rn); }
static void clz(Emit *e, int rd, int rm)  { ei(e, AL | 0x016F0F10u | ((u32)rd << 12) | (u32)rm); }
static void rbit(Emit *e, int rd, int rm) { ei(e, AL | 0x06FF0F30u | ((u32)rd << 12) | (u32)rm); }
static void rev(Emit *e, int rd, int rm)  { ei(e, AL | 0x06BF0F30u | ((u32)rd << 12) | (u32)rm); }
static void umull(Emit *e, int rlo, int rhi, int rm, int rs) {
    ei(e, AL | (4u << 21) | ((u32)rhi << 16) | ((u32)rlo << 12) |
          ((u32)rs << 8) | 0x90u | (u32)rm);
}
static void smull(Emit *e, int rlo, int rhi, int rm, int rs) {
    ei(e, AL | (6u << 21) | ((u32)rhi << 16) | ((u32)rlo << 12) |
          ((u32)rs << 8) | 0x90u | (u32)rm);
}
static void mul_rr(Emit *e, int rd, int rm, int rs) {
    ei(e, AL | ((u32)rd << 16) | ((u32)rs << 8) | 0x90u | (u32)rm);
}
static void mla(Emit *e, int rd, int rm, int rs, int rn) {
    ei(e, AL | (1u << 21) | ((u32)rd << 16) | ((u32)rn << 12) |
          ((u32)rs << 8) | 0x90u | (u32)rm);
}
static void bx_r(Emit *e, int rm)  { ei(e, AL | 0x012FFF10u | (u32)rm); }
static void blx_r(Emit *e, int rm) { ei(e, AL | 0x012FFF30u | (u32)rm); }

/* B<cond> to an absolute code-cache address. The cache is capped so imm24
 * (+-32 MiB from the instruction after next) always reaches. */
static void b_to(Emit *e, int cond, const u8 *target) {
    s32 rel = (s32)(target - (e->rx + 8));
    ei(e, COND(cond) | (0xAu << 24) | (((u32)rel >> 2) & 0xFFFFFFu));
}
/* Forward branch, resolved later by fwd_here. */
static u8 *b_fwd(Emit *e, int cond) {
    u8 *pos = e->rw;
    ei(e, COND(cond) | (0xAu << 24));
    return pos;
}
static void fwd_here(Emit *e, u8 *pos) {
    if (!pos || e->overflow) return;
    u32 w;
    memcpy(&w, pos, 4);
    /* The branch sits at `pos`; its own rx is 8 less than the target of a
     * displacement measured from pos+8. */
    s32 rel = (s32)(e->rw - (pos + 8));
    w = (w & 0xFF000000u) | (((u32)rel >> 2) & 0xFFFFFFu);
    memcpy(pos, &w, 4);
}

/* ---- register allocator (over guest halves) ---- */

/* Memory home of a half. VREG_ZERO has none — it reads as zero and its writes
 * are discarded, so it is never mapped, never dirty and never synced. */
static void hv_home(BE *be, int hv, int *base, s32 *off) {
    int v = hv >> 1, hi = hv & 1;
    if (v < 31)           { *base = RCPU; *off = OFF_X(v) + 4 * hi; return; }
    if (v == VREG_SP)     { *base = RCPU; *off = OFF_SP + 4 * hi; return; }
    *base = RENV;
    *off = (s32)(offsetof(JitEnv, tmp_spill) + 8 * (v - VREG_TMP0) + 4 * hi);
}
static void ld_home(BE *be, int rd, int hv) {
    int base; s32 off;
    hv_home(be, hv, &base, &off);
    ld_r(be->e, rd, base, off);
}
static void st_home(BE *be, int rs, int hv) {
    int base; s32 off;
    hv_home(be, hv, &base, &off);
    st_r(be->e, rs, base, off);
}

static void ra_unmap(BE *be, int hv) {
    int h = be->h[hv];
    if (h >= 0) { be->r2v[h] = NHV; be->h[hv] = -1; be->dirty[hv] = 0; }
}
static void ra_evict(BE *be, int h) {
    int hv = be->r2v[h];
    if (hv >= NHV) return;
    if (be->dirty[hv]) st_home(be, h, hv);
    ra_unmap(be, hv);
}
static int ra_alloc(BE *be) {
    int best = -1;
    u32 best_lru = ~0u;
    for (int i = 0; i < POOL_N; i++) {
        int h = pool[i];
        if (be->locked[h]) continue;
        if (be->r2v[h] >= NHV) return h;
        if (be->lru[h] < best_lru) { best_lru = be->lru[h]; best = h; }
    }
    if (best < 0) {                              /* every pool register locked:
                                                  * a bug in some recipe. Fail
                                                  * loudly, never silently
                                                  * hand back one in use. */
        be->e->overflow = 1;
        return R0;
    }
    ra_evict(be, best);
    return best;
}
static void ra_lock(BE *be, int h) { be->locked[h] = 1; }
static void ra_unlock_all(BE *be) { memset(be->locked, 0, sizeof be->locked); }

static int use_hv(BE *be, int hv) {
    int h = be->h[hv];
    if (h < 0) {
        h = ra_alloc(be);
        if (be->zero[hv]) {
            mov_ri(be->e, h, 0);                 /* home is stale: keep dirty */
            be->zero[hv] = 0;
            be->dirty[hv] = 1;
        } else {
            ld_home(be, h, hv);
            be->dirty[hv] = 0;
        }
        be->h[hv] = (s8)h;
        be->r2v[h] = (u8)hv;
    }
    be->lru[h] = ++be->stamp;
    return h;
}
/* Register for a half about to be overwritten (no load). VREG_ZERO's writes go
 * to scratch and are discarded — a distinct register per half so a pair recipe
 * that computes into both stays structurally identical. */
static int def_hv(BE *be, int hv) {
    if ((hv >> 1) == VREG_ZERO) return (hv & 1) ? R1 : R0;
    int h = be->h[hv];
    if (h < 0) {
        h = ra_alloc(be);
        be->h[hv] = (s8)h;
        be->r2v[h] = (u8)hv;
    }
    be->zero[hv] = 0;
    be->dirty[hv] = 1;
    be->lru[h] = ++be->stamp;
    return h;
}
static int mod_hv(BE *be, int hv) {
    if ((hv >> 1) == VREG_ZERO) return (hv & 1) ? R1 : R0;
    int h = use_hv(be, hv);
    be->dirty[hv] = 1;
    return h;
}
static void set_zero_hv(BE *be, int hv) {
    if ((hv >> 1) == VREG_ZERO) return;
    ra_unmap(be, hv);                            /* value is overwritten */
    be->zero[hv] = 1;
}

/* A half's value in a register. Unlike i686 there is no memory-operand form to
 * exploit, so a source that is not resident is loaded into `scratch` — which is
 * why this host wants r0-r3 and r12 free rather than two registers. */
static int src_hv(BE *be, int hv, int scratch) {
    if ((hv >> 1) == VREG_ZERO) { mov_ri(be->e, scratch, 0); return scratch; }
    int h = be->h[hv];
    if (h >= 0) { be->lru[h] = ++be->stamp; return h; }
    if (be->zero[hv]) { mov_ri(be->e, scratch, 0); return scratch; }
    ld_home(be, scratch, hv);
    return scratch;
}

/* Make every home current. Flag-safe (moves and stores only). */
static void sync_all(BE *be) {
    int zeroed = -1;
    for (int hv = 0; hv < NHV; hv++) {
        if (be->zero[hv]) {
            if (zeroed < 0) { mov_ri(be->e, R0, 0); zeroed = R0; }
            st_home(be, zeroed, hv);
            be->zero[hv] = 0;
        } else if (be->h[hv] >= 0 && be->dirty[hv]) {
            st_home(be, be->h[hv], hv);
            be->dirty[hv] = 0;
        }
    }
}
static void inval_all(BE *be) {
    for (int hv = 0; hv < NHV; hv++) ra_unmap(be, hv);
}
static void inval_v(BE *be, int v) {
    if (v == VREG_ZERO) return;
    ra_unmap(be, HV(v, 0));
    ra_unmap(be, HV(v, 1));
    be->zero[HV(v, 0)] = be->zero[HV(v, 1)] = 0;
}

/* ---- guest flags ----
 * mrs/msr APSR move N/Z/C/V as a unit and in the guest's own bit positions, so
 * the architectural word costs three instructions for a 32-bit result. A 64-bit
 * one needs two more: the host Z describes the high word alone, so it is
 * dropped from the captured word and re-supplied from the pair with a
 * conditional orr. */
/* An S-op's flag kind. It matters for exactly one thing here: AArch64's logical
 * S-forms (ANDS/BICS) define C = 0 and V = 0, while ARM32's leave both alone —
 * the shifter would have to supply C, and V is simply untouched. So a logical
 * capture masks them off. The arithmetic forms need no adjustment at all: ARM32
 * and AArch64 agree on the carry and overflow senses of add and subtract. */
enum { FK_ARITH, FK_LOGIC };

static void emit_flags(BE *be, int kind, int w, int lo, int hi) {
    Emit *e = be->e;
    /* mrs delivers N/Z/C/V already in the guest's own bit positions. */
    mrs_apsr(e, R0);
    if (w) {
        /* The host Z describes the high word alone, so drop it and re-supply it
         * from the pair with a predicated orr. */
        alu_ri_s(e, OP_AND, 0, R0, R0,
                 kind == FK_LOGIC ? 0x80000000u : 0xB0000000u, R1);
        dp_r(e, CC_AL, OP_ORR, 1, R1, lo, hi, SH_LSL, 0);   /* orrs: pair Z */
        dp_i(e, CC_EQ, OP_ORR, 0, R0, R0, dp_imm(0x40000000u));
    } else {
        alu_ri_s(e, OP_AND, 0, R0, R0,
                 kind == FK_LOGIC ? 0xC0000000u : 0xF0000000u, R1);
    }
    st_r(e, R0, RCPU, OFF_NZCV);
}

/* Set the host flags from c->nzcv so a <cond> instruction tests the guest
 * condition directly. Clobbers r0. */
static void cond_load(BE *be) {
    ld_r(be->e, R0, RCPU, OFF_NZCV);
    msr_apsr(be->e, R0);
}
/* ARM32 has no NV; AArch64's NV behaves as AL. */
static int guest_cond(unsigned c) { return (c & 15) == 15 ? CC_AL : (int)(c & 15); }
static int cond_inv(int c) { return c ^ 1; }

/* ---- outgoing arguments and helper calls ---- */

static void arg_imm_stack(BE *be, int slot, u32 v) {
    mov_ri(be->e, R0, v);
    st_r(be->e, R0, SP_, FR_ARG(slot));
}
static void arg_imm64_stack(BE *be, int slot, u64 v) {
    arg_imm_stack(be, slot, (u32)v);
    arg_imm_stack(be, slot + 1, (u32)(v >> 32));
}
static void arg_hv64_stack(BE *be, int slot, int v) {
    for (int half = 0; half < 2; half++) {
        int r = src_hv(be, HV(v, half), R0);
        st_r(be->e, r, SP_, FR_ARG(slot + half));
    }
}
/* Call a helper whose address sits in the JitEnv (bl's +-32 MiB cannot be
 * relied on to reach the emulator's own text from the code cache). */
static void call_env(BE *be, size_t off) {
    ld_r(be->e, R12, RENV, (s32)off);
    blx_r(be->e, R12);
}
/* Call one of this file's own helpers, by absolute address. */
static void call_abs(BE *be, const void *fn) {
    mov_ri(be->e, R12, (u32)(uintptr_t)fn);
    blx_r(be->e, R12);
}

/* ---- pure C helpers for the ops with no short pair form ----
 * All are leaf functions of their arguments: they touch no emulator state, so a
 * call needs no guest-state sync. AAPCS puts every argument in r0-r3 and the
 * result in r0/r1. */

static u32 h_udiv32(u64 a, u64 b) {
    u32 x = (u32)a, y = (u32)b;
    return y ? x / y : 0;
}
static u32 h_sdiv32(u64 a, u64 b) {
    s32 x = (s32)(u32)a, y = (s32)(u32)b;
    if (!y) return 0;
    if (y == -1 && x == INT32_MIN) return (u32)x;
    return (u32)(x / y);
}
static u64 h_udiv64(u64 a, u64 b) { return b ? a / b : 0; }
static u64 h_sdiv64(u64 a, u64 b) {
    s64 x = (s64)a, y = (s64)b;
    if (!y) return 0;
    if (y == -1 && x == INT64_MIN) return (u64)x;
    return (u64)(x / y);
}
static u64 h_umulh(u64 a, u64 b) {
    u32 al = (u32)a, ah = (u32)(a >> 32), bl = (u32)b, bh = (u32)(b >> 32);
    u64 ll = (u64)al * bl, lh = (u64)al * bh, hl = (u64)ah * bl;
    u64 mid = (ll >> 32) + (u32)lh + (u32)hl;
    return (u64)ah * bh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}
static u64 h_smulh(u64 a, u64 b) {
    u64 r = h_umulh(a, b);
    if ((s64)a < 0) r -= b;
    if ((s64)b < 0) r -= a;
    return r;
}
static u64 h_lsl64(u64 v, u32 n) { return v << (n & 63); }
static u64 h_lsr64(u64 v, u32 n) { return v >> (n & 63); }
static u64 h_asr64(u64 v, u32 n) { return (u64)((s64)v >> (n & 63)); }
static u64 h_ror64(u64 v, u32 n) {
    n &= 63;
    return n ? (v >> n) | (v << (64 - n)) : v;
}

/* ---- exits ---- */

static void icount_add(BE *be, u32 n) {
    if (!n) return;
    Emit *e = be->e;
    ld_r(e, R0, RCPU, OFF_ICOUNT);
    ld_r(e, R1, RCPU, OFF_ICOUNT + 4);
    alu_ri_s(e, OP_ADD, 1, R0, R0, n, R12);      /* adds */
    alu_ri_s(e, OP_ADC, 0, R1, R1, 0, R12);
    st_r(e, R0, RCPU, OFF_ICOUNT);
    st_r(e, R1, RCPU, OFF_ICOUNT + 4);
}

static void store_pc_imm(BE *be, u64 pc) {
    Emit *e = be->e;
    mov_ri(e, R0, (u32)pc);
    st_r(e, R0, RCPU, OFF_PC);
    mov_ri(e, R0, (u32)(pc >> 32));
    st_r(e, R0, RCPU, OFF_PC + 4);
}

static void exit_plain(BE *be, u32 icnt) {       /* c->pc already correct */
    icount_add(be, icnt);
    mov_ri(be->e, R0, JIT_EXIT_NONE);
    b_to(be->e, CC_AL, be->env->epilogue_rx);
}

/* Chainable exit. The patch site is one instruction — fixed-width ISA, so the
 * chain is a single `b` written over it and JBlock::stub_word0 restores the
 * original word verbatim. */
static void exit_stub(BE *be, int slot, u64 target_pc, u32 icnt) {
    Emit *e = be->e;
    JBlock *b = be->b;
    icount_add(be, icnt);
    b->exit_pc[slot] = target_pc;
    b->exit_off[slot] = (u32)(e->rx - b->code);
    u8 *site = e->rw;
    store_pc_imm(be, target_pc);
    if (!e->overflow) memcpy(&b->stub_word0[slot], site, 4);
    mov_ri(e, R0, ((u32)(b - be->env->arena) << 1) | (u32)slot);
    b_to(e, CC_AL, be->env->epilogue_rx);
}

/* ---- thunks ---- */

int be_available(void) { return 1; }

void be_emit_thunks(Emit *e, JitEnv *env) {
    env->enter = (u32 (*)(JitEnv *, const u8 *))(uintptr_t)e->rx;
    ei(e, AL | 0x092D0000u | 0x4FF0u);            /* push {r4-r11, lr} */
    mov_rr(e, R12, R1);                           /* code_rx (arg1) */
    mov_rr(e, RENV, R0);                          /* env (arg0) */
    ld_r(e, RCPU, RENV, (s32)offsetof(JitEnv, c));
    alu_ri_s(e, OP_SUB, 0, SP_, SP_, FR_SIZE, R0);
    bx_r(e, R12);

    env->epilogue_rx = e->rx;
    alu_ri_s(e, OP_ADD, 0, SP_, SP_, FR_SIZE, R1);
    ei(e, AL | 0x08BD0000u | 0x8FF0u);            /* pop {r4-r11, pc} */
}

/* ---- pair recipes ---- */

typedef struct { int lo, hi; } Pair;

/* Destination registers primed with `a`'s value, so an in-place `op dst, b`
 * computes dst = a OP b. The caller must have handled dst == b already. */
static Pair prime_pair(BE *be, int d, int a, int w) {
    Pair p;
    p.lo = (d == a) ? mod_hv(be, HV(d, 0)) : def_hv(be, HV(d, 0));
    ra_lock(be, p.lo);
    if (d != a) mov_rr(be->e, p.lo, src_hv(be, HV(a, 0), R0));
    p.hi = -1;
    if (w) {
        p.hi = (d == a) ? mod_hv(be, HV(d, 1)) : def_hv(be, HV(d, 1));
        ra_lock(be, p.hi);
        if (d != a) mov_rr(be->e, p.hi, src_hv(be, HV(a, 1), R0));
    }
    return p;
}
static void finish32(BE *be, int d, int w) {
    if (!w) set_zero_hv(be, HV(d, 1));
}
/* Commit a pair computed in scratch registers to the destination. */
static void commit_pair(BE *be, int d, int w, int lo, int hi) {
    int dlo = def_hv(be, HV(d, 0));
    ra_lock(be, dlo);
    mov_rr(be->e, dlo, lo);
    if (w) mov_rr(be->e, def_hv(be, HV(d, 1)), hi);
    else finish32(be, d, 0);
}

/* Does this opcode pair form a carry chain? If so the LOW half must set the
 * flags whatever the guest wants, because the high adc/sbc consumes its carry —
 * getting this wrong silently drops every carry out of a 64-bit add. */
static int pair_carries(int ophi) { return ophi == OP_ADC || ophi == OP_SBC; }

/* dst = a OP b over halves. `oplo`/`ophi` are the data-processing opcodes; s
 * makes the *high* op (or the only op) set the guest flags. */
static Pair alu_pair(BE *be, int oplo, int ophi, int s, int d, int a, int b,
                     int w, int commut) {
    Emit *e = be->e;
    Pair p;
    if (d == b && d != a) {
        if (commut) { int t = a; a = b; b = t; }
        else {
            /* Non-commutative with the destination as the second operand:
             * compute in scratch, then commit. */
            int alo = src_hv(be, HV(a, 0), R0);
            int blo = src_hv(be, HV(b, 0), R1);
            dp_r(e, CC_AL, oplo, w ? pair_carries(ophi) : s, R2, alo, blo, SH_LSL, 0);
            if (w) {
                int ahi = src_hv(be, HV(a, 1), R0);
                int bhi = src_hv(be, HV(b, 1), R1);
                dp_r(e, CC_AL, ophi, s, R3, ahi, bhi, SH_LSL, 0);
            }
            p.lo = R2; p.hi = R3;
            commit_pair(be, d, w, R2, R3);
            return p;
        }
    }
    p = prime_pair(be, d, a, w);
    int blo = src_hv(be, HV(b, 0), R0);
    dp_r(e, CC_AL, oplo, w ? pair_carries(ophi) : s, p.lo, p.lo, blo,
             SH_LSL, 0);
    if (w) {
        int bhi = src_hv(be, HV(b, 1), R0);
        dp_r(e, CC_AL, ophi, s, p.hi, p.hi, bhi, SH_LSL, 0);
    }
    finish32(be, d, w);
    return p;
}
/* The same for an S-form whose destination is XZR: the result goes to scratch
 * purely for its flags (and for a 64-bit Z). */
static Pair alu_discard(BE *be, int oplo, int ophi, int a, int b, int w) {
    Emit *e = be->e;
    Pair p = { R2, R3 };
    int alo = src_hv(be, HV(a, 0), R0);
    int blo = src_hv(be, HV(b, 0), R1);
    dp_r(e, CC_AL, oplo, w ? pair_carries(ophi) : 1, R2, alo, blo, SH_LSL, 0);
    if (w) {
        int ahi = src_hv(be, HV(a, 1), R0);
        int bhi = src_hv(be, HV(b, 1), R1);
        dp_r(e, CC_AL, ophi, 1, R3, ahi, bhi, SH_LSL, 0);
    }
    return p;
}
/* dst = a OP imm. */
static Pair alui_pair(BE *be, int oplo, int ophi, int s, int d, int a, u64 imm,
                      int w) {
    Emit *e = be->e;
    Pair p = prime_pair(be, d, a, w);
    alu_ri_s(e, oplo, w ? pair_carries(ophi) : s, p.lo, p.lo, (u32)imm, R0);
    if (w) alu_ri_s(e, ophi, s, p.hi, p.hi, (u32)(imm >> 32), R0);
    finish32(be, d, w);
    return p;
}
static Pair alui_discard(BE *be, int oplo, int ophi, int a, u64 imm, int w) {
    Emit *e = be->e;
    Pair p = { R2, R3 };
    int alo = src_hv(be, HV(a, 0), R0);
    alu_ri_s(e, oplo, w ? pair_carries(ophi) : 1, R2, alo, (u32)imm, R1);
    if (w) {
        int ahi = src_hv(be, HV(a, 1), R0);
        alu_ri_s(e, ophi, 1, R3, ahi, (u32)(imm >> 32), R1);
    }
    return p;
}

/* ---- shifts by a constant amount ---- */

static void shift_imm_pair(BE *be, int op, Pair p, unsigned amt) {
    Emit *e = be->e;
    if (!amt) return;
    switch (op) {
        case IRO_LSLI:
            if (amt < 32) {
                /* hi = (hi << n) | (lo >> (32-n)); lo <<= n */
                dp_r(e, CC_AL, OP_MOV, 0, p.hi, 0, p.hi, SH_LSL, amt);
                dp_r(e, CC_AL, OP_ORR, 0, p.hi, p.hi, p.lo, SH_LSR, 32 - amt);
                dp_r(e, CC_AL, OP_MOV, 0, p.lo, 0, p.lo, SH_LSL, amt);
            } else {
                dp_r(e, CC_AL, OP_MOV, 0, p.hi, 0, p.lo, SH_LSL, amt - 32);
                mov_ri(e, p.lo, 0);
            }
            break;
        case IRO_LSRI:
            if (amt < 32) {
                dp_r(e, CC_AL, OP_MOV, 0, p.lo, 0, p.lo, SH_LSR, amt);
                dp_r(e, CC_AL, OP_ORR, 0, p.lo, p.lo, p.hi, SH_LSL, 32 - amt);
                dp_r(e, CC_AL, OP_MOV, 0, p.hi, 0, p.hi, SH_LSR, amt);
            } else {
                /* LSR #0 encodes LSR #32 on ARM, so an exact 32 is a move. */
                if (amt > 32) dp_r(e, CC_AL, OP_MOV, 0, p.lo, 0, p.hi, SH_LSR, amt - 32);
                else          mov_rr(e, p.lo, p.hi);
                mov_ri(e, p.hi, 0);
            }
            break;
        case IRO_ASRI:
            if (amt < 32) {
                dp_r(e, CC_AL, OP_MOV, 0, p.lo, 0, p.lo, SH_LSR, amt);
                dp_r(e, CC_AL, OP_ORR, 0, p.lo, p.lo, p.hi, SH_LSL, 32 - amt);
                dp_r(e, CC_AL, OP_MOV, 0, p.hi, 0, p.hi, SH_ASR, amt);
            } else {
                /* ASR #0 encodes ASR #32, so an exact 32 is a plain move. */
                if (amt > 32) dp_r(e, CC_AL, OP_MOV, 0, p.lo, 0, p.hi, SH_ASR, amt - 32);
                else          mov_rr(e, p.lo, p.hi);
                dp_r(e, CC_AL, OP_MOV, 0, p.hi, 0, p.hi, SH_ASR, 31);
            }
            break;
        default:                                 /* IRO_RORI */
            if (amt == 32) {
                mov_rr(e, R0, p.lo);
                mov_rr(e, p.lo, p.hi);
                mov_rr(e, p.hi, R0);
            } else {
                unsigned n = amt < 32 ? amt : amt - 32;
                if (amt > 32) {                  /* rotate 32 first */
                    mov_rr(e, R0, p.lo);
                    mov_rr(e, p.lo, p.hi);
                    mov_rr(e, p.hi, R0);
                }
                /* newlo = (lo >> n) | (hi << (32-n)), newhi likewise */
                mov_rr(e, R0, p.lo);
                dp_r(e, CC_AL, OP_MOV, 0, p.lo, 0, p.lo, SH_LSR, n);
                dp_r(e, CC_AL, OP_ORR, 0, p.lo, p.lo, p.hi, SH_LSL, 32 - n);
                dp_r(e, CC_AL, OP_MOV, 0, p.hi, 0, p.hi, SH_LSR, n);
                dp_r(e, CC_AL, OP_ORR, 0, p.hi, p.hi, R0, SH_LSL, 32 - n);
            }
            break;
    }
}

/* ---- memory (helper-only in this backend) ---- */

static void emit_mem(BE *be, const IROp *o) {
    Emit *e = be->e;
    sync_all(be);
    /* va = base + offset, into the AAPCS pair r2/r3 */
    int blo = src_hv(be, HV(o->a, 0), R2);
    mov_rr(e, R2, blo);
    int bhi = src_hv(be, HV(o->a, 1), R3);
    mov_rr(e, R3, bhi);
    if (o->imm) {
        alu_ri_s(e, OP_ADD, 1, R2, R2, (u32)o->imm, R12);       /* adds */
        alu_ri_s(e, OP_ADC, 0, R3, R3, (u32)(o->imm >> 32), R12);
    }
    if (o->op == IRO_ST) {                       /* (c, va, val, pc, desc) */
        arg_hv64_stack(be, 0, o->b);
        arg_imm64_stack(be, 2, o->imm2pc);
        arg_imm_stack(be, 4, o->aux);
    } else {                                     /* (c, va, pc, desc) */
        arg_imm64_stack(be, 0, o->imm2pc);
        arg_imm_stack(be, 2, o->aux);
    }
    mov_rr(e, R0, RCPU);
    call_env(be, o->op == IRO_LD  ? offsetof(JitEnv, helper_ld)
              : o->op == IRO_ST  ? offsetof(JitEnv, helper_st)
              : o->op == IRO_LDV ? offsetof(JitEnv, helper_ldv)
                                 : offsetof(JitEnv, helper_stv));
    dp_i(e, CC_AL, OP_CMP, 1, 0, R0, 0);         /* cmp r0, #0 */
    u8 *ok = b_fwd(e, CC_EQ);
    exit_plain(be, o->icnt);                     /* faulted */
    fwd_here(e, ok);
    if (o->op == IRO_LD) inval_v(be, o->dst);    /* helper wrote the home */
}

/* ---- one guest instruction through the interpreter ---- */

static void emit_exec1(BE *be, u64 pc, u32 insn, int ic, u32 icnt) {
    Emit *e = be->e;
    sync_all(be);
    inval_all(be);
    arg_imm_stack(be, 0, insn);
    mov_ri(e, R2, (u32)pc);
    mov_ri(e, R3, (u32)(pc >> 32));
    mov_rr(e, R0, RCPU);
    call_env(be, ic ? offsetof(JitEnv, helper_exec1_ic)
                    : offsetof(JitEnv, helper_exec1));
    dp_i(e, CC_AL, OP_CMP, 1, 0, R0, 0);
    u8 *cont = b_fwd(e, CC_EQ);
    exit_plain(be, icnt);
    fwd_here(e, cont);
}

/* ---- block body ---- */

static int emit_op(BE *be, const IRBlock *ir, int i);

int be_emit_block(Emit *e, JitEnv *env, JBlock *b, const struct IRBlock *ir) {
    BE be;
    memset(&be, 0, sizeof be);
    be.e = e;
    be.env = env;
    be.b = b;
    for (int hv = 0; hv < NHV; hv++) be.h[hv] = -1;
    for (int h = 0; h < HREG_N; h++) be.r2v[h] = NHV;
    b->exit_pc[0] = b->exit_pc[1] = ~0ULL;
    b->exit_off[0] = b->exit_off[1] = 0;
    b->patched[0] = b->patched[1] = 0;
    b->in_head = ~0u;

    /* Safepoint: the hot entry is a load, a compare and a branch; the exit body
     * sits after the block's last op. c->pc has to be restored to the block
     * start there — a direct chain jump in bypassed the predecessor's write. */
    ld_r(e, R0, RENV, (s32)offsetof(JitEnv, interrupt));
    dp_i(e, CC_AL, OP_CMP, 1, 0, R0, 0);
    u8 *cold = b_fwd(e, CC_NE);

    for (int k = 0; k < ir->n && !e->overflow; ) {
        ra_unlock_all(&be);
        k += emit_op(&be, ir, k);
    }

    if (e->overflow) return -1;
    fwd_here(e, cold);
    store_pc_imm(&be, b->pc);
    exit_plain(&be, 0);
    return e->overflow ? -1 : 0;
}

static int emit_op(BE *be, const IRBlock *ir, int i) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    int w = o->w;

    switch (o->op) {
        case IRO_NOP:
            break;

        case IRO_MOVI: {
            u64 imm = w ? o->imm : (u32)o->imm;
            if ((u32)imm) mov_ri(e, def_hv(be, HV(o->dst, 0)), (u32)imm);
            else set_zero_hv(be, HV(o->dst, 0));
            if (w && (u32)(imm >> 32))
                mov_ri(e, def_hv(be, HV(o->dst, 1)), (u32)(imm >> 32));
            else
                set_zero_hv(be, HV(o->dst, 1));
            break;
        }
        case IRO_MOV:
            if (o->dst != o->a) {
                int dlo = def_hv(be, HV(o->dst, 0));
                ra_lock(be, dlo);
                mov_rr(e, dlo, src_hv(be, HV(o->a, 0), R0));
                if (w) mov_rr(e, def_hv(be, HV(o->dst, 1)),
                              src_hv(be, HV(o->a, 1), R0));
            }
            finish32(be, o->dst, w);
            break;
        case IRO_MOVK: {                          /* dst == a; insert imm16 */
            unsigned sh = o->cc;
            int half = (sh >= 32);
            Pair p = prime_pair(be, o->dst, o->a, w || half);
            int r = half ? p.hi : p.lo;
            alu_ri_s(e, OP_BIC, 0, r, r, 0xffffu << (sh & 31), R0);
            u32 part = (u32)(o->imm >> (32 * half));
            if (part) alu_ri_s(e, OP_ORR, 0, r, r, part, R0);
            finish32(be, o->dst, w);
            break;
        }

        /* ---- register ALU ---- */
        case IRO_ADD: alu_pair(be, OP_ADD, OP_ADC, 0, o->dst, o->a, o->b, w, 1); break;
        case IRO_SUB: alu_pair(be, OP_SUB, OP_SBC, 0, o->dst, o->a, o->b, w, 0); break;
        case IRO_AND: alu_pair(be, OP_AND, OP_AND, 0, o->dst, o->a, o->b, w, 1); break;
        case IRO_ORR: alu_pair(be, OP_ORR, OP_ORR, 0, o->dst, o->a, o->b, w, 1); break;
        case IRO_EOR: alu_pair(be, OP_EOR, OP_EOR, 0, o->dst, o->a, o->b, w, 1); break;
        /* dst = a OP ~b: ARM has BIC natively, and ORN/EON need one mvn. */
        case IRO_BIC: alu_pair(be, OP_BIC, OP_BIC, 0, o->dst, o->a, o->b, w, 0); break;
        case IRO_ORN: case IRO_EON: {
            int op = (o->op == IRO_ORN) ? OP_ORR : OP_EOR;
            int blo = src_hv(be, HV(o->b, 0), R0);
            dp_r(e, CC_AL, OP_MVN, 0, R2, 0, blo, SH_LSL, 0);
            if (w) {
                int bhi = src_hv(be, HV(o->b, 1), R0);
                dp_r(e, CC_AL, OP_MVN, 0, R3, 0, bhi, SH_LSL, 0);
            }
            Pair p = prime_pair(be, o->dst, o->a, w);
            dp_r(e, CC_AL, op, 0, p.lo, p.lo, R2, SH_LSL, 0);
            if (w) dp_r(e, CC_AL, op, 0, p.hi, p.hi, R3, SH_LSL, 0);
            finish32(be, o->dst, w);
            break;
        }

        case IRO_ADDS: case IRO_SUBS: case IRO_ANDS: case IRO_BICS: {
            int oplo = o->op == IRO_ADDS ? OP_ADD : o->op == IRO_SUBS ? OP_SUB
                     : o->op == IRO_ANDS ? OP_AND : OP_BIC;
            int ophi = o->op == IRO_ADDS ? OP_ADC : o->op == IRO_SUBS ? OP_SBC
                                                                     : oplo;
            int commut = (o->op == IRO_ADDS || o->op == IRO_ANDS);
            if (o->dst == VREG_ZERO && o->flags_dead) break;
            Pair p;
            if (o->dst == VREG_ZERO) p = alu_discard(be, oplo, ophi, o->a, o->b, w);
            else p = alu_pair(be, oplo, ophi, !o->flags_dead, o->dst, o->a,
                              o->b, w, commut);
            if (!o->flags_dead)
                emit_flags(be, (o->op == IRO_ANDS || o->op == IRO_BICS)
                                   ? FK_LOGIC : FK_ARITH, w, p.lo, p.hi);
            break;
        }

        case IRO_ADC: case IRO_SBC: case IRO_ADCS: case IRO_SBCS: {
            int sbc  = (o->op == IRO_SBC || o->op == IRO_SBCS);
            int setf = (o->op == IRO_ADCS || o->op == IRO_SBCS);
            int op = sbc ? OP_SBC : OP_ADC;
            if (setf && o->flags_dead && o->dst == VREG_ZERO) break;
            /* The pair form of a three-input add is adc/adc (sbc/sbc) with the
             * host carry seeded from the guest C. ARM SBC is a + ~b + C, which
             * is exactly the host's sbc, so no inversion is needed here — the
             * two architectures agree on the borrow sense. */
            Pair p;
            int scratch = (o->dst == VREG_ZERO) ||
                          (o->dst == o->b && o->dst != o->a);
            if (scratch) {
                p.lo = R2; p.hi = R3;
                mov_rr(e, R2, src_hv(be, HV(o->a, 0), R2));
                if (w) mov_rr(e, R3, src_hv(be, HV(o->a, 1), R3));
            } else {
                p = prime_pair(be, o->dst, o->a, w);
            }
            /* Seed the host flags from c->nzcv, then the adc chain. Only
             * flag-safe moves may intervene, and the loads above are that. */
            int blo = src_hv(be, HV(o->b, 0), R1);
            int bhi = w ? src_hv(be, HV(o->b, 1), R12) : blo;
            cond_load(be);                       /* msr APSR: C = guest C */
            dp_r(e, CC_AL, op, w ? 1 : setf, p.lo, p.lo, blo, SH_LSL, 0);
            if (w) dp_r(e, CC_AL, op, setf, p.hi, p.hi, bhi, SH_LSL, 0);
            if (!scratch) finish32(be, o->dst, w);
            else if (o->dst != VREG_ZERO) commit_pair(be, o->dst, w, R2, R3);
            if (setf && !o->flags_dead) emit_flags(be, FK_ARITH, w, p.lo, p.hi);
            break;
        }

        case IRO_ADDI: case IRO_SUBI: case IRO_ANDI: case IRO_ORRI:
        case IRO_EORI: {
            int oplo = o->op == IRO_ADDI ? OP_ADD : o->op == IRO_SUBI ? OP_SUB
                     : o->op == IRO_ANDI ? OP_AND : o->op == IRO_ORRI ? OP_ORR
                                                                      : OP_EOR;
            int ophi = o->op == IRO_ADDI ? OP_ADC : o->op == IRO_SUBI ? OP_SBC
                                                                     : oplo;
            u64 imm = w ? o->imm : (u32)o->imm;
            if (o->op == IRO_ANDI && w && (u32)(imm >> 32) == 0) {
                Pair p = prime_pair(be, o->dst, o->a, 0);
                alu_ri_s(e, OP_AND, 0, p.lo, p.lo, (u32)imm, R0);
                set_zero_hv(be, HV(o->dst, 1));
                break;
            }
            alui_pair(be, oplo, ophi, 0, o->dst, o->a, imm, w);
            break;
        }
        case IRO_ADDIS: case IRO_SUBIS: case IRO_ANDIS: {
            int oplo = o->op == IRO_ADDIS ? OP_ADD
                     : o->op == IRO_SUBIS ? OP_SUB : OP_AND;
            int ophi = o->op == IRO_ADDIS ? OP_ADC
                     : o->op == IRO_SUBIS ? OP_SBC : OP_AND;
            u64 imm = w ? o->imm : (u32)o->imm;
            if (o->dst == VREG_ZERO && o->flags_dead) break;
            Pair p;
            if (o->dst == VREG_ZERO) p = alui_discard(be, oplo, ophi, o->a, imm, w);
            else p = alui_pair(be, oplo, ophi, !o->flags_dead, o->dst, o->a,
                               imm, w);
            if (!o->flags_dead)
                emit_flags(be, o->op == IRO_ANDIS ? FK_LOGIC : FK_ARITH, w,
                           p.lo, p.hi);
            break;
        }

        /* ---- shifts ---- */
        case IRO_LSLI: case IRO_LSRI: case IRO_ASRI: case IRO_RORI: {
            if (!w) {
                static const u8 st[] = { SH_LSL, SH_LSR, SH_ASR, SH_ROR };
                Pair p = prime_pair(be, o->dst, o->a, 0);
                if (o->imm)
                    dp_r(e, CC_AL, OP_MOV, 0, p.lo, 0, p.lo,
                         st[o->op - IRO_LSLI], (unsigned)o->imm);
                finish32(be, o->dst, 0);
                break;
            }
            Pair p = prime_pair(be, o->dst, o->a, 1);
            shift_imm_pair(be, o->op, p, (unsigned)o->imm);
            break;
        }
        case IRO_LSLV: case IRO_LSRV: case IRO_ASRV: case IRO_RORV: {
            if (!w) {
                static const u8 st[] = { SH_LSL, SH_LSR, SH_ASR, SH_ROR };
                /* ARM masks a register shift amount by 255, the guest by 31. */
                /* r12, not r0: prime_pair uses r0 as its own scratch and
                 * would clobber the count. ARM masks a register shift amount
                 * by 255, the guest by 31, hence the and. */
                int bl = src_hv(be, HV(o->b, 0), R12);
                alu_ri_s(e, OP_AND, 0, R12, bl, 31, R1);
                Pair p = prime_pair(be, o->dst, o->a, 0);
                dp_rs(e, CC_AL, OP_MOV, 0, p.lo, 0, p.lo,
                      st[o->op - IRO_LSLV], R12);
                finish32(be, o->dst, 0);
                break;
            }
            static const void *const fn[] = { (const void *)h_lsl64,
                                              (const void *)h_lsr64,
                                              (const void *)h_asr64,
                                              (const void *)h_ror64 };
            mov_rr(e, R2, src_hv(be, HV(o->b, 0), R2));
            int alo = src_hv(be, HV(o->a, 0), R0);
            int ahi = src_hv(be, HV(o->a, 1), R1);
            mov_rr(e, R1, ahi);
            mov_rr(e, R0, alo);
            call_abs(be, fn[o->op - IRO_LSLV]);
            commit_pair(be, o->dst, 1, R0, R1);
            break;
        }
        case IRO_EXTR: {
            unsigned amt = (unsigned)o->imm;
            if (!w) {
                int bl = src_hv(be, HV(o->b, 0), R0);
                mov_rr(e, R2, bl);
                if (amt) {
                    int ah = src_hv(be, HV(o->a, 0), R1);
                    dp_r(e, CC_AL, OP_MOV, 0, R2, 0, R2, SH_LSR, amt);
                    dp_r(e, CC_AL, OP_ORR, 0, R2, R2, ah, SH_LSL, 32 - amt);
                }
                commit_pair(be, o->dst, 0, R2, R3);
                break;
            }
            /* 128-bit funnel of (a:b) >> amt, low 64 bits: two ORR/LSR pairs
             * whose sources are one word apart. */
            int w0, w1, w2;                       /* the three words involved */
            if (amt == 0) {
                mov_rr(e, R2, src_hv(be, HV(o->b, 0), R2));
                mov_rr(e, R3, src_hv(be, HV(o->b, 1), R3));
                commit_pair(be, o->dst, 1, R2, R3);
                break;
            }
            if (amt < 32) { w0 = HV(o->b, 0); w1 = HV(o->b, 1); w2 = HV(o->a, 0); }
            else          { w0 = HV(o->b, 1); w1 = HV(o->a, 0); w2 = HV(o->a, 1); }
            unsigned n = amt < 32 ? amt : amt - 32;
            int r0 = src_hv(be, w0, R0);
            mov_rr(e, R2, r0);
            int r1 = src_hv(be, w1, R1);
            mov_rr(e, R3, r1);
            if (n) {
                int r2 = src_hv(be, w2, R12);
                dp_r(e, CC_AL, OP_MOV, 0, R2, 0, R2, SH_LSR, n);
                dp_r(e, CC_AL, OP_ORR, 0, R2, R2, R3, SH_LSL, 32 - n);
                dp_r(e, CC_AL, OP_MOV, 0, R3, 0, R3, SH_LSR, n);
                dp_r(e, CC_AL, OP_ORR, 0, R3, R3, r2, SH_LSL, 32 - n);
            }
            commit_pair(be, o->dst, 1, R2, R3);
            break;
        }

        /* ---- multiply / divide ---- */
        case IRO_MADD: case IRO_MSUB: {
            int sub = (o->op == IRO_MSUB);
            if (!w) {
                int al = src_hv(be, HV(o->a, 0), R0);
                int bl = src_hv(be, HV(o->b, 0), R1);
                if (o->cc != VREG_ZERO && !sub) {
                    int rl = src_hv(be, HV(o->cc, 0), R2);
                    mla(e, R3, al, bl, rl);
                } else {
                    mul_rr(e, R3, al, bl);
                    if (o->cc != VREG_ZERO) {     /* Ra - a*b */
                        int rl = src_hv(be, HV(o->cc, 0), R2);
                        dp_r(e, CC_AL, OP_SUB, 0, R3, rl, R3, SH_LSL, 0);
                    } else if (sub) {
                        dp_i(e, CC_AL, OP_RSB, 0, R3, R3, dp_imm(0));
                    }
                }
                commit_pair(be, o->dst, 0, R3, R2);
                break;
            }
            /* 64x64 low product: umull for the low half, then the two cross
             * terms accumulate into the high word with mla. */
            int al = src_hv(be, HV(o->a, 0), R0);
            int bl = src_hv(be, HV(o->b, 0), R1);
            umull(e, R2, R3, al, bl);            /* r3:r2 = alo*blo */
            al = src_hv(be, HV(o->a, 0), R0);
            int bh = src_hv(be, HV(o->b, 1), R1);
            mla(e, R3, al, bh, R3);
            int ah = src_hv(be, HV(o->a, 1), R0);
            bl = src_hv(be, HV(o->b, 0), R1);
            mla(e, R3, ah, bl, R3);
            if (o->cc != VREG_ZERO) {
                int rl = src_hv(be, HV(o->cc, 0), R0);
                int rh = src_hv(be, HV(o->cc, 1), R1);
                if (sub) {                        /* Ra - a*b */
                    dp_r(e, CC_AL, OP_SUB, 1, R2, rl, R2, SH_LSL, 0);
                    dp_r(e, CC_AL, OP_SBC, 0, R3, rh, R3, SH_LSL, 0);
                } else {
                    dp_r(e, CC_AL, OP_ADD, 1, R2, R2, rl, SH_LSL, 0);
                    dp_r(e, CC_AL, OP_ADC, 0, R3, R3, rh, SH_LSL, 0);
                }
            } else if (sub) {                     /* 0 - a*b */
                dp_i(e, CC_AL, OP_RSB, 1, R2, R2, dp_imm(0));
                dp_i(e, CC_AL, OP_RSC, 0, R3, R3, dp_imm(0));
            }
            commit_pair(be, o->dst, 1, R2, R3);
            break;
        }
        case IRO_SMADDL: case IRO_SMSUBL: case IRO_UMADDL: case IRO_UMSUBL: {
            int sign = (o->op == IRO_SMADDL || o->op == IRO_SMSUBL);
            int sub  = (o->op == IRO_SMSUBL || o->op == IRO_UMSUBL);
            int al = src_hv(be, HV(o->a, 0), R0);
            int bl = src_hv(be, HV(o->b, 0), R1);
            if (sign) smull(e, R2, R3, al, bl);
            else      umull(e, R2, R3, al, bl);
            if (o->cc != VREG_ZERO) {
                int rl = src_hv(be, HV(o->cc, 0), R0);
                int rh = src_hv(be, HV(o->cc, 1), R1);
                if (sub) {
                    dp_r(e, CC_AL, OP_SUB, 1, R2, rl, R2, SH_LSL, 0);
                    dp_r(e, CC_AL, OP_SBC, 0, R3, rh, R3, SH_LSL, 0);
                } else {
                    dp_r(e, CC_AL, OP_ADD, 1, R2, R2, rl, SH_LSL, 0);
                    dp_r(e, CC_AL, OP_ADC, 0, R3, R3, rh, SH_LSL, 0);
                }
            } else if (sub) {
                dp_i(e, CC_AL, OP_RSB, 1, R2, R2, dp_imm(0));
                dp_i(e, CC_AL, OP_RSC, 0, R3, R3, dp_imm(0));
            }
            commit_pair(be, o->dst, 1, R2, R3);
            break;
        }
        case IRO_SMULH: case IRO_UMULH: case IRO_UDIV: case IRO_SDIV: {
            const void *fn;
            if (o->op == IRO_SMULH)      fn = (const void *)h_smulh;
            else if (o->op == IRO_UMULH) fn = (const void *)h_umulh;
            else if (o->op == IRO_UDIV)
                fn = w ? (const void *)h_udiv64 : (const void *)h_udiv32;
            else
                fn = w ? (const void *)h_sdiv64 : (const void *)h_sdiv32;
            /* r1:r0 = a, r3:r2 = b */
            int bl = src_hv(be, HV(o->b, 0), R2);
            mov_rr(e, R2, bl);
            int bh = src_hv(be, HV(o->b, 1), R3);
            mov_rr(e, R3, bh);
            int al = src_hv(be, HV(o->a, 0), R0);
            int ah = src_hv(be, HV(o->a, 1), R1);
            mov_rr(e, R1, ah);
            mov_rr(e, R0, al);
            call_abs(be, fn);
            commit_pair(be, o->dst, (o->op == IRO_SMULH || o->op == IRO_UMULH)
                                        ? 1 : w, R0, R1);
            break;
        }

        case IRO_CLZ: {
            int al = src_hv(be, HV(o->a, 0), R0);
            if (!w) {
                clz(e, R2, al);
                commit_pair(be, o->dst, 0, R2, R3);
                break;
            }
            int ah = src_hv(be, HV(o->a, 1), R1);
            /* clz(hi), and if the high word was empty, 32 + clz(lo). */
            clz(e, R2, ah);
            dp_i(e, CC_AL, OP_CMP, 1, 0, ah, dp_imm(0));
            clz(e, R3, al);
            dp_i(e, CC_EQ, OP_ADD, 0, R2, R3, dp_imm(32));
            commit_pair(be, o->dst, 0, R2, R3);
            break;
        }
        case IRO_REV64: case IRO_REV32: {
            if (o->op == IRO_REV32) {
                Pair p = prime_pair(be, o->dst, o->a, 0);
                rev(e, p.lo, p.lo);
                finish32(be, o->dst, 0);
                break;
            }
            int al = src_hv(be, HV(o->a, 0), R0);
            int ah = src_hv(be, HV(o->a, 1), R1);
            rev(e, R2, ah);                       /* and swap the words */
            rev(e, R3, al);
            commit_pair(be, o->dst, 1, R2, R3);
            break;
        }
        case IRO_RBIT: {
            int al = src_hv(be, HV(o->a, 0), R0);
            if (!w) {
                rbit(e, R2, al);
                commit_pair(be, o->dst, 0, R2, R3);
                break;
            }
            int ah = src_hv(be, HV(o->a, 1), R1);
            rbit(e, R2, ah);                      /* bit-reverse and swap */
            rbit(e, R3, al);
            commit_pair(be, o->dst, 1, R2, R3);
            break;
        }

        case IRO_CSEL: case IRO_CSINC: case IRO_CSINV: case IRO_CSNEG: {
            /* f(b) is computed UNPREDICATED first, because it needs the host
             * flags itself — the 64-bit increment and negate are carry chains —
             * and a predicated flag-setter would destroy the very condition the
             * next predicated instruction tests. Only then are the guest flags
             * loaded and `a` selected with predicated moves. Going through
             * scratch also means a destination that is also a source cannot
             * lose its value before it has been read. */
            int cc = guest_cond(o->cc);
            if (cc != CC_AL) {
                int blo = src_hv(be, HV(o->b, 0), R0);
                int bhi = w ? src_hv(be, HV(o->b, 1), R1) : R1;
                switch (o->op) {
                    case IRO_CSINV:
                        dp_r(e, CC_AL, OP_MVN, 0, R2, 0, blo, SH_LSL, 0);
                        if (w) dp_r(e, CC_AL, OP_MVN, 0, R3, 0, bhi, SH_LSL, 0);
                        break;
                    case IRO_CSNEG:           /* rsbs/rsc negates the pair */
                        dp_i(e, CC_AL, OP_RSB, w ? 1 : 0, R2, blo, dp_imm(0));
                        if (w) dp_i(e, CC_AL, OP_RSC, 0, R3, bhi, dp_imm(0));
                        break;
                    case IRO_CSINC:
                        dp_i(e, CC_AL, OP_ADD, w ? 1 : 0, R2, blo, dp_imm(1));
                        if (w) dp_i(e, CC_AL, OP_ADC, 0, R3, bhi, dp_imm(0));
                        break;
                    default:                  /* IRO_CSEL */
                        mov_rr(e, R2, blo);
                        if (w) mov_rr(e, R3, bhi);
                        break;
                }
                cond_load(be);                /* msr APSR: the guest condition */
            }
            {   /* select `a` where the condition holds (unconditional if AL) */
                int alo = src_hv(be, HV(o->a, 0), R0);
                dp_r(e, cc, OP_MOV, 0, R2, 0, alo, SH_LSL, 0);
                if (w) {
                    int ahi = src_hv(be, HV(o->a, 1), R1);
                    dp_r(e, cc, OP_MOV, 0, R3, 0, ahi, SH_LSL, 0);
                }
            }
            commit_pair(be, o->dst, w, R2, R3);
            break;
        }

        case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI: {
            int is_imm = (o->op == IRO_CCMPI || o->op == IRO_CCMNI);
            int is_cmn = (o->op == IRO_CCMNR || o->op == IRO_CCMNI);
            int cc = guest_cond(o->cc);
            cond_load(be);
            u8 *els = NULL, *end = NULL;
            if (cc != CC_AL) els = b_fwd(e, cond_inv(cc));
            /* The compare arm computes into scratch only; both arms leave the
             * allocator exactly as they found it. */
            int oplo = is_cmn ? OP_ADD : OP_SUB;
            int ophi = is_cmn ? OP_ADC : OP_SBC;
            int alo = src_hv(be, HV(o->a, 0), R0);
            if (is_imm) alu_ri_s(e, oplo, w ? 1 : 1, R2, alo, (u32)o->imm, R1);
            else {
                int blo = src_hv(be, HV(o->b, 0), R1);
                dp_r(e, CC_AL, oplo, 1, R2, alo, blo, SH_LSL, 0);
            }
            if (w) {
                int ahi = src_hv(be, HV(o->a, 1), R0);
                if (is_imm)
                    alu_ri_s(e, ophi, 1, R3, ahi, (u32)(o->imm >> 32), R1);
                else {
                    int bhi = src_hv(be, HV(o->b, 1), R1);
                    dp_r(e, CC_AL, ophi, 1, R3, ahi, bhi, SH_LSL, 0);
                }
            }
            emit_flags(be, FK_ARITH, w, R2, R3);
            if (cc != CC_AL) {
                end = b_fwd(e, CC_AL);
                fwd_here(e, els);
                mov_ri(e, R0, o->aux);
                st_r(e, R0, RCPU, OFF_NZCV);
                fwd_here(e, end);
            }
            break;
        }

        /* ---- terminals ---- */
        case IRO_JMP:
            sync_all(be);
            exit_stub(be, 0, o->imm, o->icnt);
            break;
        case IRO_BCOND: {
            sync_all(be);
            int cc = guest_cond(o->cc);
            cond_load(be);
            const IROp *nxt = &ir->ops[i + 1];
            if (cc == CC_AL) { exit_stub(be, 0, o->imm, o->icnt); return 2; }
            u8 *taken = b_fwd(e, cc);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_CBZ: case IRO_CBNZ: {
            sync_all(be);
            int lo = src_hv(be, HV(o->a, 0), R0);
            if (w) {
                int hi = src_hv(be, HV(o->a, 1), R1);
                dp_r(e, CC_AL, OP_ORR, 1, R2, lo, hi, SH_LSL, 0);
            } else {
                dp_i(e, CC_AL, OP_CMP, 1, 0, lo, dp_imm(0));
            }
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = b_fwd(e, o->op == IRO_CBZ ? CC_EQ : CC_NE);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_TBZ: case IRO_TBNZ: {
            sync_all(be);
            unsigned bit = o->cc;
            int r = src_hv(be, HV(o->a, bit >= 32), R0);
            alu_ri_s(e, OP_TST, 1, 0, r, 1u << (bit & 31), R1);
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = b_fwd(e, o->op == IRO_TBZ ? CC_EQ : CC_NE);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_JMPIND: {
            sync_all(be);
            icount_add(be, o->icnt);              /* first: it needs r0/r1 as
                                                   * scratch, and the target pc
                                                   * is wanted in them after */
            int lo = src_hv(be, HV(o->a, 0), R0);
            mov_rr(e, R0, lo);
            int hi = src_hv(be, HV(o->a, 1), R1);
            mov_rr(e, R1, hi);
            st_r(e, R0, RCPU, OFF_PC);
            st_r(e, R1, RCPU, OFF_PC + 4);
            /* entry = &env->jcache[(pc >> 2) & (JIT_JC_SIZE - 1)] */
            ubfx(e, R2, R0, 2, JIT_JC_BITS);
            dp_r(e, CC_AL, OP_ADD, 0, R2, RENV, R2, SH_LSL, 4);
            s32 jc = (s32)offsetof(JitEnv, jcache);
            ld_r(e, R3, R2, jc);
            dp_r(e, CC_AL, OP_CMP, 1, 0, R3, R0, SH_LSL, 0);
            ls_i(e, 1, 0, R3, R2, jc + 4);        /* ldr (unconditional) */
            dp_r(e, CC_EQ, OP_CMP, 1, 0, R3, R1, SH_LSL, 0);
            u8 *miss = b_fwd(e, CC_NE);
            ld_r(e, R3, R2, jc + 8);
            bx_r(e, R3);
            fwd_here(e, miss);
            mov_ri(e, R0, JIT_EXIT_NONE);
            b_to(e, CC_AL, be->env->epilogue_rx);
            break;
        }

        case IRO_LD: case IRO_ST: case IRO_LDV: case IRO_STV:
            emit_mem(be, o);
            break;
        case IRO_ATOMIC:
            emit_exec1(be, o->imm2pc, (u32)o->imm, 0, o->icnt);
            break;
        case IRO_CALL1:
            emit_exec1(be, o->imm, o->aux, o->w, o->icnt);
            break;

        case IRO_CPULD: {
            int dlo = def_hv(be, HV(o->dst, 0));
            ra_lock(be, dlo);
            ld_r(e, dlo, RCPU, (s32)o->imm);
            ld_r(e, def_hv(be, HV(o->dst, 1)), RCPU, (s32)o->imm + 4);
            break;
        }
        case IRO_CPUST: {
            int lo = src_hv(be, HV(o->a, 0), R0);
            st_r(e, lo, RCPU, (s32)o->imm);
            int hi = src_hv(be, HV(o->a, 1), R0);
            st_r(e, hi, RCPU, (s32)o->imm + 4);
            break;
        }
        case IRO_FENCE:
            ei(e, 0xF57FF05Fu);                   /* dmb sy */
            break;

        default:
            /* Unreached: the frontend only emits the ops above, and be_vop_ok
             * declines every IRO_VOP class on this host. */
            e->overflow = 1;
            break;
    }
    return 1;
}

/* ---- chaining ---- */

void be_patch_chain(JitEnv *env, JBlock *b, int slot, const u8 *target_rx) {
    u8 *site_rw = env->cache_rw + (b->code - env->cache_rx) + b->exit_off[slot];
    const u8 *site_rx = b->code + b->exit_off[slot];
    s32 rel = (s32)(target_rx - (site_rx + 8));
    u32 w = AL | (0xAu << 24) | (((u32)rel >> 2) & 0xFFFFFFu);
    memcpy(site_rw, &w, 4);
    b->patched[slot] = 1;
}

void be_unpatch_chain(JitEnv *env, JBlock *b, int slot) {
    u8 *site_rw = env->cache_rw + (b->code - env->cache_rx) + b->exit_off[slot];
    memcpy(site_rw, &b->stub_word0[slot], 4);
    b->patched[slot] = 0;
}

int be_vop_ok(unsigned vclass, u32 insn) {
    (void)vclass; (void)insn;
    return 0;                             /* no FP/SIMD tier on this host yet */
}

void be_flush_icache(const u8 *rx, const u8 *rw, size_t len) {
    __builtin___clear_cache((char *)(uintptr_t)rx, (char *)(uintptr_t)rx + len);
    if (rw != rx)
        __builtin___clear_cache((char *)(uintptr_t)rw, (char *)(uintptr_t)rw + len);
}

#endif /* __arm__ */
