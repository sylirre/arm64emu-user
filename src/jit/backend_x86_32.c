/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* i686 (x86-32) code generator — the first of the ILP32 backends.
 *
 * Everything structural is the 64-bit backends' design; what is new here is
 * that a guest 64-bit value does not fit a host register. Conventions in
 * generated code:
 *
 *   ebp            = CPU*, loaded once by the enter thunk
 *   eax, edx       = emitter scratch, never allocated (also the mul/div pair
 *                    and the edx:eax return pair of a helper)
 *   ebx, esi, edi, ecx = allocatable pool; ecx last, because it is the only
 *                    one a C helper call does not preserve
 *   esp            = a FIXED frame (see FR_*), never moved by generated code
 *
 * The JitEnv is not pinned to a register at all: it is a `__thread` object and
 * generated code is per-thread, so its address is a translate-time constant and
 * x86 addresses it as an absolute displacement for free. Helpers are called by
 * direct `call rel32` for the same reason a 32-bit host makes easy — every
 * target is in reach.
 *
 * **Register pairs.** Guest register halves are the unit of allocation: vreg v
 * contributes halves HV(v,0) (low word) and HV(v,1) (high word), 72 in all,
 * each independently resident in a host register, live only in its CPU-struct
 * home, or *known zero* with a stale home (what a 32-bit-wide guest write
 * leaves behind, which is most of them — so the common case costs no register
 * and no store until something reads it). A 64-bit guest op becomes the
 * host's add/adc, sub/sbb, per-half logicals, and shld/shrd funnels; the few
 * that have no short pair form (64-bit divide, the high half of a 64x64
 * multiply, RBIT, variable 64-bit shifts) call a small C helper in this file.
 *
 * Only *destinations* are allocated. A source is read wherever its value
 * already is — an allocated register, its memory home, or an immediate zero —
 * because x86 takes a memory operand on the same instruction, so `add lo,
 * [ebp+x1]` needs no register at all. That is what makes a four-register pool
 * workable: pressure is bounded by the number of live definitions, not by the
 * operand count.
 *
 * **Guest NZCV** is materialized into `c->nzcv` at every S-op (this backend has
 * no lazy-flag window yet). The recipe captures the host flags with `setcc`
 * into four frame bytes and folds them into the architectural word with one
 * multiply; a 64-bit Z, which the host's high-half flag does not describe, is
 * derived from both result halves.
 *
 * Not inlined here: everything FP/SIMD (be_vop_ok declines the lot, so the
 * frontend keeps its exec_fpsimd helper calls), the atomics, and the memory
 * accesses, which go through the same jit_ld/jit_st/jit_ldv/jit_stv helpers
 * the 64-bit backends fall back to. */
#include "ir.h"

#ifdef __i386__

#include <stdlib.h>
#include <string.h>

_Static_assert(A64_HOST_ILP32, "this backend is the ILP32 one");
/* Half indices assume a little-endian host: HV(v,0) is at the low address of
 * the guest register's home. i386 is always little-endian; the assert is here
 * so a future big-endian ILP32 port has to look at this. */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "LE host assumed");

enum { EAX = 0, ECX, EDX, EBX, ESP_, EBP, ESI, EDI, HREG_N };

/* Allocatable pool, preference order: the callee-saved registers first so ecx
 * — the one a helper call clobbers — is handed out last and reloaded least. */
static const u8 pool[] = { EBX, ESI, EDI, ECX };
#define POOL_N ((int)sizeof pool)

/* host condition codes (the low nibble of the jcc/setcc/cmovcc opcode) */
enum { CC_O = 0, CC_NO, CC_B, CC_AE, CC_E, CC_NE, CC_BE, CC_A,
       CC_S, CC_NS, CC_P, CC_NP, CC_L, CC_GE, CC_LE, CC_G,
       CC_ALWAYS = 16, CC_NEVER = 17 };

/* ALU group indices: the imm form is 81 /n, "reg <- reg op rm" is 0x03 + 8n,
 * "rm <- rm op reg" is 0x01 + 8n. */
enum { AL_ADD = 0, AL_OR, AL_ADC, AL_SBB, AL_AND, AL_SUB, AL_XOR, AL_CMP };
/* shift/rotate group indices for C1 /n and D3 /n */
enum { SH_ROL = 0, SH_ROR, SH_SHL = 4, SH_SHR, SH_SAR = 7 };

#define OFF_X(n)   ((s32)(offsetof(CPU, x) + 8 * (n)))
#define OFF_SP     ((s32)offsetof(CPU, sp_el))
#define OFF_PC     ((s32)offsetof(CPU, pc))
#define OFF_NZCV   ((s32)offsetof(CPU, nzcv))
#define OFF_ICOUNT ((s32)offsetof(CPU, icount))
#define OFF_V(n)   ((s32)(offsetof(CPU, v) + 16 * (n)))

/* ---- the fixed frame ----
 * The enter thunk carves it out once and generated code never moves esp, which
 * buys three things: a call site is 16-byte aligned by construction (the i386
 * psABI wants it and the helpers are SSE-compiled C), scratch memory costs a
 * 4-byte `[esp+disp8]` operand rather than a register, and a host bus fault
 * inside an inline access can resume at a slow path with the frame intact.
 *   [esp +  0 .. 31]  outgoing call arguments (8 dwords; jit_st needs all 8)
 *   [esp + 32 .. 35]  the NZCV capture bytes, V C Z N in that order
 *   [esp + 36 .. 67]  eight scratch dwords
 * 76 is the smallest size >= 68 that is 12 mod 16, which is exactly what turns
 * the thunk's post-push esp back into 0 mod 16. */
#define FR_ARG(n)  (4 * (n))
#define FR_FLAGS   32
#define FR_S(n)    (36 + 4 * (n))
#define FR_SIZE    76
_Static_assert(FR_SIZE % 16 == 12, "frame size must realign esp at a call");
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

/* A memory operand. base/index are host registers or -1; scale is a log2. */
typedef struct { s8 base, index; u8 scale; s32 disp; } Mem;
static Mem M_ebp(s32 d)  { Mem m = { EBP,  -1, 0, d }; return m; }
static Mem M_esp(s32 d)  { Mem m = { ESP_, -1, 0, d }; return m; }
static Mem M_abs(u32 a)  { Mem m = { -1,   -1, 0, (s32)a }; return m; }
/* [abs + idx << scale]: the SIB form with no base, which is how this backend
 * reaches the D-TLB and the jump cache without pinning a register for them. */
static Mem M_absx(u32 a, int idx, u8 scale) {
    Mem m = { -1, (s8)idx, scale, (s32)a };
    return m;
}
static Mem M_reg(int r, s32 d) { Mem m = { (s8)r, -1, 0, d }; return m; }

/* An r/m operand: either a host register or a memory reference. */
typedef struct { u8 is_reg; u8 reg; Mem m; } RM;
static RM RM_R(int r) { RM x; x.is_reg = 1; x.reg = (u8)r; x.m = M_abs(0); return x; }
static RM RM_M(Mem m) { RM x; x.is_reg = 0; x.reg = 0; x.m = m; return x; }

static void modrm_rm(Emit *e, int reg, RM rm) {
    if (rm.is_reg) {
        e8(e, (u8)(0xC0 | ((reg & 7) << 3) | (rm.reg & 7)));
        return;
    }
    Mem m = rm.m;
    if (m.base < 0) {                            /* absolute, maybe indexed */
        if (m.index < 0) {
            e8(e, (u8)(((reg & 7) << 3) | 5));   /* mod=00 rm=101: disp32 */
        } else {
            e8(e, (u8)(((reg & 7) << 3) | 4));   /* mod=00 rm=100: SIB */
            e8(e, (u8)((m.scale << 6) | ((m.index & 7) << 3) | 5));
        }
        e32(e, (u32)m.disp);
        return;
    }
    int sib = (m.index >= 0) || (m.base == ESP_);
    int mod = (m.disp == 0 && m.base != EBP) ? 0
            : (m.disp >= -128 && m.disp <= 127) ? 1 : 2;
    e8(e, (u8)((mod << 6) | ((reg & 7) << 3) | (sib ? 4 : (m.base & 7))));
    if (sib)
        e8(e, (u8)((m.scale << 6) |
                   (((m.index < 0 ? ESP_ : m.index) & 7) << 3) | (m.base & 7)));
    if (mod == 1) e8(e, (u8)m.disp);
    else if (mod == 2) e32(e, (u32)m.disp);
}

static void op_rm(Emit *e, u8 opc, int reg, RM rm) {
    e8(e, opc);
    modrm_rm(e, reg, rm);
}
static void op0f_rm(Emit *e, u8 opc, int reg, RM rm) {
    e8(e, 0x0F); e8(e, opc);
    modrm_rm(e, reg, rm);
}
static void op_rr(Emit *e, u8 opc, int reg, int rm) { op_rm(e, opc, reg, RM_R(rm)); }

/* mov */
static void mov_ri(Emit *e, int reg, u32 imm) {
    e8(e, (u8)(0xB8 | (reg & 7)));
    e32(e, imm);
}
static void mov_rr(Emit *e, int dst, int src) {
    if (dst != src) op_rr(e, 0x8B, dst, src);
}
static void ld_r(Emit *e, int dst, Mem m)  { op_rm(e, 0x8B, dst, RM_M(m)); }
static void st_r(Emit *e, int src, Mem m)  { op_rm(e, 0x89, src, RM_M(m)); }
static void mov_mi(Emit *e, Mem m, u32 imm) {         /* mov dword [m], imm32 */
    op_rm(e, 0xC7, 0, RM_M(m));
    e32(e, imm);
}
static void mov_mi16(Emit *e, Mem m, u16 imm) {       /* mov word [m], imm16 */
    e8(e, 0x66);
    op_rm(e, 0xC7, 0, RM_M(m));
    e8(e, (u8)imm); e8(e, (u8)(imm >> 8));
}

/* ALU with an immediate; the sign-extended imm8 form where it fits. */
static void alu_rmi(Emit *e, int n, RM rm, u32 imm) {
    if ((u32)(s32)(s8)imm == imm) {
        op_rm(e, 0x83, n, rm);
        e8(e, (u8)imm);
    } else {
        op_rm(e, 0x81, n, rm);
        e32(e, imm);
    }
}
static void alu_ri(Emit *e, int n, int reg, u32 imm) { alu_rmi(e, n, RM_R(reg), imm); }
/* reg = reg OP rm */
static void alu_r_rm(Emit *e, int n, int reg, RM rm) {
    op_rm(e, (u8)(0x03 + 8 * n), reg, rm);
}
static void shift_ri(Emit *e, int n, int reg, unsigned amt) {
    if (!amt) return;
    if (amt == 1) { op_rr(e, 0xD1, n, reg); return; }
    op_rr(e, 0xC1, n, reg);
    e8(e, (u8)amt);
}
static void shift_cl(Emit *e, int n, int reg) { op_rr(e, 0xD3, n, reg); }
/* shld/shrd dst_reg, src_reg, imm8 */
static void shld_ri(Emit *e, int dst, int src, unsigned amt) {
    op0f_rm(e, 0xA4, src, RM_R(dst));
    e8(e, (u8)amt);
}
static void shrd_ri(Emit *e, int dst, int src, unsigned amt) {
    op0f_rm(e, 0xAC, src, RM_R(dst));
    e8(e, (u8)amt);
}
static void unop_rm(Emit *e, int n, RM rm) { op_rm(e, 0xF7, n, rm); }  /* not/neg/mul/div */
static void setcc_m(Emit *e, int cc, Mem m) { op0f_rm(e, (u8)(0x90 | cc), 0, RM_M(m)); }
static void test_rmi(Emit *e, RM rm, u32 imm) {
    op_rm(e, 0xF7, 0, rm);
    e32(e, imm);
}

static void jmp_to(Emit *e, const u8 *target) {
    e8(e, 0xE9);
    e32(e, (u32)(target - (e->rx + 4)));
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
/* call a C function by its real address: on a 32-bit host every target is
 * within rel32 reach of the code cache, so no thunk or pointer load. */
static void call_c(Emit *e, const void *fn) {
    e8(e, 0xE8);
    e32(e, (u32)((const u8 *)fn - (e->rx + 4)));
}

static u32 env_abs(BE *be, size_t off) {
    return (u32)(uintptr_t)be->env + (u32)off;
}

/* ---- register allocator (over guest halves) ---- */

/* Memory home of a half. VREG_ZERO has none — it reads as zero and its writes
 * are discarded, so it is never mapped, never dirty and never synced. */
static Mem hv_home(BE *be, int hv) {
    int v = hv >> 1, hi = hv & 1;
    if (v < 31)       return M_ebp(OFF_X(v) + 4 * hi);
    if (v == VREG_SP) return M_ebp(OFF_SP + 4 * hi);
    return M_abs(env_abs(be, offsetof(JitEnv, tmp_spill) +
                             8 * (size_t)(v - VREG_TMP0) + 4 * (size_t)hi));
}

static void ra_unmap(BE *be, int hv) {
    int h = be->h[hv];
    if (h >= 0) { be->r2v[h] = NHV; be->h[hv] = -1; be->dirty[hv] = 0; }
}

/* Make a host register free: write its half's home if the copy there is stale,
 * then drop the mapping. */
static void ra_evict(BE *be, int h) {
    int hv = be->r2v[h];
    if (hv >= NHV) return;
    if (be->dirty[hv]) st_r(be->e, h, hv_home(be, hv));
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
    if (best < 0) {
        /* Every pool register locked by the op being emitted. No emission
         * sequence here needs more than three at once, so this is a bug in
         * one of them; fail loudly (translate() retries, then gives up on the
         * JIT) rather than silently returning a register in use. */
        be->e->overflow = 1;
        return EAX;
    }
    ra_evict(be, best);
    return best;
}

static void ra_lock(BE *be, int h) { be->locked[h] = 1; }
static void ra_unlock_all(BE *be) { memset(be->locked, 0, sizeof be->locked); }

/* Register holding a half's current value. Never called for VREG_ZERO: its
 * only caller, mod_hv, answers that case from scratch. */
static int use_hv(BE *be, int hv) {
    int h = be->h[hv];
    if (h < 0) {
        h = ra_alloc(be);
        if (be->zero[hv]) {
            mov_ri(be->e, h, 0);                 /* home is stale: keep dirty */
            be->zero[hv] = 0;
            be->dirty[hv] = 1;
        } else {
            ld_r(be->e, h, hv_home(be, hv));
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
    if ((hv >> 1) == VREG_ZERO) return (hv & 1) ? EDX : EAX;
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

/* Register holding a half's value, about to be modified in place. */
static int mod_hv(BE *be, int hv) {
    if ((hv >> 1) == VREG_ZERO) return (hv & 1) ? EDX : EAX;
    int h = use_hv(be, hv);
    be->dirty[hv] = 1;
    return h;
}

/* Record that a half is zero without emitting anything: what every 32-bit-wide
 * guest write leaves in the upper half. The home is left stale; sync_all
 * stores the constant, and use_hv materializes it. */
static void set_zero_hv(BE *be, int hv) {
    if ((hv >> 1) == VREG_ZERO) return;
    ra_unmap(be, hv);                            /* value is overwritten */
    be->zero[hv] = 1;
}

/* A source operand: wherever the value already is. Emits nothing. */
enum { S_RM, S_IMM };
typedef struct { u8 kind; RM rm; u32 imm; } Src;
static Src src_hv(BE *be, int hv) {
    Src s;
    if ((hv >> 1) == VREG_ZERO || be->zero[hv]) {
        s.kind = S_IMM; s.imm = 0; s.rm = RM_R(EAX);
        return s;
    }
    s.kind = S_RM;
    s.imm = 0;
    int h = be->h[hv];
    s.rm = (h >= 0) ? RM_R(h) : RM_M(hv_home(be, hv));
    if (h >= 0) be->lru[h] = ++be->stamp;
    return s;
}
/* The same, but usable where the instruction has no immediate form: an
 * immediate source is materialized into `scratch` (eax or edx). */
static RM src_rm(BE *be, int hv, int scratch) {
    Src s = src_hv(be, hv);
    if (s.kind == S_IMM) {
        mov_ri(be->e, scratch, s.imm);
        return RM_R(scratch);
    }
    return s.rm;
}

static void mov_rs(Emit *e, int dst, Src s) {
    if (s.kind == S_IMM) mov_ri(e, dst, s.imm);
    else if (s.rm.is_reg) mov_rr(e, dst, s.rm.reg);
    else op_rm(e, 0x8B, dst, s.rm);
}
static void alu_rs(Emit *e, int n, int dst, Src s) {
    if (s.kind == S_IMM) alu_ri(e, n, dst, s.imm);
    else alu_r_rm(e, n, dst, s.rm);
}

/* Make every home current. Flag-safe (moves and immediate stores only), which
 * matters at exits: the guest flags may be the only thing still live. */
static void sync_all(BE *be) {
    for (int hv = 0; hv < NHV; hv++) {
        if (be->zero[hv]) {
            mov_mi(be->e, hv_home(be, hv), 0);
            be->zero[hv] = 0;
        } else if (be->h[hv] >= 0 && be->dirty[hv]) {
            st_r(be->e, be->h[hv], hv_home(be, hv));
            be->dirty[hv] = 0;
        }
    }
}
static void inval_all(BE *be) {
    for (int hv = 0; hv < NHV; hv++) ra_unmap(be, hv);
}
static void inval_v(BE *be, int v) {             /* one guest register's pair */
    if (v == VREG_ZERO) return;
    ra_unmap(be, HV(v, 0));
    ra_unmap(be, HV(v, 1));
    be->zero[HV(v, 0)] = be->zero[HV(v, 1)] = 0;
}
/* A C call keeps ebx/esi/edi but not ecx: reload whatever lived there. Runs
 * after sync_all, so every mapping is clean and the home is the truth.
 *
 * This must be the FIRST thing emitted after a call and before anything that
 * defines a register: a def can hand out ecx for the call's own result, and a
 * reload after that would overwrite it with the destination's stale home. */
static void reload_clobbered(BE *be) {
    int hv = be->r2v[ECX];
    if (hv < NHV) ld_r(be->e, ECX, hv_home(be, hv));
}
/* Free ecx for use as a scratch/count register. */
static void free_ecx(BE *be) { ra_evict(be, ECX); }

/* ---- guest flags ----
 * No lazy window yet: an S-op writes the architectural word. The four bits are
 * captured with setcc into consecutive frame bytes (V C Z N) and folded with a
 * single multiply — 0x10204080 = 2^28|2^21|2^14|2^7 shifts byte 0 to bit 28,
 * byte 1 to 29, byte 2 to 30 and byte 3 to 31, and every cross term lands
 * outside the 0xF0000000 mask. */
enum { FK_ADD, FK_SUB, FK_LOGIC };

static void emit_flags(BE *be, int kind, int w, int lo, int hi) {
    Emit *e = be->e;
    if (kind == FK_LOGIC) {
        mov_mi16(e, M_esp(FR_FLAGS), 0);         /* ARM: C and V read zero */
    } else {
        setcc_m(e, CC_O, M_esp(FR_FLAGS + 0));   /* V */
        /* ARM C is the carry-out of an addition and the NOT-borrow of a
         * subtraction; x86 CF is the carry/borrow itself. */
        setcc_m(e, kind == FK_SUB ? CC_AE : CC_B, M_esp(FR_FLAGS + 1));
    }
    setcc_m(e, CC_S, M_esp(FR_FLAGS + 3));       /* N */
    if (w) {
        /* The high half's ZF describes only that half. setcc does not touch
         * the flags, so the pair can be folded now that N/C/V are captured. */
        mov_rr(e, EAX, lo);
        op_rr(e, 0x0B, EAX, hi);                 /* or eax, hi */
    }
    setcc_m(e, CC_E, M_esp(FR_FLAGS + 2));       /* Z */
    e8(e, 0x69);                                 /* imul eax, [flags], imm32 */
    modrm_rm(e, EAX, RM_M(M_esp(FR_FLAGS)));
    e32(e, 0x10204080u);
    alu_ri(e, AL_AND, EAX, 0xF0000000u);
    st_r(e, EAX, M_ebp(OFF_NZCV));
}

/* Set the host flags so `cc` tests guest condition `cond`, reading c->nzcv.
 * Clobbers eax and edx. */
static int cond_setup(BE *be, unsigned cond) {
    Emit *e = be->e;
    cond &= 15;
    if (cond >= 14) return CC_ALWAYS;            /* AL / NV */
    ld_r(e, EAX, M_ebp(OFF_NZCV));
    switch (cond) {
        case 0: case 1:                          /* EQ / NE: Z */
            test_rmi(e, RM_R(EAX), PS_Z);
            return cond == 0 ? CC_NE : CC_E;
        case 2: case 3:                          /* HS / LO: C */
            test_rmi(e, RM_R(EAX), PS_C);
            return cond == 2 ? CC_NE : CC_E;
        case 4: case 5:                          /* MI / PL: N */
            test_rmi(e, RM_R(EAX), PS_N);
            return cond == 4 ? CC_NE : CC_E;
        case 6: case 7:                          /* VS / VC: V */
            test_rmi(e, RM_R(EAX), PS_V);
            return cond == 6 ? CC_NE : CC_E;
        case 8: case 9:                          /* HI / LS: C && !Z */
            mov_rr(e, EDX, EAX);
            alu_ri(e, AL_AND, EDX, PS_C | PS_Z);
            alu_ri(e, AL_CMP, EDX, PS_C);
            return cond == 8 ? CC_E : CC_NE;
        case 10: case 11:                        /* GE / LT: N == V */
            mov_rr(e, EDX, EAX);
            shift_ri(e, SH_SHR, EDX, 3);         /* N (31) down to 28 */
            op_rr(e, 0x33, EDX, EAX);            /* xor edx, eax */
            test_rmi(e, RM_R(EDX), PS_V);
            return cond == 10 ? CC_E : CC_NE;
        default: {                               /* GT / LE: !Z && N == V */
            mov_rr(e, EDX, EAX);
            shift_ri(e, SH_SHR, EDX, 3);
            op_rr(e, 0x33, EDX, EAX);
            alu_ri(e, AL_AND, EDX, PS_V);        /* (N^V) << 28 */
            alu_ri(e, AL_AND, EAX, PS_Z);
            op_rr(e, 0x0B, EDX, EAX);            /* or edx, eax */
            return cond == 12 ? CC_E : CC_NE;    /* zero => GT */
        }
    }
}

/* ---- outgoing arguments and helper calls ---- */

static void arg_cpu(BE *be, int slot) { st_r(be->e, EBP, M_esp(FR_ARG(slot))); }
static void arg_imm(BE *be, int slot, u32 v) { mov_mi(be->e, M_esp(FR_ARG(slot)), v); }
static void arg_imm64(BE *be, int slot, u64 v) {
    arg_imm(be, slot, (u32)v);
    arg_imm(be, slot + 1, (u32)(v >> 32));
}
/* A guest register pair as a u64 argument. */
static void arg_hv64(BE *be, int slot, int v) {
    for (int half = 0; half < 2; half++) {
        Src s = src_hv(be, HV(v, half));
        if (s.kind == S_IMM) { arg_imm(be, slot + half, s.imm); continue; }
        mov_rs(be->e, EAX, s);
        st_r(be->e, EAX, M_esp(FR_ARG(slot + half)));
    }
}
/* A value already in eax (low) / edx (high). */
static void arg_pair_regs(BE *be, int slot, int lo, int hi) {
    st_r(be->e, lo, M_esp(FR_ARG(slot)));
    st_r(be->e, hi, M_esp(FR_ARG(slot + 1)));
}

/* ---- pure C helpers for the ops with no short pair form ----
 * Called with the guest's own semantics baked in, so the emitter stays free of
 * special cases. All are leaf functions of their arguments: they touch no
 * emulator state, so a call needs no guest-state sync, only ecx freed. */

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
/* High 64 bits of a 64x64 product. No __int128 on a 32-bit target, so it is
 * the four-partial-product schoolbook sum; the signed form corrects the
 * unsigned one by the standard two's-complement adjustment. */
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
static u64 h_rbit(u64 v, u32 w) {
    u64 r = 0;
    unsigned bits = w ? 64 : 32;
    for (unsigned i = 0; i < bits; i++)
        if ((v >> i) & 1) r |= 1ULL << (bits - 1 - i);
    return r;
}

/* ---- exits ---- */

static void icount_add(BE *be, u32 n) {
    if (!n) return;                              /* clobbers flags: callers
                                                  * are past their branches */
    alu_rmi(be->e, AL_ADD, RM_M(M_ebp(OFF_ICOUNT)), n);
    alu_rmi(be->e, AL_ADC, RM_M(M_ebp(OFF_ICOUNT + 4)), 0);
}

/* The two immediate stores of c->pc, always in the disp32 form: the first is
 * the chain patch site, and be_unpatch_chain rebuilds its bytes from this
 * fixed encoding, so the length must not depend on the offset. */
static void store_pc_imm(Emit *e, u64 pc) {
    for (int half = 0; half < 2; half++) {
        e8(e, 0xC7);
        e8(e, (u8)(0x80 | EBP));                 /* mod=10 rm=101: disp32 */
        e32(e, (u32)(OFF_PC + 4 * half));
        e32(e, half ? (u32)(pc >> 32) : (u32)pc);
    }
}
#define PC_STORE_BYTES 10

static void exit_plain(BE *be, u32 icnt) {       /* c->pc already correct */
    icount_add(be, icnt);
    mov_ri(be->e, EAX, JIT_EXIT_NONE);
    jmp_to(be->e, be->env->epilogue_rx);
}

/* Chainable exit: [icount][patch site: store pc, return the exit id]. */
static void exit_stub(BE *be, int slot, u64 target_pc, u32 icnt) {
    Emit *e = be->e;
    JBlock *b = be->b;
    icount_add(be, icnt);
    b->exit_pc[slot] = target_pc;
    b->exit_off[slot] = (u32)(e->rx - b->code);
    store_pc_imm(e, target_pc);
    mov_ri(e, EAX, ((u32)(b - be->env->arena) << 1) | (u32)slot);
    jmp_to(e, be->env->epilogue_rx);
}

/* ---- thunks ---- */

int be_available(void) { return 1; }

void be_emit_thunks(Emit *e, JitEnv *env) {
    env->enter = (u32 (*)(JitEnv *, const u8 *))(uintptr_t)e->rx;
    e8(e, 0x55);                                 /* push ebp */
    e8(e, 0x53);                                 /* push ebx */
    e8(e, 0x56);                                 /* push esi */
    e8(e, 0x57);                                 /* push edi */
    ld_r(e, EAX, M_esp(20));                     /* env */
    ld_r(e, ECX, M_esp(24));                     /* code_rx */
    ld_r(e, EBP, M_reg(EAX, (s32)offsetof(JitEnv, c)));
    alu_ri(e, AL_SUB, ESP_, FR_SIZE);            /* esp now 0 mod 16 */
    op_rm(e, 0xFF, 4, RM_R(ECX));                /* jmp ecx */

    env->epilogue_rx = e->rx;
    alu_ri(e, AL_ADD, ESP_, FR_SIZE);
    e8(e, 0x5F);                                 /* pop edi */
    e8(e, 0x5E);                                 /* pop esi */
    e8(e, 0x5B);                                 /* pop ebx */
    e8(e, 0x5D);                                 /* pop ebp */
    e8(e, 0xC3);                                 /* ret */
}

/* ---- pair recipes ---- */

typedef struct { int lo, hi; } Pair;

/* Destination registers primed with `a`'s value, so an in-place `op dst, b`
 * computes dst = a OP b. Both are locked for the rest of the op.
 *
 * The caller must have handled dst == b already (by commuting the operands or
 * by routing through scratch): priming would overwrite b's register. */
static Pair prime_pair(BE *be, int d, int a, int w) {
    Pair p;
    p.lo = (d == a) ? mod_hv(be, HV(d, 0)) : def_hv(be, HV(d, 0));
    ra_lock(be, p.lo);
    if (d != a) mov_rs(be->e, p.lo, src_hv(be, HV(a, 0)));
    p.hi = -1;
    if (w) {
        p.hi = (d == a) ? mod_hv(be, HV(d, 1)) : def_hv(be, HV(d, 1));
        ra_lock(be, p.hi);
        if (d != a) mov_rs(be->e, p.hi, src_hv(be, HV(a, 1)));
    }
    return p;
}

/* Finish a 32-bit-wide op: the upper half of the guest register reads zero. */
static void finish32(BE *be, int d, int w) {
    if (!w) set_zero_hv(be, HV(d, 1));
}

/* Commit a pair computed in scratch registers to the destination. */
static void commit_pair(BE *be, int d, int w, int lo, int hi) {
    int dlo = def_hv(be, HV(d, 0));
    ra_lock(be, dlo);
    mov_rr(be->e, dlo, lo);
    if (w) {
        int dhi = def_hv(be, HV(d, 1));
        mov_rr(be->e, dhi, hi);
    } else {
        finish32(be, d, 0);
    }
}

/* dst = a OP b over halves, with the immediate/logical group `n`. Handles
 * dst == b by commuting (commut) or by computing in eax/edx. Returns the
 * result registers so a flag-setting caller can fold Z from them. */
static Pair alu_pair(BE *be, int n, int nhi, int d, int a, int b, int w,
                     int commut) {
    Emit *e = be->e;
    Pair p;
    if (d == b && d != a) {
        if (commut) { int t = a; a = b; b = t; }
        else {
            /* Non-commutative with the destination as the second operand:
             * compute in scratch, then commit. */
            mov_rs(e, EAX, src_hv(be, HV(a, 0)));
            alu_rs(e, n, EAX, src_hv(be, HV(b, 0)));
            if (w) {
                mov_rs(e, EDX, src_hv(be, HV(a, 1)));
                alu_rs(e, nhi, EDX, src_hv(be, HV(b, 1)));
            }
            commit_pair(be, d, w, EAX, EDX);
            p.lo = EAX; p.hi = EDX;
            return p;
        }
    }
    p = prime_pair(be, d, a, w);
    alu_rs(e, n, p.lo, src_hv(be, HV(b, 0)));
    if (w) alu_rs(e, nhi, p.hi, src_hv(be, HV(b, 1)));
    finish32(be, d, w);
    return p;
}

/* The same for an S-form whose destination is XZR: nothing to write, so the
 * result goes to scratch purely for its flags (and for the 64-bit Z). */
static Pair alu_discard(BE *be, int n, int nhi, int a, int b, int w) {
    Emit *e = be->e;
    Pair p = { EAX, EDX };
    mov_rs(e, EAX, src_hv(be, HV(a, 0)));
    alu_rs(e, n, EAX, src_hv(be, HV(b, 0)));
    if (w) {
        mov_rs(e, EDX, src_hv(be, HV(a, 1)));
        alu_rs(e, nhi, EDX, src_hv(be, HV(b, 1)));
    }
    return p;
}

/* dst = a OP imm. */
static Pair alui_pair(BE *be, int n, int nhi, int d, int a, u64 imm, int w) {
    Pair p = prime_pair(be, d, a, w);
    alu_ri(be->e, n, p.lo, (u32)imm);
    if (w) alu_ri(be->e, nhi, p.hi, (u32)(imm >> 32));
    finish32(be, d, w);
    return p;
}
static Pair alui_discard(BE *be, int n, int nhi, int a, u64 imm, int w) {
    Pair p = { EAX, EDX };
    mov_rs(be->e, EAX, src_hv(be, HV(a, 0)));
    alu_ri(be->e, n, EAX, (u32)imm);
    if (w) {
        mov_rs(be->e, EDX, src_hv(be, HV(a, 1)));
        alu_ri(be->e, nhi, EDX, (u32)(imm >> 32));
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
                shld_ri(e, p.hi, p.lo, amt);
                shift_ri(e, SH_SHL, p.lo, amt);
            } else {
                mov_rr(e, p.hi, p.lo);
                shift_ri(e, SH_SHL, p.hi, amt - 32);
                mov_ri(e, p.lo, 0);
            }
            break;
        case IRO_LSRI:
            if (amt < 32) {
                shrd_ri(e, p.lo, p.hi, amt);
                shift_ri(e, SH_SHR, p.hi, amt);
            } else {
                mov_rr(e, p.lo, p.hi);
                shift_ri(e, SH_SHR, p.lo, amt - 32);
                mov_ri(e, p.hi, 0);
            }
            break;
        case IRO_ASRI:
            if (amt < 32) {
                shrd_ri(e, p.lo, p.hi, amt);
                shift_ri(e, SH_SAR, p.hi, amt);
            } else {
                mov_rr(e, p.lo, p.hi);
                shift_ri(e, SH_SAR, p.lo, amt - 32);
                shift_ri(e, SH_SAR, p.hi, 31);   /* sign fill */
            }
            break;
        default:                                 /* IRO_RORI */
            if (amt == 32) {
                mov_rr(e, EAX, p.lo);
                mov_rr(e, p.lo, p.hi);
                mov_rr(e, p.hi, EAX);
            } else if (amt < 32) {
                mov_rr(e, EAX, p.lo);
                shrd_ri(e, p.lo, p.hi, amt);
                shrd_ri(e, p.hi, EAX, amt);
            } else {
                unsigned m = amt - 32;           /* rotate 32, then m */
                mov_rr(e, EAX, p.lo);
                mov_rr(e, EDX, p.hi);
                mov_rr(e, p.lo, EDX);
                shrd_ri(e, p.lo, EAX, m);
                mov_rr(e, p.hi, EAX);
                shrd_ri(e, p.hi, EDX, m);
            }
            break;
    }
}

/* ---- inline softmmu ----
 * The fast path is probe + access: nothing but scratch registers is touched and
 * no guest state is written, so all the sync cost lives in the slow branch —
 * which calls the same jit_ld/jit_st/jit_ldv/jit_stv helper the 64-bit backends
 * fall back to, with the faulting pc baked in, and converges with a loaded value
 * in the same registers the fast path leaves it in.
 *
 * The probe is longer here than on a 64-bit host for exactly one reason: the tag
 * is a guest page number, which is 64-bit, so it takes two compares. Everything
 * else is the established scheme. The index comes from the FIRST byte's page and
 * the compared tag from the LAST byte's, which folds the page-cross gate into
 * the tag mismatch: a crossing access indexes one entry and compares against a
 * different page, and every entry's page is congruent to its own index, so it
 * cannot accidentally agree. A TBI-tagged pointer mismatches the same way, since
 * the interpreter stores the top-byte-stripped page.
 *
 * Register budget: the entry offset needs to survive three memory references,
 * so it takes one pool register; eax and edx are the rest. eax carries the host
 * pointer into the access and edx shuttles the data, which is why an 8-byte load
 * reads its high word first — the second load is what finally overwrites the
 * pointer. */
#define FR_VLO FR_S(0)          /* the probe parks va's low word here */

static u32 cache_off(BE *be) {
    return (u32)(be->e->rx - be->env->cache_rx);
}

/* [eax] / [eax + disp] */
static Mem M_at(s32 d) { return M_reg(EAX, d); }

static void emit_mem(BE *be, const IROp *o) {
    Emit *e = be->e;
    int is_st = (o->op == IRO_ST || o->op == IRO_STV);
    int is_v  = (o->op == IRO_LDV || o->op == IRO_STV);
    unsigned desc = o->aux;
    unsigned szlog = is_v ? MDESC_VSZL(desc) : (unsigned)o->cc;
    unsigned sz = 1u << szlog;
    int need = is_st ? 2 /*PTE_W*/ : 1 /*PTE_R*/;

    /* The homes must be current before the paths split: the helper commits its
     * result there, and a fault exits the block from the slow arm. */
    sync_all(be);

    /* Take the probe's pool register BEFORE locating the operands: eviction can
     * spill the base's own register, and a Src captured earlier would then name
     * a register that no longer holds it. Both arms see it unmapped. */
    int t = ra_alloc(be);
    ra_evict(be, t);
    ra_lock(be, t);
    Src blo = src_hv(be, HV(o->a, 0)), bhi = src_hv(be, HV(o->a, 1));

    u8 *slow0 = NULL, *slow1 = NULL, *slow2 = NULL, *slow3 = NULL;
    if (UNLIKELY(be->env->slowmem)) {
        slow0 = jmp_fwd(e);                      /* bisection: helper always */
        goto fast;
    }
    /* va -> (eax, edx) */
    mov_rs(e, EAX, blo);
    mov_rs(e, EDX, bhi);
    if (o->imm) {
        alu_ri(e, AL_ADD, EAX, (u32)o->imm);
        alu_ri(e, AL_ADC, EDX, (u32)(o->imm >> 32));
    }
    st_r(e, EAX, M_esp(FR_VLO));                 /* for the page offset below */
    /* entry byte offset = ((va >> 12) & 1023) * 16 == (va & 0x3ff000) >> 8 */
    mov_rr(e, t, EAX);
    alu_ri(e, AL_AND, t, 0x003FF000u);
    shift_ri(e, SH_SHR, t, 8);
    if (sz > 1) {                                /* the access's last byte */
        alu_ri(e, AL_ADD, EAX, sz - 1);
        alu_ri(e, AL_ADC, EDX, 0);
    }
    shrd_ri(e, EAX, EDX, 12);                    /* tag, low word */
    shift_ri(e, SH_SHR, EDX, 12);                /* tag, high word */
    u32 tlb = (u32)(uintptr_t)be->env->dtlb;
    op_rm(e, 0x3B, EAX, RM_M(M_absx(tlb, t, 0)));         /* cmp against page */
    slow1 = jcc_fwd(e, CC_NE);
    op_rm(e, 0x3B, EDX, RM_M(M_absx(tlb + 4, t, 0)));
    slow2 = jcc_fwd(e, CC_NE);
    ld_r(e, EAX, M_absx(tlb + 8, t, 0));                  /* pte */
    e8(e, 0xA8); e8(e, (u8)need);                         /* test al, need */
    slow3 = jcc_fwd(e, CC_E);
    alu_ri(e, AL_AND, EAX, 0xFFFFFFF8u);         /* strip PTE_FLAGS */
    ld_r(e, EDX, M_esp(FR_VLO));
    alu_ri(e, AL_AND, EDX, GUEST_PAGE_MASK);
    op_rr(e, 0x03, EAX, EDX);                    /* eax = host pointer */

fast:;
    u32 fix_fast = cache_off(be);
    if (!is_v) {
        if (is_st) {
            /* A byte store needs a byte-addressable source, which esi and edi
             * are not on this ISA, so the value always goes through edx. */
            mov_rs(e, EDX, src_hv(be, HV(o->b, 0)));
            if (szlog == 0)      op_rm(e, 0x88, EDX, RM_M(M_at(0)));
            else if (szlog == 1) { e8(e, 0x66); op_rm(e, 0x89, EDX, RM_M(M_at(0))); }
            else                 op_rm(e, 0x89, EDX, RM_M(M_at(0)));
            if (szlog == 3) {
                mov_rs(e, EDX, src_hv(be, HV(o->b, 1)));
                op_rm(e, 0x89, EDX, RM_M(M_at(4)));
            }
        } else {
            int sign = MDESC_SIGN(desc);
            if (szlog == 3) {
                ld_r(e, EDX, M_at(4));           /* high word first: the second
                                                  * load overwrites the pointer */
                ld_r(e, EAX, M_at(0));
            } else {
                if (szlog == 2) ld_r(e, EAX, M_at(0));
                else op0f_rm(e, (u8)(sign ? (szlog ? 0xBF : 0xBE)
                                          : (szlog ? 0xB7 : 0xB6)),
                             EAX, RM_M(M_at(0)));   /* movsx / movzx */
                if (o->w) {
                    if (sign && szlog < 3) {     /* sign-fill the high word */
                        mov_rr(e, EDX, EAX);
                        shift_ri(e, SH_SAR, EDX, 31);
                    } else {
                        mov_ri(e, EDX, 0);
                    }
                }
            }
        }
    } else {
        /* Vector accesses work on c->v[rt] directly, a word at a time; the
         * pointer stays in eax throughout. */
        unsigned vd = MDESC_RT(desc);
        unsigned words = sz >= 4 ? sz / 4 : 1;
        for (unsigned k = 0; k < words; k++) {
            if (is_st) {
                ld_r(e, EDX, M_ebp(OFF_V(vd) + 4 * (s32)k));
                if (k == 0 && szlog == 0)      op_rm(e, 0x88, EDX, RM_M(M_at(0)));
                else if (k == 0 && szlog == 1) { e8(e, 0x66);
                                                 op_rm(e, 0x89, EDX, RM_M(M_at(0))); }
                else op_rm(e, 0x89, EDX, RM_M(M_at(4 * (s32)k)));
            } else {
                if (szlog == 0)      op0f_rm(e, 0xB6, EDX, RM_M(M_at(0)));
                else if (szlog == 1) op0f_rm(e, 0xB7, EDX, RM_M(M_at(0)));
                else                 ld_r(e, EDX, M_at(4 * (s32)k));
                st_r(e, EDX, M_ebp(OFF_V(vd) + 4 * (s32)k));
            }
        }
        if (!is_st && sz < 16) {                 /* jit_ldv zero-extends */
            mov_ri(e, EDX, 0);
            for (unsigned k = words; k < 4; k++)
                st_r(e, EDX, M_ebp(OFF_V(vd) + 4 * (s32)k));
        }
    }
    u8 *done = jmp_fwd(e);

    /* ---- slow path ---- */
    fwd_here(e, slow0);
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    fwd_here(e, slow3);
    be_fixup_add(be->env, fix_fast, cache_off(be));
    mov_rs(e, EAX, blo);                         /* the probe consumed va */
    mov_rs(e, EDX, bhi);
    if (o->imm) {
        alu_ri(e, AL_ADD, EAX, (u32)o->imm);
        alu_ri(e, AL_ADC, EDX, (u32)(o->imm >> 32));
    }
    arg_cpu(be, 0);
    arg_pair_regs(be, 1, EAX, EDX);
    if (o->op == IRO_ST) {                       /* jit_st(c, va, val, pc, desc) */
        arg_hv64(be, 3, o->b);
        arg_imm64(be, 5, o->imm2pc);
        arg_imm(be, 7, desc);
    } else {                                     /* (c, va, pc, desc) */
        arg_imm64(be, 3, o->imm2pc);
        arg_imm(be, 5, desc);
    }
    call_c(e, o->op == IRO_LD  ? (const void *)jit_ld
            : o->op == IRO_ST  ? (const void *)jit_st
            : o->op == IRO_LDV ? (const void *)jit_ldv
                               : (const void *)jit_stv);
    op_rr(e, 0x85, EAX, EAX);                    /* test eax, eax */
    u8 *ok = jcc_fwd(e, CC_E);
    exit_plain(be, o->icnt);                     /* faulted: leave the block */
    fwd_here(e, ok);
    reload_clobbered(be);
    if (o->op == IRO_LD && o->dst != VREG_ZERO) {
        /* The helper committed to the home; converge on the registers the fast
         * path would have left the value in. */
        ld_r(e, EAX, hv_home(be, HV(o->dst, 0)));
        if (o->w) ld_r(e, EDX, hv_home(be, HV(o->dst, 1)));
    }
    fwd_here(e, done);

    /* ---- merge ---- */
    if (o->op == IRO_LD && o->dst != VREG_ZERO)
        commit_pair(be, o->dst, o->w, EAX, EDX);
}

/* ---- fused runs: one probe for a whole same-base run ----
 * jit_mem_run_len finds consecutive integer loads or stores off the same
 * unclobbered base with constant offsets whose whole span fits one guest page.
 * They share ONE span-checked probe: the tag compare uses the span's last byte
 * against the tag stored for the first's page, so any crossing of the run
 * mismatches and takes the bail route, where the accesses re-run through their
 * helpers in program order — a fault at access j leaves accesses < j committed
 * and j's destination unwritten, exactly the interpreter's rule.
 *
 * This is worth more here than on a 64-bit host precisely because the probe is
 * longer: an LDP/STP pair or a prologue spill run pays it once instead of twice
 * to eight times.
 *
 * Loads commit to their destinations' memory HOMES rather than to registers. A
 * 64-bit backend pre-maps the destinations outside the branch so both arms agree
 * on the allocator state; here there are four pool registers and a run can carry
 * eight destination halves, so agreement is reached the other way round — the
 * fast path writes the same homes the helpers would, and both arms then drop the
 * mappings. The cost is a reload per value later; the saving is a whole probe. */
static int fuse_enabled(void) {
    static int v = -1;
    if (v < 0) v = getenv("A64_JIT_NOFUSE") == NULL;
    return v;
}

/* base -> eax:edx, read from its home. A Src naming a register is not safe
 * across the bail path: the first helper call clobbers ecx. sync_all made the
 * home current, and no access in a run may write the base. */
static void bail_base(BE *be, int v) {
    if (v == VREG_ZERO) { mov_ri(be->e, EAX, 0); mov_ri(be->e, EDX, 0); return; }
    ld_r(be->e, EAX, hv_home(be, HV(v, 0)));
    ld_r(be->e, EDX, hv_home(be, HV(v, 1)));
}
/* A store value as a u64 argument, likewise straight from its home. */
static void arg_hv64_home(BE *be, int slot, int v) {
    for (int half = 0; half < 2; half++) {
        if (v == VREG_ZERO) { arg_imm(be, slot + half, 0); continue; }
        ld_r(be->e, EAX, hv_home(be, HV(v, half)));
        st_r(be->e, EAX, M_esp(FR_ARG(slot + half)));
    }
}

static void emit_mem_run(BE *be, const IRBlock *ir, int i, int k) {
    Emit *e = be->e;
    const IROp *o = &ir->ops[i];
    int is_st = (o->op == IRO_ST);
    int need = is_st ? 2 : 1;

    s64 lo = (s64)o->imm, hi = lo + (s64)(1u << o->cc);
    for (int t = 1; t < k; t++) {
        s64 plo = (s64)ir->ops[i + t].imm;
        s64 phi = plo + (s64)(1u << ir->ops[i + t].cc);
        if (plo < lo) lo = plo;
        if (phi > hi) hi = phi;
    }

    sync_all(be);
    int t_reg = ra_alloc(be);
    ra_evict(be, t_reg);
    ra_lock(be, t_reg);
    Src blo = src_hv(be, HV(o->a, 0)), bhi = src_hv(be, HV(o->a, 1));

    u8 *slow0 = NULL, *slow1 = NULL, *slow2 = NULL, *slow3 = NULL;
    if (UNLIKELY(be->env->slowmem)) {
        slow0 = jmp_fwd(e);
        goto fast;
    }
    mov_rs(e, EAX, blo);                         /* va0 = base + lo */
    mov_rs(e, EDX, bhi);
    if (lo) {
        alu_ri(e, AL_ADD, EAX, (u32)(u64)lo);
        alu_ri(e, AL_ADC, EDX, (u32)((u64)lo >> 32));
    }
    st_r(e, EAX, M_esp(FR_VLO));
    mov_rr(e, t_reg, EAX);
    alu_ri(e, AL_AND, t_reg, 0x003FF000u);
    shift_ri(e, SH_SHR, t_reg, 8);
    if (hi - lo > 1) {                           /* the span's last byte */
        alu_ri(e, AL_ADD, EAX, (u32)(hi - lo - 1));
        alu_ri(e, AL_ADC, EDX, 0);
    }
    shrd_ri(e, EAX, EDX, 12);
    shift_ri(e, SH_SHR, EDX, 12);
    u32 tlb = (u32)(uintptr_t)be->env->dtlb;
    op_rm(e, 0x3B, EAX, RM_M(M_absx(tlb, t_reg, 0)));
    slow1 = jcc_fwd(e, CC_NE);
    op_rm(e, 0x3B, EDX, RM_M(M_absx(tlb + 4, t_reg, 0)));
    slow2 = jcc_fwd(e, CC_NE);
    ld_r(e, EAX, M_absx(tlb + 8, t_reg, 0));
    e8(e, 0xA8); e8(e, (u8)need);                /* test al, need */
    slow3 = jcc_fwd(e, CC_E);
    alu_ri(e, AL_AND, EAX, 0xFFFFFFF8u);
    ld_r(e, EDX, M_esp(FR_VLO));
    alu_ri(e, AL_AND, EDX, GUEST_PAGE_MASK);
    op_rr(e, 0x03, EAX, EDX);                    /* eax = host pointer of va0 */

fast:;
    u32 fix_fast = cache_off(be);
    for (int t = 0; t < k; t++) {
        const IROp *p = &ir->ops[i + t];
        s32 d = (s32)((s64)p->imm - lo);
        unsigned szlog = p->cc;
        if (is_st) {
            mov_rs(e, EDX, src_hv(be, HV(p->b, 0)));
            if (szlog == 0)      op_rm(e, 0x88, EDX, RM_M(M_at(d)));
            else if (szlog == 1) { e8(e, 0x66); op_rm(e, 0x89, EDX, RM_M(M_at(d))); }
            else                 op_rm(e, 0x89, EDX, RM_M(M_at(d)));
            if (szlog == 3) {
                mov_rs(e, EDX, src_hv(be, HV(p->b, 1)));
                op_rm(e, 0x89, EDX, RM_M(M_at(d + 4)));
            }
        } else if (p->dst != VREG_ZERO) {
            int sign = MDESC_SIGN(p->aux);
            if (szlog == 3) {
                ld_r(e, EDX, M_at(d));
                st_r(e, EDX, hv_home(be, HV(p->dst, 0)));
                ld_r(e, EDX, M_at(d + 4));
                st_r(e, EDX, hv_home(be, HV(p->dst, 1)));
            } else {
                if (szlog == 2) ld_r(e, EDX, M_at(d));
                else op0f_rm(e, (u8)(sign ? (szlog ? 0xBF : 0xBE)
                                          : (szlog ? 0xB7 : 0xB6)),
                             EDX, RM_M(M_at(d)));
                st_r(e, EDX, hv_home(be, HV(p->dst, 0)));
                if (p->w && sign) {              /* sign-fill the high word */
                    shift_ri(e, SH_SAR, EDX, 31);
                    st_r(e, EDX, hv_home(be, HV(p->dst, 1)));
                } else {
                    mov_mi(e, hv_home(be, HV(p->dst, 1)), 0);
                }
            }
        }
    }
    u8 *done = jmp_fwd(e);

    /* ---- bail: the helpers, in program order ---- */
    fwd_here(e, slow0);
    fwd_here(e, slow1);
    fwd_here(e, slow2);
    fwd_here(e, slow3);
    be_fixup_add(be->env, fix_fast, cache_off(be));
    for (int t = 0; t < k; t++) {
        const IROp *p = &ir->ops[i + t];
        bail_base(be, o->a);
        if (p->imm) {
            alu_ri(e, AL_ADD, EAX, (u32)p->imm);
            alu_ri(e, AL_ADC, EDX, (u32)(p->imm >> 32));
        }
        arg_cpu(be, 0);
        arg_pair_regs(be, 1, EAX, EDX);
        if (is_st) {
            arg_hv64_home(be, 3, p->b);
            arg_imm64(be, 5, p->imm2pc);
            arg_imm(be, 7, p->aux);
        } else {
            arg_imm64(be, 3, p->imm2pc);
            arg_imm(be, 5, p->aux);
        }
        call_c(e, is_st ? (const void *)jit_st : (const void *)jit_ld);
        op_rr(e, 0x85, EAX, EAX);
        u8 *okk = jcc_fwd(e, CC_E);
        exit_plain(be, p->icnt);
        fwd_here(e, okk);
    }
    reload_clobbered(be);
    fwd_here(e, done);

    /* Both arms left every loaded value in its home; drop the mappings so the
     * next use reloads, which is the state each arm agrees on. */
    if (!is_st)
        for (int t = 0; t < k; t++) inval_v(be, ir->ops[i + t].dst);
}

/* ---- one guest instruction through the interpreter ----
 * IRO_CALL1 (and IRO_ATOMIC, which this backend does not inline): full state
 * sync, call, and leave the block if the helper says control moved. */
static void emit_exec1(BE *be, u64 pc, u32 insn, int ic, u32 icnt) {
    Emit *e = be->e;
    sync_all(be);
    inval_all(be);
    arg_cpu(be, 0);
    arg_imm64(be, 1, pc);
    arg_imm(be, 3, insn);
    call_c(e, ic ? (const void *)jit_exec1_ic : (const void *)jit_exec1);
    op_rr(e, 0x85, EAX, EAX);
    u8 *cont = jcc_fwd(e, CC_E);
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

    /* Safepoint: the hot entry is cmp+jcc and the exit body sits after the
     * block's last op. c->pc has to be restored to the block start there — a
     * direct chain jump in bypassed the predecessor's exit-stub pc write. */
    alu_rmi(e, AL_CMP, RM_M(M_abs(env_abs(&be, offsetof(JitEnv, interrupt)))), 0);
    u8 *cold = jcc_fwd(e, CC_NE);

    for (int k = 0; k < ir->n && !e->overflow; ) {
        ra_unlock_all(&be);
        k += emit_op(&be, ir, k);
    }

    if (e->overflow) return -1;
    fwd_here(e, cold);
    store_pc_imm(e, b->pc);
    exit_plain(&be, 0);
    return e->overflow ? -1 : 0;
}

/* Emits ir->ops[i]; returns how many IR ops were consumed (a terminal
 * conditional branch consumes its paired fallthrough IRO_JMP). */
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
        case IRO_MOV: {
            if (o->dst != o->a) {
                int dlo = def_hv(be, HV(o->dst, 0));
                ra_lock(be, dlo);
                mov_rs(e, dlo, src_hv(be, HV(o->a, 0)));
                if (w) mov_rs(e, def_hv(be, HV(o->dst, 1)),
                              src_hv(be, HV(o->a, 1)));
            }
            finish32(be, o->dst, w);
            break;
        }
        case IRO_MOVK: {                          /* dst == a; insert imm16 */
            unsigned sh = o->cc;
            int half = (sh >= 32);
            Pair p = prime_pair(be, o->dst, o->a, w || half);
            int r = half ? p.hi : p.lo;
            alu_ri(e, AL_AND, r, (u32)~(0xffffu << (sh & 31)));
            u32 part = (u32)(o->imm >> (32 * half));
            if (part) alu_ri(e, AL_OR, r, part);
            finish32(be, o->dst, w);
            break;
        }

        /* ---- register ALU ---- */
        case IRO_ADD: alu_pair(be, AL_ADD, AL_ADC, o->dst, o->a, o->b, w, 1); break;
        case IRO_SUB: alu_pair(be, AL_SUB, AL_SBB, o->dst, o->a, o->b, w, 0); break;
        case IRO_AND: alu_pair(be, AL_AND, AL_AND, o->dst, o->a, o->b, w, 1); break;
        case IRO_ORR: alu_pair(be, AL_OR,  AL_OR,  o->dst, o->a, o->b, w, 1); break;
        case IRO_EOR: alu_pair(be, AL_XOR, AL_XOR, o->dst, o->a, o->b, w, 1); break;

        case IRO_BIC: case IRO_ORN: case IRO_EON: {
            /* dst = a OP ~b. b is complemented into scratch FIRST, which also
             * settles the dst == b case: nothing reads b afterwards. */
            int n = o->op == IRO_BIC ? AL_AND : o->op == IRO_ORN ? AL_OR : AL_XOR;
            mov_rs(e, EAX, src_hv(be, HV(o->b, 0)));
            unop_rm(e, 2, RM_R(EAX));            /* not eax */
            if (w) {
                mov_rs(e, EDX, src_hv(be, HV(o->b, 1)));
                unop_rm(e, 2, RM_R(EDX));
            }
            Pair p = prime_pair(be, o->dst, o->a, w);
            op_rr(e, (u8)(0x03 + 8 * n), p.lo, EAX);
            if (w) op_rr(e, (u8)(0x03 + 8 * n), p.hi, EDX);
            finish32(be, o->dst, w);
            break;
        }

        case IRO_ADDS: case IRO_SUBS: case IRO_ANDS: {
            int n = o->op == IRO_ADDS ? AL_ADD : o->op == IRO_SUBS ? AL_SUB : AL_AND;
            int nhi = o->op == IRO_ADDS ? AL_ADC : o->op == IRO_SUBS ? AL_SBB : AL_AND;
            int kind = o->op == IRO_ADDS ? FK_ADD
                     : o->op == IRO_SUBS ? FK_SUB : FK_LOGIC;
            int commut = (o->op != IRO_SUBS);
            Pair p;
            if (o->dst == VREG_ZERO)
                p = alu_discard(be, n, nhi, o->a, o->b, w);
            else
                p = alu_pair(be, n, nhi, o->dst, o->a, o->b, w, commut);
            if (!o->flags_dead) emit_flags(be, kind, w, p.lo, p.hi);
            break;
        }
        case IRO_BICS: {
            mov_rs(e, EAX, src_hv(be, HV(o->b, 0)));
            unop_rm(e, 2, RM_R(EAX));
            if (w) {
                mov_rs(e, EDX, src_hv(be, HV(o->b, 1)));
                unop_rm(e, 2, RM_R(EDX));
            }
            Pair p;
            if (o->dst == VREG_ZERO) {
                p.lo = EAX; p.hi = EDX;
                alu_rs(e, AL_AND, EAX, src_hv(be, HV(o->a, 0)));
                if (w) alu_rs(e, AL_AND, EDX, src_hv(be, HV(o->a, 1)));
            } else {
                p = prime_pair(be, o->dst, o->a, w);
                op_rr(e, 0x23, p.lo, EAX);
                if (w) op_rr(e, 0x23, p.hi, EDX);
                finish32(be, o->dst, w);
            }
            if (!o->flags_dead) emit_flags(be, FK_LOGIC, w, p.lo, p.hi);
            break;
        }

        case IRO_ADC: case IRO_SBC: case IRO_ADCS: case IRO_SBCS: {
            int sbc  = (o->op == IRO_SBC || o->op == IRO_SBCS);
            int setf = (o->op == IRO_ADCS || o->op == IRO_SBCS);
            int n = sbc ? AL_SBB : AL_ADC;
            if (setf && o->flags_dead && o->dst == VREG_ZERO) break;
            /* The pair form of a three-input add is just adc/adc (sbb/sbb)
             * with CF seeded from the guest C: the low half's carry-out feeds
             * the high half exactly as the guest's single 64-bit op would. */
            Pair p;
            int scratch = (o->dst == VREG_ZERO) ||
                          (o->dst == o->b && o->dst != o->a);
            if (scratch) {
                p.lo = EAX; p.hi = EDX;
                mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
                if (w) mov_rs(e, EDX, src_hv(be, HV(o->a, 1)));
            } else {
                p = prime_pair(be, o->dst, o->a, w);
            }
            Src blo = src_hv(be, HV(o->b, 0));
            Src bhi = w ? src_hv(be, HV(o->b, 1)) : blo;
            /* CF = guest C, read straight out of the architectural word — bt
             * takes a memory operand, so the seed costs no register. ARM SBC
             * is a + ~b + C, which is x86 sbb with CF = !C. Only flag-safe
             * moves may follow before the adc that consumes it, and every
             * allocator action above emits exactly those. */
            e8(e, 0x0F); e8(e, 0xBA);
            modrm_rm(e, 4, RM_M(M_ebp(OFF_NZCV)));
            e8(e, 29);
            if (sbc) e8(e, 0xF5);                /* cmc */
            alu_rs(e, n, p.lo, blo);
            if (w) alu_rs(e, n, p.hi, bhi);
            if (!scratch) finish32(be, o->dst, w);
            else if (o->dst != VREG_ZERO) commit_pair(be, o->dst, w, EAX, EDX);
            if (setf && !o->flags_dead)
                emit_flags(be, sbc ? FK_SUB : FK_ADD, w, p.lo, p.hi);
            break;
        }

        case IRO_ADDI: case IRO_SUBI: case IRO_ANDI: case IRO_ORRI:
        case IRO_EORI: {
            int n = o->op == IRO_ADDI ? AL_ADD : o->op == IRO_SUBI ? AL_SUB
                  : o->op == IRO_ANDI ? AL_AND : o->op == IRO_ORRI ? AL_OR
                                                                   : AL_XOR;
            int nhi = o->op == IRO_ADDI ? AL_ADC : o->op == IRO_SUBI ? AL_SBB : n;
            u64 imm = w ? o->imm : (u32)o->imm;
            if (o->op == IRO_ANDI && w && (u32)(imm >> 32) == 0) {
                /* AND that clears the whole upper half: prime the low half
                 * only and record the zero. */
                Pair p = prime_pair(be, o->dst, o->a, 0);
                alu_ri(e, AL_AND, p.lo, (u32)imm);
                set_zero_hv(be, HV(o->dst, 1));
                break;
            }
            alui_pair(be, n, nhi, o->dst, o->a, imm, w);
            break;
        }
        case IRO_ADDIS: case IRO_SUBIS: case IRO_ANDIS: {
            int n = o->op == IRO_ADDIS ? AL_ADD : o->op == IRO_SUBIS ? AL_SUB : AL_AND;
            int nhi = o->op == IRO_ADDIS ? AL_ADC : o->op == IRO_SUBIS ? AL_SBB : AL_AND;
            int kind = o->op == IRO_ADDIS ? FK_ADD
                     : o->op == IRO_SUBIS ? FK_SUB : FK_LOGIC;
            u64 imm = w ? o->imm : (u32)o->imm;
            Pair p;
            if (o->dst == VREG_ZERO) p = alui_discard(be, n, nhi, o->a, imm, w);
            else                     p = alui_pair(be, n, nhi, o->dst, o->a, imm, w);
            if (!o->flags_dead) emit_flags(be, kind, w, p.lo, p.hi);
            break;
        }

        /* ---- shifts ---- */
        case IRO_LSLI: case IRO_LSRI: case IRO_ASRI: case IRO_RORI: {
            if (!w) {
                static const u8 n32[] = { SH_SHL, SH_SHR, SH_SAR, SH_ROR };
                Pair p = prime_pair(be, o->dst, o->a, 0);
                shift_ri(e, n32[o->op - IRO_LSLI], p.lo, (unsigned)o->imm);
                finish32(be, o->dst, 0);
                break;
            }
            Pair p = prime_pair(be, o->dst, o->a, 1);
            shift_imm_pair(be, o->op, p, (unsigned)o->imm);
            break;
        }
        case IRO_LSLV: case IRO_LSRV: case IRO_ASRV: case IRO_RORV: {
            if (!w) {
                static const u8 n32[] = { SH_SHL, SH_SHR, SH_SAR, SH_ROR };
                free_ecx(be);
                mov_rs(e, ECX, src_hv(be, HV(o->b, 0)));
                ra_lock(be, ECX);
                Pair p = prime_pair(be, o->dst, o->a, 0);
                shift_cl(e, n32[o->op - IRO_LSLV], p.lo);
                finish32(be, o->dst, 0);
                break;
            }
            static const void *const fn[] = { (const void *)h_lsl64,
                                              (const void *)h_lsr64,
                                              (const void *)h_asr64,
                                              (const void *)h_ror64 };
            free_ecx(be);
            arg_hv64(be, 0, o->a);
            Src s = src_hv(be, HV(o->b, 0));
            if (s.kind == S_IMM) arg_imm(be, 2, s.imm);
            else { mov_rs(e, EAX, s); st_r(e, EAX, M_esp(FR_ARG(2))); }
            call_c(e, fn[o->op - IRO_LSLV]);
            reload_clobbered(be);
            commit_pair(be, o->dst, 1, EAX, EDX);
            break;
        }
        case IRO_EXTR: {
            unsigned amt = (unsigned)o->imm;
            if (!w) {
                RM ah = src_rm(be, HV(o->a, 0), EDX);
                mov_rs(e, EAX, src_hv(be, HV(o->b, 0)));
                if (amt) {
                    if (!ah.is_reg) { op_rm(e, 0x8B, EDX, ah); ah = RM_R(EDX); }
                    shrd_ri(e, EAX, ah.reg, amt);
                }
                commit_pair(be, o->dst, 0, EAX, EDX);
                break;
            }
            /* 128-bit funnel of (a:b) >> amt, low 64 bits. Every case is two
             * shrd's whose sources are one word apart; the finished low word
             * parks in the frame while the high one is built. */
            if (!amt) {
                mov_rs(e, EAX, src_hv(be, HV(o->b, 0)));
                mov_rs(e, EDX, src_hv(be, HV(o->b, 1)));
            } else if (amt < 32) {
                mov_rs(e, EAX, src_hv(be, HV(o->b, 0)));
                mov_rs(e, EDX, src_hv(be, HV(o->b, 1)));
                shrd_ri(e, EAX, EDX, amt);       /* low = shrd(b_lo, b_hi) */
                st_r(e, EAX, M_esp(FR_S(0)));
                mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
                shrd_ri(e, EDX, EAX, amt);       /* high = shrd(b_hi, a_lo) */
                ld_r(e, EAX, M_esp(FR_S(0)));
            } else if (amt == 32) {
                mov_rs(e, EAX, src_hv(be, HV(o->b, 1)));
                mov_rs(e, EDX, src_hv(be, HV(o->a, 0)));
            } else {
                unsigned m = amt - 32;
                mov_rs(e, EAX, src_hv(be, HV(o->b, 1)));
                mov_rs(e, EDX, src_hv(be, HV(o->a, 0)));
                shrd_ri(e, EAX, EDX, m);         /* low = shrd(b_hi, a_lo) */
                st_r(e, EAX, M_esp(FR_S(0)));
                mov_rs(e, EAX, src_hv(be, HV(o->a, 1)));
                shrd_ri(e, EDX, EAX, m);         /* high = shrd(a_lo, a_hi) */
                ld_r(e, EAX, M_esp(FR_S(0)));
            }
            commit_pair(be, o->dst, 1, EAX, EDX);
            break;
        }

        /* ---- multiply / divide ---- */
        case IRO_MADD: case IRO_MSUB: {
            int sub = (o->op == IRO_MSUB);
            if (!w) {
                mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
                op0f_rm(e, 0xAF, EAX, src_rm(be, HV(o->b, 0), EDX));
                if (o->cc != VREG_ZERO) {
                    if (sub) {
                        mov_rs(e, EDX, src_hv(be, HV(o->cc, 0)));
                        op_rr(e, 0x2B, EDX, EAX);        /* edx -= eax */
                        mov_rr(e, EAX, EDX);
                    } else {
                        alu_rs(e, AL_ADD, EAX, src_hv(be, HV(o->cc, 0)));
                    }
                } else if (sub) {
                    unop_rm(e, 3, RM_R(EAX));            /* neg */
                }
                commit_pair(be, o->dst, 0, EAX, EDX);
                break;
            }
            /* 64x64 low product: al*bl, plus the two cross terms in the high
             * word. mul writes edx:eax, so the partials live in the frame. */
            free_ecx(be);
            mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
            unop_rm(e, 4, src_rm(be, HV(o->b, 0), ECX)); /* mul: edx:eax */
            st_r(e, EAX, M_esp(FR_S(0)));
            st_r(e, EDX, M_esp(FR_S(1)));
            mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
            op0f_rm(e, 0xAF, EAX, src_rm(be, HV(o->b, 1), ECX));
            op_rm(e, 0x01, EAX, RM_M(M_esp(FR_S(1))));   /* [S1] += eax */
            mov_rs(e, EAX, src_hv(be, HV(o->a, 1)));
            op0f_rm(e, 0xAF, EAX, src_rm(be, HV(o->b, 0), ECX));
            op_rm(e, 0x01, EAX, RM_M(M_esp(FR_S(1))));
            ld_r(e, EAX, M_esp(FR_S(0)));
            ld_r(e, EDX, M_esp(FR_S(1)));
            if (o->cc != VREG_ZERO) {
                if (sub) {                               /* Ra - a*b */
                    st_r(e, EAX, M_esp(FR_S(0)));
                    st_r(e, EDX, M_esp(FR_S(1)));
                    mov_rs(e, EAX, src_hv(be, HV(o->cc, 0)));
                    mov_rs(e, EDX, src_hv(be, HV(o->cc, 1)));
                    op_rm(e, 0x2B, EAX, RM_M(M_esp(FR_S(0))));
                    op_rm(e, 0x1B, EDX, RM_M(M_esp(FR_S(1))));
                } else {
                    alu_rs(e, AL_ADD, EAX, src_hv(be, HV(o->cc, 0)));
                    alu_rs(e, AL_ADC, EDX, src_hv(be, HV(o->cc, 1)));
                }
            } else if (sub) {                            /* 0 - a*b */
                unop_rm(e, 2, RM_R(EAX));                /* not eax */
                unop_rm(e, 2, RM_R(EDX));
                alu_ri(e, AL_ADD, EAX, 1);
                alu_ri(e, AL_ADC, EDX, 0);
            }
            commit_pair(be, o->dst, 1, EAX, EDX);
            break;
        }
        case IRO_SMADDL: case IRO_SMSUBL: case IRO_UMADDL: case IRO_UMSUBL: {
            int sign = (o->op == IRO_SMADDL || o->op == IRO_SMSUBL);
            int sub  = (o->op == IRO_SMSUBL || o->op == IRO_UMSUBL);
            free_ecx(be);
            mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
            unop_rm(e, sign ? 5 : 4, src_rm(be, HV(o->b, 0), ECX));  /* imul/mul */
            if (o->cc != VREG_ZERO) {
                if (sub) {
                    st_r(e, EAX, M_esp(FR_S(0)));
                    st_r(e, EDX, M_esp(FR_S(1)));
                    mov_rs(e, EAX, src_hv(be, HV(o->cc, 0)));
                    mov_rs(e, EDX, src_hv(be, HV(o->cc, 1)));
                    op_rm(e, 0x2B, EAX, RM_M(M_esp(FR_S(0))));
                    op_rm(e, 0x1B, EDX, RM_M(M_esp(FR_S(1))));
                } else {
                    alu_rs(e, AL_ADD, EAX, src_hv(be, HV(o->cc, 0)));
                    alu_rs(e, AL_ADC, EDX, src_hv(be, HV(o->cc, 1)));
                }
            } else if (sub) {
                unop_rm(e, 2, RM_R(EAX));
                unop_rm(e, 2, RM_R(EDX));
                alu_ri(e, AL_ADD, EAX, 1);
                alu_ri(e, AL_ADC, EDX, 0);
            }
            commit_pair(be, o->dst, 1, EAX, EDX);
            break;
        }
        case IRO_SMULH: case IRO_UMULH: {
            free_ecx(be);
            arg_hv64(be, 0, o->a);
            arg_hv64(be, 2, o->b);
            call_c(e, o->op == IRO_SMULH ? (const void *)h_smulh
                                         : (const void *)h_umulh);
            reload_clobbered(be);
            commit_pair(be, o->dst, 1, EAX, EDX);
            break;
        }
        case IRO_UDIV: case IRO_SDIV: {
            free_ecx(be);
            arg_hv64(be, 0, o->a);
            arg_hv64(be, 2, o->b);
            call_c(e, o->op == IRO_UDIV
                          ? (w ? (const void *)h_udiv64 : (const void *)h_udiv32)
                          : (w ? (const void *)h_sdiv64 : (const void *)h_sdiv32));
            reload_clobbered(be);
            commit_pair(be, o->dst, w, EAX, EDX);
            break;
        }

        case IRO_CLZ: {
            /* bsr gives the index of the highest set bit and ZF for "none".
             * The result is built in eax so a dst == a overlap cannot lose a
             * source word between the two halves. */
            u8 *have_hi = NULL;
            if (w) {
                op0f_rm(e, 0xBD, EAX, src_rm(be, HV(o->a, 1), EDX));
                have_hi = jcc_fwd(e, CC_NE);     /* the count is in the high
                                                  * word: 31 - index */
            }
            op0f_rm(e, 0xBD, EAX, src_rm(be, HV(o->a, 0), EDX));
            u8 *none = jcc_fwd(e, CC_E);
            alu_ri(e, AL_XOR, EAX, 31);
            if (w) alu_ri(e, AL_ADD, EAX, 32);   /* plus the empty high word */
            u8 *done = jmp_fwd(e);
            fwd_here(e, none);
            mov_ri(e, EAX, w ? 64 : 32);
            u8 *done2 = w ? jmp_fwd(e) : NULL;
            if (w) {
                fwd_here(e, have_hi);
                alu_ri(e, AL_XOR, EAX, 31);
            }
            fwd_here(e, done);
            fwd_here(e, done2);
            commit_pair(be, o->dst, 0, EAX, EDX);   /* 0..64 fits the low word */
            break;
        }
        case IRO_REV64: case IRO_REV32: {
            if (o->op == IRO_REV32) {             /* bswap32, zero-extended */
                Pair p = prime_pair(be, o->dst, o->a, 0);
                e8(e, 0x0F); e8(e, (u8)(0xC8 | (p.lo & 7)));
                finish32(be, o->dst, 0);
                break;
            }
            mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
            mov_rs(e, EDX, src_hv(be, HV(o->a, 1)));
            e8(e, 0x0F); e8(e, (u8)(0xC8 | EAX));
            e8(e, 0x0F); e8(e, (u8)(0xC8 | EDX));
            commit_pair(be, o->dst, 1, EDX, EAX); /* and swap the words */
            break;
        }
        case IRO_RBIT: {
            free_ecx(be);
            arg_hv64(be, 0, o->a);
            arg_imm(be, 2, (u32)w);
            call_c(e, (const void *)h_rbit);
            reload_clobbered(be);
            commit_pair(be, o->dst, w, EAX, EDX);
            break;
        }

        case IRO_CSEL: case IRO_CSINC: case IRO_CSINV: case IRO_CSNEG: {
            /* Both arms compute into scratch and the result is committed after
             * they merge. That settles two things at once: no allocator action
             * happens inside a conditional region (the two runtime paths have
             * to agree on where every value lives), and a destination that is
             * also a source — `csel x3, x3, x2` — cannot have its own register
             * claimed before the value has been read. */
            int cc = cond_setup(be, o->cc);
            Src alo = src_hv(be, HV(o->a, 0)), ahi = src_hv(be, HV(o->a, 1));
            Src blo = src_hv(be, HV(o->b, 0)), bhi = src_hv(be, HV(o->b, 1));
            u8 *taken = NULL, *end = NULL;
            if (cc != CC_ALWAYS && cc != CC_NEVER) taken = jcc_fwd(e, cc);
            if (cc != CC_ALWAYS) {                /* result = f(b) */
                mov_rs(e, EAX, blo);
                if (w) mov_rs(e, EDX, bhi);
                if (o->op == IRO_CSINV || o->op == IRO_CSNEG) {
                    unop_rm(e, 2, RM_R(EAX));
                    if (w) unop_rm(e, 2, RM_R(EDX));
                }
                if (o->op == IRO_CSINC || o->op == IRO_CSNEG) {
                    alu_ri(e, AL_ADD, EAX, 1);
                    if (w) alu_ri(e, AL_ADC, EDX, 0);
                }
            }
            if (cc != CC_ALWAYS && cc != CC_NEVER) {
                end = jmp_fwd(e);
                fwd_here(e, taken);
            }
            if (cc != CC_NEVER) {                 /* result = a */
                mov_rs(e, EAX, alo);
                if (w) mov_rs(e, EDX, ahi);
            }
            fwd_here(e, end);
            commit_pair(be, o->dst, w, EAX, EDX);
            break;
        }

        case IRO_CCMPR: case IRO_CCMNR: case IRO_CCMPI: case IRO_CCMNI: {
            int is_imm = (o->op == IRO_CCMPI || o->op == IRO_CCMNI);
            int is_cmn = (o->op == IRO_CCMNR || o->op == IRO_CCMNI);
            int cc = cond_setup(be, o->cc);
            u8 *els = NULL, *end = NULL;
            if (cc == CC_NEVER) {
                mov_mi(e, M_ebp(OFF_NZCV), o->aux);
                break;
            }
            /* The compare arm computes into scratch only; both arms leave the
             * allocator exactly as they found it. */
            Src alo = src_hv(be, HV(o->a, 0)), ahi = src_hv(be, HV(o->a, 1));
            Src blo = is_imm ? alo : src_hv(be, HV(o->b, 0));
            Src bhi = is_imm ? alo : src_hv(be, HV(o->b, 1));
            if (cc != CC_ALWAYS) els = jcc_fwd(e, cc ^ 1);
            mov_rs(e, EAX, alo);
            if (is_imm) alu_ri(e, is_cmn ? AL_ADD : AL_SUB, EAX, (u32)o->imm);
            else        alu_rs(e, is_cmn ? AL_ADD : AL_SUB, EAX, blo);
            if (w) {
                mov_rs(e, EDX, ahi);
                if (is_imm) alu_ri(e, is_cmn ? AL_ADC : AL_SBB, EDX,
                                   (u32)(o->imm >> 32));
                else        alu_rs(e, is_cmn ? AL_ADC : AL_SBB, EDX, bhi);
            }
            emit_flags(be, is_cmn ? FK_ADD : FK_SUB, w, EAX, EDX);
            if (cc != CC_ALWAYS) {
                end = jmp_fwd(e);
                fwd_here(e, els);
                mov_mi(e, M_ebp(OFF_NZCV), o->aux);
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
            int cc = cond_setup(be, o->cc);
            const IROp *nxt = &ir->ops[i + 1];
            if (cc == CC_ALWAYS) { exit_stub(be, 0, o->imm, o->icnt); return 2; }
            if (cc == CC_NEVER)  { exit_stub(be, 0, nxt->imm, nxt->icnt); return 2; }
            u8 *taken = jcc_fwd(e, cc);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_CBZ: case IRO_CBNZ: {
            sync_all(be);
            Src lo = src_hv(be, HV(o->a, 0));
            if (lo.kind == S_IMM) {               /* register reads zero */
                mov_ri(e, EAX, 0);
                lo.kind = S_RM; lo.rm = RM_R(EAX);
            }
            if (w) {
                mov_rs(e, EAX, lo);
                alu_rs(e, AL_OR, EAX, src_hv(be, HV(o->a, 1)));
            } else if (lo.rm.is_reg) {
                op_rr(e, 0x85, lo.rm.reg, lo.rm.reg);      /* test r, r */
            } else {
                alu_rmi(e, AL_CMP, lo.rm, 0);
            }
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = jcc_fwd(e, o->op == IRO_CBZ ? CC_E : CC_NE);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_TBZ: case IRO_TBNZ: {
            sync_all(be);
            unsigned bit = o->cc;
            Src s = src_hv(be, HV(o->a, bit >= 32));
            if (s.kind == S_IMM) {
                mov_ri(e, EAX, 0);
                s.kind = S_RM; s.rm = RM_R(EAX);
            }
            test_rmi(e, s.rm, 1u << (bit & 31));
            const IROp *nxt = &ir->ops[i + 1];
            u8 *taken = jcc_fwd(e, o->op == IRO_TBZ ? CC_E : CC_NE);
            exit_stub(be, 1, nxt->imm, nxt->icnt);
            fwd_here(e, taken);
            exit_stub(be, 0, o->imm, o->icnt);
            return 2;
        }
        case IRO_JMPIND: {
            sync_all(be);
            mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
            mov_rs(e, EDX, src_hv(be, HV(o->a, 1)));
            st_r(e, EAX, M_ebp(OFF_PC));
            st_r(e, EDX, M_ebp(OFF_PC + 4));
            st_r(e, EDX, M_esp(FR_S(0)));         /* the tag's high word */
            icount_add(be, o->icnt);
            /* The entry's byte offset is ((pc >> 2) & (N-1)) * 16, which is
             * (pc & ((N-1) << 2)) * 4 — one mask and the SIB *4 scale, no
             * shift. The table itself is an absolute base, so the probe costs
             * no register beyond the index. */
            mov_rr(e, EDX, EAX);
            alu_ri(e, AL_AND, EDX, (JIT_JC_SIZE - 1) << 2);
            u32 jc = env_abs(be, offsetof(JitEnv, jcache));
            op_rm(e, 0x3B, EAX, RM_M(M_absx(jc, EDX, 2)));
            u8 *miss = jcc_fwd(e, CC_NE);
            ld_r(e, EAX, M_esp(FR_S(0)));
            op_rm(e, 0x3B, EAX, RM_M(M_absx(jc + 4, EDX, 2)));
            u8 *miss2 = jcc_fwd(e, CC_NE);
            op_rm(e, 0xFF, 4, RM_M(M_absx(jc + 8, EDX, 2)));   /* jmp [entry] */
            fwd_here(e, miss);
            fwd_here(e, miss2);
            mov_ri(e, EAX, JIT_EXIT_NONE);
            jmp_to(e, be->env->epilogue_rx);
            break;
        }

        case IRO_LD: case IRO_ST: {
            int k = fuse_enabled() ? jit_mem_run_len(ir, i) : 1;
            if (k >= 2) { emit_mem_run(be, ir, i, k); return k; }
            emit_mem(be, o);
            break;
        }
        case IRO_LDV: case IRO_STV:
            emit_mem(be, o);
            break;
        case IRO_ATOMIC:
            /* Not inlined here: re-run the whole instruction. It is excluded
             * from IRBlock.ninsns, and jit_exec1 counts what it executes, so
             * this retires and counts exactly once. */
            emit_exec1(be, o->imm2pc, (u32)o->imm, 0, o->icnt);
            break;
        case IRO_CALL1:
            emit_exec1(be, o->imm, o->aux, o->w, o->icnt);
            break;

        case IRO_CPULD: {
            int dlo = def_hv(be, HV(o->dst, 0));
            ra_lock(be, dlo);
            ld_r(e, dlo, M_ebp((s32)o->imm));
            ld_r(e, def_hv(be, HV(o->dst, 1)), M_ebp((s32)o->imm + 4));
            break;
        }
        case IRO_CPUST:
            mov_rs(e, EAX, src_hv(be, HV(o->a, 0)));
            st_r(e, EAX, M_ebp((s32)o->imm));
            mov_rs(e, EAX, src_hv(be, HV(o->a, 1)));
            st_r(e, EAX, M_ebp((s32)o->imm + 4));
            break;
        case IRO_FENCE:
            e8(e, 0x0F); e8(e, 0xAE); e8(e, 0xF0);   /* mfence */
            break;

        default:
            /* Unreached: the frontend only emits the ops above, and be_vop_ok
             * declines every IRO_VOP class on this host. */
            e->overflow = 1;
            break;
    }
    return 1;
}

/* ---- chaining ----
 * The patch site is the exit stub's first instruction, `mov dword
 * [ebp+OFF_PC], lo` in its 10-byte disp32 form; five bytes of it become a
 * jmp rel32 and the unpatch rebuilds them from the same fixed encoding. */
_Static_assert(PC_STORE_BYTES >= 5, "patch site must fit a jmp rel32");

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
    u32 off = (u32)OFF_PC, lo = (u32)b->exit_pc[slot];
    site_rw[0] = 0xC7;
    site_rw[1] = (u8)(0x80 | EBP);
    memcpy(site_rw + 2, &off, 4);
    memcpy(site_rw + 6, &lo, 4);          /* only bytes 0..4 were clobbered */
    b->patched[slot] = 0;
}

int be_vop_ok(unsigned vclass, u32 insn) {
    (void)vclass; (void)insn;
    return 0;                             /* no FP/SIMD tier on this host yet */
}

void be_flush_icache(const u8 *rx, const u8 *rw, size_t len) {
    (void)rx; (void)rw; (void)len;        /* x86 fetch is coherent */
}

#endif /* __i386__ */
