/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* AArch64 CPU state and core interpreter interface. */
#ifndef A64_CPU_H
#define A64_CPU_H

#include "types.h"

struct Machine;

/* PSTATE condition flag bit positions (matching SPSR_ELx / NZCV layout). */
#define PS_N (1u << 31)
#define PS_Z (1u << 30)
#define PS_C (1u << 29)
#define PS_V (1u << 28)

/* DAIF mask bits (as in PSTATE/SPSR bits [9:6]). */
#define PS_D (1u << 9)
#define PS_A (1u << 8)
#define PS_I (1u << 7)
#define PS_F (1u << 6)

/* Exception entry kinds (offsets within a vector group are computed from these). */
typedef enum {
    EXC_SYNC = 0,
    EXC_IRQ  = 1,
    EXC_FIQ  = 2,
    EXC_SERROR = 3,
} ExcKind;

/* Result of executing a single instruction. */
typedef enum {
    STEP_OK = 0,
    STEP_HALT,        /* fatal: unimplemented / stop the machine */
} StepResult;

typedef struct CPU {
    /* General purpose. x[31] is reserved; use reg helpers for XZR/SP semantics. */
    u64 x[31];
    u64 pc;

    /* PSTATE */
    u32 nzcv;         /* uses PS_N/Z/C/V bit positions */
    u32 daif;         /* uses PS_D/A/I/F bit positions */
    u8  el;           /* current exception level 0..3 (we implement 0,1; minimal 2) */
    u8  sp_sel;       /* SPSel: 0 => SP_EL0, 1 => SP_ELx */

    /* Banked stack pointers SP_EL0..SP_EL3 */
    u64 sp_el[4];

    /* SIMD/FP */
    V128 v[32];
    u32 fpcr, fpsr;
    bool fp_trapped;  /* set if CPACR/CPTR disables FP (kept simple) */

    /* Banked system registers (index by EL where meaningful) */
    u64 sctlr[4];
    u64 ttbr0[4];
    u64 ttbr1[4];
    u64 tcr[4];
    u64 mair[4];
    u64 amair[4];
    u64 vbar[4];
    u64 esr[4];
    u64 far[4];
    u64 elr[4];
    u64 spsr[4];
    u64 tpidr[4];     /* TPIDR_ELx */
    u64 tpidrro_el0;
    u64 contextidr_el1;
    u64 cpacr_el1;
    u64 mdscr_el1;
    u64 par_el1;

    /* Identification / affinity */
    u64 mpidr;

    /* Generic timer */
    u64 cntfrq;
    u64 cntp_ctl, cntp_cval, cntp_tval_base;
    u64 cntv_ctl, cntv_cval;
    u64 cntkctl_el1;
    s64 cntvoff;
    u64 cntpct_base;   /* AE_RTCLOCK mode: host ns at which the counter == 0 */
    u64 timer_skip;    /* deterministic mode: virtual ticks fast-forwarded over WFI idle */

    /* Exclusive monitor. excl_val[2] hold the values LDXR/LDXP loaded so STXR/
     * STXP can do a real host compare-and-swap (SMP-correct across guest
     * threads on weakly ordered hosts), not just an address match. */
    bool excl_valid;
    u64  excl_addr;
    u64  excl_size;
    u64  excl_val, excl_val2;

    /* Interrupt input lines (driven by the GIC). */
    bool irq_line;
    bool fiq_line;

    /* Run control */
    bool halted;       /* WFI/WFE: waiting for an event */
    bool stop;         /* machine should terminate */
    bool reset;        /* PSCI SYSTEM_RESET: warm-reboot the machine, don't exit */
    u64  icount;       /* retired instruction count */
    u64  cur_insn_pc;  /* address of the instruction currently executing */

    struct Machine *m;
} CPU;

/* ---- Register access helpers (XZR vs SP semantics) ---- */

/* Current selected stack pointer. */
static inline u64 *cpu_cur_sp(CPU *c) {
    return c->sp_sel ? &c->sp_el[c->el] : &c->sp_el[0];
}

/* Read GPR with reg==31 meaning XZR (zero). */
static inline u64 reg_x(CPU *c, unsigned n) {
    return (n == 31) ? 0 : c->x[n];
}
/* Write GPR with reg==31 meaning discard. */
static inline void set_x(CPU *c, unsigned n, u64 v) {
    if (n != 31) c->x[n] = v;
}
/* Read GPR with reg==31 meaning SP. */
static inline u64 reg_xsp(CPU *c, unsigned n) {
    return (n == 31) ? *cpu_cur_sp(c) : c->x[n];
}
static inline void set_xsp(CPU *c, unsigned n, u64 v) {
    if (n == 31) *cpu_cur_sp(c) = v; else c->x[n] = v;
}

/* 32/64-bit width helpers: result truncation when sf==0. */
static inline u64 reg_x_sz(CPU *c, unsigned n, bool is64) {
    u64 v = reg_x(c, n);
    return is64 ? v : (u32)v;
}
static inline void set_x_sz(CPU *c, unsigned n, bool is64, u64 v) {
    set_x(c, n, is64 ? v : (u32)v);
}

/* Build a PSTATE/SPSR word from current state. */
u32 cpu_pack_spsr(CPU *c);
void cpu_unpack_spsr(CPU *c, u32 spsr);

/* ---- Core API ---- */
void cpu_reset(CPU *c, u64 entry, unsigned reset_el);
StepResult cpu_step(CPU *c);                 /* fetch/decode/execute one instruction */

/* Take an exception of `kind` to EL1 (we route all exceptions to EL1).
 * ret_addr is the value placed in ELR_EL1. */
void exception_take(CPU *c, ExcKind kind, u64 esr, u64 far, u64 ret_addr);

/* Raise a synchronous exception (ELR = address of the faulting instruction). */
void cpu_raise_sync(CPU *c, u64 esr, u64 far);

/* Debug dump. */
void cpu_dump(CPU *c);

/* Decoder entry: execute one already-fetched instruction word. Defined in decode.c. */
void exec_a64(CPU *c, u32 insn);

/* Condition code evaluation (cond 0..15) using current NZCV. */
bool cond_holds(CPU *c, unsigned cond);

/* Global trace flags (set from CLI). */
extern int g_trace;        /* per-instruction trace */
extern int g_singlestep;   /* unused placeholder for parity with QEMU */
extern int g_dbg;          /* targeted device/IRQ debug (env AEDBG) */
extern int g_rtrace;       /* compact register trace for differential debugging */
extern int g_prof;         /* hot-PC profiler (env AEPROF) */
void prof_dump(void);      /* print the hottest PCs (no-op unless g_prof) */
extern u64 g_tpc;          /* env AETPC: dump CPU state when pc == this */
extern int g_ring;         /* env AERING: ring-buffer recent steps */
void ring_dump(void);      /* print the recent-instruction ring buffer */
extern u64 g_watch;        /* env AEWATCH: log writes to [g_watch, g_watch+8) */
extern int g_debug_hooks;  /* OR of all per-step debug facilities (perf guard) */
extern int g_iabort_log;   /* env AEIABORT: log instruction aborts */
extern int g_rtclock;      /* env AE_RTCLOCK: drive the generic timer from the host
                              clock instead of the deterministic instruction count */
extern u64 g_vawatch;      /* env AEVAW: log writes whose range covers this VA */
extern int g_systrace;     /* env AESYS: trace mm syscalls (mmap/brk/munmap/...) */
void systrace_svc(CPU *c); /* record an in-flight mm syscall for return logging */
extern int g_heaptrack;    /* env AEHEAP: musl malloc/free/realloc double-alloc finder */
extern u64 g_heap_at;      /* env AEHEAP_AT: log every alloc/free touching this VA */
void heaptrack_init(void); /* allocate the heap-tracker tables (call once at startup) */
void heaptrack_report(void); /* print heap-tracker stats (call once at exit) */
void heaptrack_query(CPU *c, u64 va); /* report which live block (if any) contains va */
void cov_load(const char *path);  /* load QEMU coverage PC set (divergence finder) */

#endif /* A64_CPU_H */
