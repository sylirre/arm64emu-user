/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* CPU core: reset, single-step driver, condition codes, dump. */
#include "cpu.h"
#include "mmu.h"
#include "sysreg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_trace = 0;
int g_singlestep = 0;
int g_dbg = 0;
int g_rtrace = 0;
int g_prof = 0;
u64 g_tpc = 0;       /* env AETPC: dump state whenever pc == this (debug) */
int g_ring = 0;      /* env AERING: record a ring buffer of recent steps */
u64 g_watch = 0;     /* env AEWATCH: log writes to [g_watch, g_watch+8) */
int g_iabort_log = 0;/* env AEIABORT: log instruction aborts (debug) */
int g_rtclock = 0;   /* env AE_RTCLOCK: host-clock timer (default = deterministic) */
u64 g_vawatch = 0;   /* env AEVAW: log writes whose range covers this VA (debug) */
int g_systrace = 0;  /* unused in linux-user (the syscall layer has -strace) */

/* Kept as a no-op: decode.c calls this before every SVC; the linux-user
 * syscall tracing lives in syscall.c (-strace). */
void systrace_svc(CPU *c) { (void)c; }

/* Coverage-divergence finder (env AECOV=file): a sorted set of PCs QEMU is known
 * to execute. The first PC our run executes that is NOT in this set marks where
 * we left QEMU's path — i.e. at/just after the first control-flow divergence. */
static u64 *g_cov;
static size_t g_cov_n;
static int cmp_u64(const void *a, const void *b) {
    u64 x = *(const u64 *)a, y = *(const u64 *)b;
    return (x > y) - (x < y);
}
void cov_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cov: cannot open %s\n", path); return; }
    size_t cap = 4096; g_cov = malloc(cap * sizeof(u64)); g_cov_n = 0;
    char line[64];
    while (fgets(line, sizeof line, f)) {
        u64 v = strtoull(line, NULL, 16);
        if (g_cov_n == cap) { cap *= 2; g_cov = realloc(g_cov, cap * sizeof(u64)); }
        g_cov[g_cov_n++] = v;
    }
    fclose(f);
    qsort(g_cov, g_cov_n, sizeof(u64), cmp_u64);
    fprintf(stderr, "cov: loaded %zu PCs from %s\n", g_cov_n, path);
}
static bool cov_has(u64 pc) {
    return bsearch(&pc, g_cov, g_cov_n, sizeof(u64), cmp_u64) != NULL;
}

/* Recent-instruction ring buffer: records (pc, insn, x-snapshot) so a fault can
 * be explained by the basic block that led to it. */
#define RING_N 96
static struct { u64 pc; u32 insn; u64 x0, x1, x2; } g_ringbuf[RING_N];
static unsigned g_ringpos;
static void ring_record(CPU *c, u32 insn) {
    unsigned i = g_ringpos++ & (RING_N - 1);
    g_ringbuf[i].pc = c->pc; g_ringbuf[i].insn = insn;
    g_ringbuf[i].x0 = c->x[0]; g_ringbuf[i].x1 = c->x[1]; g_ringbuf[i].x2 = c->x[2];
}
void ring_dump(void) {
    if (!g_ring) return;
    fprintf(stderr, "[ring] last %d instructions (oldest first):\n", RING_N);
    for (int k = 0; k < RING_N; k++) {
        unsigned i = (g_ringpos + k) & (RING_N - 1);
        if (g_ringbuf[i].pc == 0) continue;
        fprintf(stderr, "  pc=0x%llx insn=0x%08x x0=0x%llx x1=0x%llx x2=0x%llx\n",
                (unsigned long long)g_ringbuf[i].pc, g_ringbuf[i].insn,
                (unsigned long long)g_ringbuf[i].x0, (unsigned long long)g_ringbuf[i].x1,
                (unsigned long long)g_ringbuf[i].x2);
    }
}

/* Lightweight hot-PC profiler (env AEPROF=1). A direct-mapped histogram that
 * tells whether the CPU is spinning in a tight loop vs. making broad progress.
 * Off by default; one predictable branch in the step loop when enabled. */
#define PROF_SLOTS 65536
static struct { u64 pc; u64 hits; } g_prof_tab[PROF_SLOTS];
static void prof_record(u64 pc) {
    unsigned i = (unsigned)((pc >> 2) & (PROF_SLOTS - 1));
    /* linear probe a few slots to limit collisions */
    for (int k = 0; k < 8; k++) {
        unsigned j = (i + k) & (PROF_SLOTS - 1);
        if (g_prof_tab[j].hits == 0 || g_prof_tab[j].pc == pc) {
            g_prof_tab[j].pc = pc; g_prof_tab[j].hits++; return;
        }
    }
    g_prof_tab[i].hits++;   /* collision overflow: still counts */
}
void prof_dump(void) {
    if (!g_prof) return;
    /* selection of the top 25 by hits */
    for (int n = 0; n < 25; n++) {
        unsigned best = 0; u64 bh = 0;
        for (unsigned j = 0; j < PROF_SLOTS; j++)
            if (g_prof_tab[j].hits > bh) { bh = g_prof_tab[j].hits; best = j; }
        if (bh == 0) break;
        fprintf(stderr, "[prof] pc=0x%llx hits=%llu\n",
                (unsigned long long)g_prof_tab[best].pc, (unsigned long long)bh);
        g_prof_tab[best].hits = 0;   /* consume */
    }
}

void cpu_reset(CPU *c, u64 entry, unsigned reset_el) {
    struct Machine *m = c->m;
    memset(c, 0, sizeof(*c));
    c->m = m;
    c->pc = entry;
    c->el = reset_el;
    c->sp_sel = 1;                       /* SPSel=1 at reset (use SP_ELx) */
    c->daif = PS_D | PS_A | PS_I | PS_F; /* all masked at reset */
    c->nzcv = 0;
    c->cntfrq = 24000000ULL;             /* 24 MHz, matches virt DTB */
    /* MPIDR_EL1: bit31 RES1, single core affinity 0. */
    c->mpidr = (1ULL << 31);
    if (sysreg_init) sysreg_init(c);
}

bool cond_holds(CPU *c, unsigned cond) {
    bool N = (c->nzcv & PS_N) != 0;
    bool Z = (c->nzcv & PS_Z) != 0;
    bool C = (c->nzcv & PS_C) != 0;
    bool V = (c->nzcv & PS_V) != 0;
    bool r;
    switch (cond >> 1) {
        case 0: r = Z; break;                 /* EQ/NE */
        case 1: r = C; break;                 /* CS/CC */
        case 2: r = N; break;                 /* MI/PL */
        case 3: r = V; break;                 /* VS/VC */
        case 4: r = C && !Z; break;           /* HI/LS */
        case 5: r = (N == V); break;          /* GE/LT */
        case 6: r = (N == V) && !Z; break;    /* GT/LE */
        default: r = true; break;             /* AL/NV */
    }
    if ((cond & 1) && cond != 0xf) r = !r;
    return r;
}

/* Set whenever any per-instruction debug facility is active (trace/rtrace/prof/
 * ring/cov/tpc). Keeps the step hot path to a single predictable branch when no
 * debugging is enabled, preserving interpreter throughput. */
int g_debug_hooks = 0;

/* Run the active per-instruction debug facilities. Returns true if execution
 * should stop (the coverage divergence finder hit a foreign PC). Only ever
 * called when g_debug_hooks is set. */
static bool step_debug(CPU *c, u32 insn) {
    if (g_rtrace) {
        fprintf(stderr, "P%llx", (unsigned long long)c->pc);
        for (int i = 0; i < 31; i++) fprintf(stderr, " %llx", (unsigned long long)c->x[i]);
        fprintf(stderr, " S%llx\n", (unsigned long long)*cpu_cur_sp(c));
    }
    if (g_trace) {
        fprintf(stderr, "%016llx: %08x  [el%u nzcv=%c%c%c%c]\n",
                (unsigned long long)c->pc, insn, c->el,
                (c->nzcv & PS_N) ? 'N' : '.', (c->nzcv & PS_Z) ? 'Z' : '.',
                (c->nzcv & PS_C) ? 'C' : '.', (c->nzcv & PS_V) ? 'V' : '.');
    }
    if (g_prof) prof_record(c->pc);
    if (g_ring) ring_record(c, insn);
    if (g_cov_n && c->icount > 1000 && !cov_has(c->pc)) {
        fprintf(stderr, "[cov] FIRST FOREIGN PC=0x%llx insn=0x%08x icount=%llu el=%u\n",
                (unsigned long long)c->pc, insn, (unsigned long long)c->icount, c->el);
        ring_dump();
        c->stop = true;
        return true;
    }
    if (g_tpc && c->pc == g_tpc) {
        fprintf(stderr, "[tpc] pc=0x%llx insn=0x%08x el=%u sp=0x%llx\n",
                (unsigned long long)c->pc, insn, c->el,
                (unsigned long long)*cpu_cur_sp(c));
        for (int i = 0; i < 31; i++)
            fprintf(stderr, " x%d=0x%llx", i, (unsigned long long)c->x[i]);
        fprintf(stderr, "\n");
    }
    return false;
}

StepResult cpu_step(CPU *c) {
    if (c->stop) return STEP_HALT;

    /* Pending IRQ delivery (single-CPU). FIQ handled the same way. */
    if (c->fiq_line && !(c->daif & PS_F)) {
        exception_take(c, EXC_FIQ, 0, 0, c->pc);
        return STEP_OK;
    }
    if (c->irq_line && !(c->daif & PS_I)) {
        exception_take(c, EXC_IRQ, 0, 0, c->pc);
        return STEP_OK;
    }

    if (c->halted) return STEP_OK;   /* WFI/WFE: caller waits for an event */

    /* Record the current instruction address BEFORE the fetch: if the fetch
     * faults (instruction abort), the synchronous exception's ELR/FAR must point
     * at the faulting address, not the previously executed instruction. */
    c->cur_insn_pc = c->pc;

    u32 insn;
    if (!mem_ifetch(c, c->pc, &insn)) return STEP_OK;  /* fetch raised an abort */

    if (g_debug_hooks && step_debug(c, insn)) return STEP_HALT;

    c->pc += 4;
    exec_a64(c, insn);
    c->icount++;

    return c->stop ? STEP_HALT : STEP_OK;
}

void cpu_dump(CPU *c) {
    for (int i = 0; i < 31; i++) {
        fprintf(stderr, "x%-2d=%016llx%s", i, (unsigned long long)c->x[i],
                (i % 4 == 3) ? "\n" : "  ");
    }
    fprintf(stderr, "\nsp =%016llx  pc =%016llx  el=%u  spsel=%u\n",
            (unsigned long long)*cpu_cur_sp(c), (unsigned long long)c->pc,
            c->el, c->sp_sel);
    fprintf(stderr, "nzcv=%c%c%c%c daif=%c%c%c%c  icount=%llu\n",
            (c->nzcv & PS_N) ? 'N' : '.', (c->nzcv & PS_Z) ? 'Z' : '.',
            (c->nzcv & PS_C) ? 'C' : '.', (c->nzcv & PS_V) ? 'V' : '.',
            (c->daif & PS_D) ? 'D' : '.', (c->daif & PS_A) ? 'A' : '.',
            (c->daif & PS_I) ? 'I' : '.', (c->daif & PS_F) ? 'F' : '.',
            (unsigned long long)c->icount);
}
