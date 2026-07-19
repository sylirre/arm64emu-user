/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* M23 test: engine-parity regressions shared with the ARM64_Emulator repo
 * (found there by cross-engine fuzzing, 2026-07-19). Both bugs were
 * x86 --jit only; the test is engine-agnostic and runs under the
 * interpreter, predecode and --jit suites alike.
 *
 * 1. Lazy-NZCV hole: an S-op whose flags are consumed by FCSEL kept host
 *    EFLAGS lazy past the FCSEL, and a following plain ALU op clobbered
 *    them before the next reader (b.cond in a later block) saw them.
 *    Pattern: SUBS ; FCSEL ; ORR ; B.MI.
 * 2. Uncounted NOPs: the JIT frontend consumed PD_NOP without ninsns++.
 *    Here CNTVCT reads the host clock (not icount), so the miscount is
 *    not observable through timer deltas; the >128-NOP run is kept for
 *    coverage of all-NOP blocks crossing the 128-insn block cap.
 *
 * x0=0 on success, else a failing-check id. Builds as a Linux user binary
 * with -DUSERMODE (exit code = x0) for the qemu-aarch64 differential
 * suite; the bare-metal variant stays buildable for the emulator twin. */

.macro NOP16
    nop; nop; nop; nop; nop; nop; nop; nop
    nop; nop; nop; nop; nop; nop; nop; nop
.endm

.text
.global _start
_start:
    /* --- 1. SUBS ; FCSEL ; plain-ALU ; B.cond --- */
    movz    x11, #1
    movz    x1, #1
    fmov    d30, x1
    fmov    d5, xzr
    subs    x5, xzr, x1                 /* 0 - 1: N=1, C=0 */
    fcsel   d3, d30, d5, pl             /* consumes flags (PL: N==0 -> d5) */
    orr     x4, x11, x8, lsl #2         /* plain ALU: EFLAGS clobber on x86 */
    b.mi    1f                          /* must be taken (N=1) */
    b       fail
1:  fmov    x2, d3                      /* PL false -> d5 (= 0) selected */
    cbnz    x2, fail

    /* same shape, flags surviving into a taken CBZ-consumer alternative:
     * ANDS producing Z, FCSEL on NE, EOR clobber, B.EQ */
    movz    x11, #2
    ands    x5, x1, xzr                 /* Z=1 */
    fcsel   d3, d5, d30, ne             /* NE false -> d30 (= 1) */
    eor     x4, x11, x11, lsl #3
    b.eq    2f                          /* must be taken (Z=1) */
    b       fail
2:  fmov    x2, d3
    cmp     x2, #1
    b.ne    fail

    /* --- 2. 144 NOPs: an all-NOP block boundary past the 128-insn cap --- */
    movz    x11, #3
    NOP16
    NOP16
    NOP16
    NOP16
    NOP16
    NOP16
    NOP16
    NOP16
    NOP16

    movz    x0, #0
    b       done

fail:
    mov     x0, x11
done:
#ifdef USERMODE
    movz    x8, #93                     /* exit(x0) */
    svc     #0
#else
    hlt     #0
#endif
