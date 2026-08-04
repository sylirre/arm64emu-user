// Instruction accounting across the NaN gate.
//
// The NaN-gated vector classes are "self-counting": the frontend keeps them
// out of IRBlock.ninsns and the backend's fast path bumps c->icount inline,
// so that a gated instruction — whose slow arm re-runs it through jit_exec1,
// and jit_exec1 counts what it executes — is not counted a second time by the
// exit stub. VC_F1 broke that rule: its FSQRT arm is gated (sqrt of a negative
// is an invalid operation and the host's DefaultNaN has the wrong sign, so the
// result must come from exec_fpsimd) while the class sat in ninsns, and every
// FSQRT that produced a NaN retired once and counted twice.
//
// Built twice, once with -DNANGATE. Both builds execute exactly the same
// instructions in the same order; the only difference is whether the FSQRT
// operand makes the gate fire. So the icount an engine reports must be the
// SAME for both builds, and the harness checks that per engine rather than
// comparing engines to each other — which it cannot do, because the JIT does
// not count the trailing HLT block and that constant offset has nothing to do
// with this bug. Before the fix the JIT's two builds differed by four.
//
// Nothing the guest can read exposes icount, so the harness reads the
// [HLT #N] diagnostic from stderr.

    .globl _start
_start:
#ifdef NANGATE
    fmov    d2, #-1.0                   // sqrt(-1): every FSQRT below gates
#else
    fmov    d2, #4.0                    // sqrt(4): none of them do
#endif

    // ungated arms of the same class, present in both builds
    fabs    d0, d2
    fneg    d1, d2
    fmov    d4, d2

    fsqrt   d6, d2
    fsqrt   d7, d2
    fsqrt   d8, d2
    fsqrt   d9, d2

    // close the block so its ninsns actually reaches icount
    b       1f
1:  mov     x0, #0
    hlt     #0
