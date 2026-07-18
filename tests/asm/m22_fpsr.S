/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* M22 self-test: FPSR cumulative exception flags (IOC/DZC/OFC/UFC/IXC), the
 * QC sticky saturation bit, and the quiet-vs-signaling compare split
 * (FCMP/FCCMP raise IOC only for signaling NaNs, FCMPE/FCCMPE for any NaN).
 *
 * Pattern per check: clear FPSR, run exactly one FP operation, read FPSR
 * back before any flag-setting integer compare runs. Covers scalar and
 * vector arithmetic (the vector forms exercise the JIT's inline SSE paths,
 * whose host status-word accumulation must match the interpreter), converts
 * (rounding IXC, saturation/NaN IOC), FRINTX vs the other FRINTs, FJCVTZS,
 * FCVT precision changes into half (OFC/UFC), FCVTXN round-to-odd, the
 * FRECPE/FRSQRTE specials (DZC/IOC/OFC), FRECPS 0*inf -> 2.0 with no IOC,
 * FMAXNM sNaN, and FPSR write/readback.
 *
 * x0=0 on success, else failing-check id. Builds with -DUSERMODE as a Linux
 * user binary (exit code = x0) so every expected value is validated under
 * qemu-aarch64 -cpu max first. */
.arch armv8.5-a+fp16

.macro CKX reg, val, id
    movz    x11, #\id
    ldr     x9, =\val
    cmp     \reg, x9
    b.ne    fail
.endm

.macro CLRF
    msr     fpsr, xzr
.endm

.macro RDF
    mrs     x13, fpsr
.endm

.text
.global _start
_start:
    ldr     x20, =fdat

    /* ---- scalar double arithmetic ---- */
    ldr     d0, [x20, #0]                /* 1.0 */
    ldr     d1, [x20, #8]                /* 2^-60 */
    CLRF
    fadd    d2, d0, d0                   /* exact */
    RDF
    CKX     x13, 0, 1
    CLRF
    fadd    d2, d0, d1                   /* inexact */
    RDF
    CKX     x13, 0x10, 2
    ldr     d3, [x20, #16]               /* 0.0 */
    CLRF
    fdiv    d2, d0, d3                   /* 1/0 */
    RDF
    CKX     x13, 0x2, 3
    CLRF
    fdiv    d2, d3, d3                   /* 0/0 */
    RDF
    CKX     x13, 0x1, 4
    ldr     d4, [x20, #24]               /* -1.0 */
    CLRF
    fsqrt   d2, d4
    RDF
    CKX     x13, 0x1, 5
    ldr     d5, [x20, #32]               /* DBL_MAX */
    CLRF
    fmul    d2, d5, d5
    RDF
    CKX     x13, 0x14, 6                 /* OFC|IXC */
    ldr     d6, [x20, #40]               /* DBL_MIN */
    CLRF
    fmul    d2, d6, d6
    RDF
    CKX     x13, 0x18, 7                 /* UFC|IXC */
    ldr     d7, [x20, #48]               /* qNaN */
    CLRF
    fadd    d2, d7, d0                   /* quiet NaN arithmetic: no IOC */
    RDF
    CKX     x13, 0, 8
    ldr     d8, [x20, #56]               /* sNaN */
    CLRF
    fadd    d2, d8, d0
    RDF
    CKX     x13, 0x1, 9

    /* ---- quiet vs signaling compares ---- */
    CLRF
    fcmp    d7, d0                       /* quiet compare, qNaN: no IOC */
    RDF
    mrs     x14, nzcv
    CKX     x13, 0, 10
    CKX     x14, 0x30000000, 11          /* unordered -> C|V */
    CLRF
    fcmpe   d7, d0                       /* signaling compare, qNaN: IOC */
    RDF
    mrs     x14, nzcv
    CKX     x13, 0x1, 12
    CKX     x14, 0x30000000, 13
    CLRF
    fcmp    d8, d0                       /* quiet compare, sNaN: IOC */
    RDF
    CKX     x13, 0x1, 14
    CLRF
    fccmpe  d7, d0, #0, al               /* condition true: compares */
    RDF
    CKX     x13, 0x1, 15
    CLRF
    fccmp   d7, d0, #0, al               /* quiet conditional, qNaN: no IOC */
    RDF
    CKX     x13, 0, 16

    /* ---- converts ---- */
    ldr     d9, [x20, #64]               /* 1.5 */
    CLRF
    fcvtzs  w2, d9
    RDF
    CKX     x13, 0x10, 17                /* rounded: IXC */
    CKX     x2, 1, 18
    ldr     d10, [x20, #72]              /* 2^40 */
    CLRF
    fcvtzs  w2, d10
    RDF
    CKX     x13, 0x1, 19                 /* saturated: IOC only */
    CKX     x2, 0x7FFFFFFF, 20
    CLRF
    fcvtzs  w2, d7                       /* NaN -> 0, IOC */
    RDF
    CKX     x13, 0x1, 21
    CKX     x2, 0, 22
    CLRF
    fcvtzs  x2, d0                       /* exact: no flags */
    RDF
    CKX     x13, 0, 23
    ldr     x3, =0x1000000000000001      /* 2^60+1: rounds when cast */
    CLRF
    scvtf   d2, x3
    RDF
    CKX     x13, 0x10, 24
    mov     x3, #16
    CLRF
    scvtf   d2, x3                       /* exact int -> fp */
    RDF
    CKX     x13, 0, 25

    /* ---- FRINT: only FRINTX raises IXC ---- */
    CLRF
    frintx  d2, d9                       /* 1.5 -> 2.0: IXC */
    RDF
    CKX     x13, 0x10, 26
    CLRF
    frintm  d2, d9                       /* other FRINTs: never IXC */
    RDF
    CKX     x13, 0, 27
    CLRF
    frintx  d2, d0                       /* exact: no IXC */
    RDF
    CKX     x13, 0, 28

    /* ---- FJCVTZS flag behavior ---- */
    CLRF
    fjcvtzs w2, d9                       /* 1.5: in range, inexact */
    RDF
    CKX     x13, 0x10, 29
    CLRF
    fjcvtzs w2, d10                      /* 2^40: wraps -> IOC */
    RDF
    CKX     x13, 0x1, 30
    CLRF
    fjcvtzs w2, d0                       /* 1.0: exact */
    RDF
    CKX     x13, 0, 31

    /* ---- vector arithmetic (JIT inline SSE paths) ---- */
    ldr     q0, [x20, #80]               /* .2d {1.0, 1.0} */
    ldr     q1, [x20, #96]               /* .2d {2^-60, 0.0} */
    CLRF
    fadd    v2.2d, v0.2d, v1.2d          /* lane 0 inexact */
    RDF
    CKX     x13, 0x10, 32
    ldr     q3, [x20, #112]              /* .4s {1.0f x4} */
    ldr     q4, [x20, #128]              /* .4s {0, 1.0f, 2.0f, 4.0f} */
    CLRF
    fdiv    v2.4s, v3.4s, v4.4s          /* lane 0: 1/0 */
    RDF
    CKX     x13, 0x2, 33
    ldr     q5, [x20, #144]              /* .4s {qNaN, 1.0f, 1.0f, 1.0f} */
    CLRF
    fcmgt   v2.4s, v5.4s, v3.4s          /* signaling vector compare: IOC */
    RDF
    CKX     x13, 0x1, 34
    CLRF
    fcmeq   v2.4s, v5.4s, v3.4s          /* quiet vector compare: no IOC */
    RDF
    CKX     x13, 0, 35
    ldr     q6, [x20, #160]              /* .4s {sNaN, 1.0f, 1.0f, 1.0f} */
    CLRF
    fcmeq   v2.4s, v6.4s, v3.4s          /* sNaN raises even in quiet compare */
    RDF
    CKX     x13, 0x1, 36
    CLRF
    frintx  v2.2d, v1.2d                 /* lane 0 = 2^-60: inexact */
    RDF
    CKX     x13, 0x10, 37
    CLRF
    frinti  v2.2d, v1.2d                 /* FRINTI: no IXC */
    RDF
    CKX     x13, 0, 38

    /* ---- FMAXNM / FMAX NaN handling ---- */
    CLRF
    fmaxnm  d2, d8, d0                   /* sNaN operand: IOC */
    RDF
    CKX     x13, 0x1, 39
    CLRF
    fmaxnm  d2, d7, d0                   /* qNaN: numeric result, no IOC */
    RDF
    CKX     x13, 0, 40
    CLRF
    fmax    d2, d7, d0                   /* qNaN: NaN result, still no IOC */
    RDF
    CKX     x13, 0, 41

    /* ---- estimates and steps ---- */
    ldr     d3, [x20, #16]               /* 0.0 (q3 clobbered d3 above) */
    CLRF
    frecpe  d2, d3                       /* 1/0 estimate -> inf, DZC */
    RDF
    CKX     x13, 0x2, 42
    ldr     s0, [x20, #176]              /* -1.0f */
    CLRF
    frsqrte s2, s0                       /* negative: IOC */
    RDF
    CKX     x13, 0x1, 43
    ldr     s0, [x20, #180]              /* 2^-152f (bits 0x00100000) */
    CLRF
    frecpe  s2, s0                       /* |x| < 2^-128: inf, OFC|IXC */
    RDF
    CKX     x13, 0x14, 44
    ldr     d0, [x20, #16]               /* 0.0 */
    ldr     d1, [x20, #184]              /* +inf */
    CLRF
    frecps  d2, d0, d1                   /* FPRecipStepFused 0*inf -> 2.0, no IOC */
    RDF
    CKX     x13, 0, 45
    fmov    x2, d2
    CKX     x2, 0x4000000000000000, 46   /* exactly 2.0 */
    CLRF
    frsqrts d2, d1, d0                   /* 0*inf -> 1.5 */
    RDF
    CKX     x13, 0, 47
    fmov    x2, d2
    CKX     x2, 0x3FF8000000000000, 48   /* exactly 1.5 */

    /* ---- QC: saturating integer ops ---- */
    ldr     q0, [x20, #192]              /* .4s {INT32_MAX x2, 1, 1} */
    ldr     q1, [x20, #208]              /* .4s {1,1,1,1} */
    CLRF
    sqadd   v2.4s, v0.4s, v1.4s          /* saturates: QC */
    RDF
    CKX     x13, 0x08000000, 49
    CLRF
    sqadd   v2.4s, v1.4s, v1.4s          /* no saturation: no QC */
    RDF
    CKX     x13, 0, 50
    CLRF
    uqsub   v2.4s, v1.4s, v0.4s          /* 1 - INT32_MAX: clamps to 0, QC */
    RDF
    CKX     x13, 0x08000000, 51
    CLRF
    sqxtn   v2.4h, v0.4s                 /* INT32_MAX -> 16 bits: QC */
    RDF
    CKX     x13, 0x08000000, 52

    /* ---- half-precision converts ---- */
    ldr     s0, [x20, #224]              /* 100000.0f: overflows half */
    CLRF
    fcvt    h2, s0
    RDF
    CKX     x13, 0x14, 53                /* OFC|IXC */
    ldr     s0, [x20, #228]              /* 2^-30f: underflows half */
    CLRF
    fcvt    h2, s0
    RDF
    CKX     x13, 0x18, 54                /* UFC|IXC */
    ldr     h0, [x20, #232]              /* half sNaN 0x7D00 */
    CLRF
    fcvt    s2, h0                       /* convert quiets + IOC */
    RDF
    CKX     x13, 0x1, 55
    fmov    w2, s2
    CKX     x2, 0x7FE00000, 56           /* payload shifted, quiet bit set */
    ldr     h0, [x20, #234]              /* half 1.0 */
    ldr     h1, [x20, #236]              /* half min subnormal 2^-24 */
    CLRF
    fadd    h2, h0, h1                   /* rounds back to 1.0: IXC only */
    RDF
    CKX     x13, 0x10, 57

    /* ---- FCVTXN round-to-odd ---- */
    ldr     d0, [x20, #240]              /* 1 + 2^-40 */
    CLRF
    fcvtxn  s2, d0
    RDF
    CKX     x13, 0x10, 58                /* inexact, sticky LSB */
    fmov    w2, s2
    CKX     x2, 0x3F800001, 59

    /* ---- non-arithmetic moves never raise ---- */
    ldr     d0, [x20, #56]               /* sNaN */
    CLRF
    fabs    d2, d0
    fneg    d3, d0
    RDF
    CKX     x13, 0, 60

    /* ---- FPSR write / readback ---- */
    ldr     x2, =0x0800009F              /* QC | IDC | all cumulative */
    msr     fpsr, x2
    mrs     x13, fpsr
    CKX     x13, 0x0800009F, 61
    CLRF
    RDF
    CKX     x13, 0, 62

    mov     x0, #0
done:
#ifdef USERMODE
    movz    x8, #93                      /* exit(x0) */
    svc     #0
#else
    hlt     #0
#endif
fail:
    mov     x0, x11
    b       done

.data
.balign 16
fdat:
    .quad 0x3FF0000000000000             /* +0:   1.0 */
    .quad 0x3C30000000000000             /* +8:   2^-60 */
    .quad 0x0000000000000000             /* +16:  0.0 */
    .quad 0xBFF0000000000000             /* +24: -1.0 */
    .quad 0x7FEFFFFFFFFFFFFF             /* +32:  DBL_MAX */
    .quad 0x0010000000000000             /* +40:  DBL_MIN */
    .quad 0x7FF8000000000000             /* +48:  qNaN */
    .quad 0x7FF4000000000000             /* +56:  sNaN */
    .quad 0x3FF8000000000000             /* +64:  1.5 */
    .quad 0x4270000000000000             /* +72:  2^40 */
    .quad 0x3FF0000000000000             /* +80:  .2d lane0 1.0 */
    .quad 0x3FF0000000000000             /* +88:  .2d lane1 1.0 */
    .quad 0x3C30000000000000             /* +96:  .2d lane0 2^-60 */
    .quad 0x0000000000000000             /* +104: .2d lane1 0.0 */
    .word 0x3F800000, 0x3F800000, 0x3F800000, 0x3F800000  /* +112: 1.0f x4 */
    .word 0x00000000, 0x3F800000, 0x40000000, 0x40800000  /* +128: 0,1,2,4 */
    .word 0x7FC00000, 0x3F800000, 0x3F800000, 0x3F800000  /* +144: qNaN,1,1,1 */
    .word 0x7FA00000, 0x3F800000, 0x3F800000, 0x3F800000  /* +160: sNaN,1,1,1 */
    .word 0xBF800000                     /* +176: -1.0f */
    .word 0x00100000                     /* +180: 2^-152f */
    .quad 0x7FF0000000000000             /* +184: +inf */
    .word 0x7FFFFFFF, 0x7FFFFFFF, 1, 1   /* +192: INT32_MAX x2, 1, 1 */
    .word 1, 1, 1, 1                     /* +208: 1 x4 */
    .word 0x47C35000                     /* +224: 100000.0f */
    .word 0x30800000                     /* +228: 2^-30f */
    .hword 0x7D00                        /* +232: half sNaN */
    .hword 0x3C00                        /* +234: half 1.0 */
    .hword 0x0001                        /* +236: half min subnormal */
    .hword 0                             /* +238: pad */
    .quad 0x3FF0000000010000             /* +240: 1 + 2^-40 */
