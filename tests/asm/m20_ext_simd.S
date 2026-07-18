/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* M20 self-test: ARMv8.1-8.4 AdvSIMD extensions — FEAT_RDM SQRDMLAH/SQRDMLSH
 * (vector, scalar, by-element; INT_MIN^2 and rounding-tips-saturation
 * corners), FEAT_DotProd SDOT/UDOT, FEAT_FCMA FCMLA/FCADD, FEAT_FHM
 * FMLAL/FMLSL, plus the vector FRINTX/FRINTI FPCR.RMode pin. x0=0 on
 * success, else failing-check id. Expected values are precomputed from the
 * ARM ARM pseudocode; the same file builds as a Linux user binary with
 * -DUSERMODE (exit code = x0) to cross-check every value against real
 * hardware semantics under qemu-aarch64 -cpu max before trusting it as the
 * emulator's reference. */
.arch armv8.5-a+fp16fml

.macro CKX reg, val, id
    movz    x11, #\id
    ldr     x9, =\val
    cmp     \reg, x9
    b.ne    fail
.endm

.text
.global _start
_start:
    /* ================= FEAT_RDM: SQRDMLAH/SQRDMLSH ================= */
    ldr     x10, =v_a
    ldr     q1, [x10]                    /* Vn .8h */
    ldr     x10, =v_b
    ldr     q2, [x10]                    /* Vm .8h */
    ldr     x10, =v_d
    ldr     q0, [x10]                    /* Vd accumulator */
    sqrdmlah v0.8h, v1.8h, v2.8h
    mov     x2, v0.d[0]
    CKX     x2, 0x80001fff7fff7fff, 1
    mov     x2, v0.d[1]
    CKX     x2, 0x8000163400007fff, 2

    ldr     x10, =v_d
    ldr     q0, [x10]
    sqrdmlsh v0.8h, v1.8h, v2.8h
    mov     x2, v0.d[0]
    CKX     x2, 0xa000dfff80038000, 3
    mov     x2, v0.d[1]
    CKX     x2, 0x93650e3400007ffe, 4

    ldr     x10, =w_a
    ldr     q1, [x10]                    /* Vn .4s */
    ldr     x10, =w_b
    ldr     q2, [x10]                    /* Vm .4s */
    ldr     x10, =w_d
    ldr     q0, [x10]
    sqrdmlah v0.4s, v1.4s, v2.4s
    mov     x2, v0.d[0]
    CKX     x2, 0x7fffffff7fffffff, 5
    mov     x2, v0.d[1]
    CKX     x2, 0x800000001fffffff, 6

    ldr     x10, =w_d
    ldr     q0, [x10]
    sqrdmlsh v0.4s, v1.4s, v2.4s
    mov     x2, v0.d[0]
    CKX     x2, 0x8000000380000000, 7
    mov     x2, v0.d[1]
    CKX     x2, 0xa0000000dfffffff, 8

    /* ---- by-element forms ---- */
    ldr     x10, =v_a
    ldr     q1, [x10]
    ldr     x10, =v_b
    ldr     q2, [x10]
    ldr     x10, =v_d
    ldr     q0, [x10]
    sqrdmlah v0.8h, v1.8h, v2.h[7]       /* idx 7 exercises H:L:M */
    mov     x2, v0.d[0]
    CKX     x2, 0x800017ff3001d000, 9
    mov     x2, v0.d[1]
    CKX     x2, 0x80001e3400007fff, 10

    ldr     x10, =w_a
    ldr     q1, [x10]
    ldr     x10, =w_b
    ldr     q2, [x10]
    ldr     x10, =w_d
    ldr     q0, [x10]
    sqrdmlsh v0.4s, v1.4s, v2.s[3]
    mov     x2, v0.d[0]
    CKX     x2, 0xc000000240000000, 11
    mov     x2, v0.d[1]
    CKX     x2, 0xa0000000dfffffff, 12

    /* same op through Vm=v17: proves the 5-bit Rm field for .S sources */
    mov     v17.16b, v2.16b
    ldr     x10, =w_d
    ldr     q0, [x10]
    sqrdmlsh v0.4s, v1.4s, v17.s[3]
    mov     x2, v0.d[0]
    CKX     x2, 0xc000000240000000, 13
    mov     x2, v0.d[1]
    CKX     x2, 0xa0000000dfffffff, 14

    /* ---- scalar forms (upper result bits must be zeroed) ---- */
    ldr     x10, =v_a                    /* h ops: d=a=b=0x8000 */
    ldr     h0, [x10]
    ldr     h1, [x10]
    ldr     h2, [x10]
    sqrdmlah h0, h1, h2                  /* exact 0 after round: INT16_MIN^2 */
    mov     x2, v0.d[0]
    CKX     x2, 0x0, 15

    ldr     x10, =sc_s                   /* s ops: d=1, a=INT32_MIN, b=INT32_MAX */
    ldr     s0, [x10]
    ldr     s1, [x10, #4]
    ldr     s2, [x10, #8]
    sqrdmlsh s0, s1, s2
    mov     x2, v0.d[0]
    CKX     x2, 0x7fffffff, 16

    /* scalar by-element: .S allows Vm>=v16 (5-bit Rm)... */
    ldr     x10, =w_b
    ldr     q22, [x10]
    ldr     x10, =w_d
    ldr     s0, [x10, #8]                /* d = 0xFFFFFFFF */
    ldr     x10, =w_a
    ldr     s1, [x10, #12]               /* a = 0xC0000000 */
    sqrdmlah s0, s1, v22.s[3]
    mov     x2, v0.d[0]
    CKX     x2, 0xdfffffff, 17

    /* ...while .H restricts Vm to v0-v15 (4-bit Rm) */
    ldr     x10, =v_b
    ldr     q12, [x10]
    ldr     x10, =v_a
    ldr     h0, [x10, #2]                /* d = 0x7FFF */
    ldr     h1, [x10, #8]                /* a = 0x0001 */
    sqrdmlsh h0, h1, v12.h[5]            /* elt = 0xFFFF */
    mov     x2, v0.d[0]
    CKX     x2, 0x7fff, 18

    /* ================= FEAT_DotProd: SDOT/UDOT ================= */
    ldr     x10, =b_a
    ldr     q4, [x10]
    ldr     x10, =b_b
    ldr     q5, [x10]
    ldr     x10, =w_d
    ldr     q0, [x10]
    sdot    v0.4s, v4.16b, v5.16b        /* 0x80*0x80 sign corners + wrap */
    mov     x2, v0.d[0]
    CKX     x2, 0x3f0300000000, 21
    mov     x2, v0.d[1]
    CKX     x2, 0x7ffff50c00000153, 22

    ldr     x10, =w_d
    ldr     q0, [x10]
    udot    v0.4s, v4.16b, v5.16b        /* same bytes zero-extended */
    mov     x2, v0.d[0]
    CKX     x2, 0x1bd030000ff00, 23
    mov     x2, v0.d[1]
    CKX     x2, 0x8001370c00000153, 24

    ldr     x10, =w_d
    ldr     q0, [x10]
    sdot    v0.2s, v4.8b, v5.8b          /* Q=0 clears the upper half */
    mov     x2, v0.d[0]
    CKX     x2, 0x3f0300000000, 25
    mov     x2, v0.d[1]
    CKX     x2, 0x0, 26

    ldr     x10, =w_d
    ldr     q0, [x10]
    sdot    v0.4s, v4.16b, v5.4b[3]      /* one Vm group broadcast */
    mov     x2, v0.d[0]
    CKX     x2, 0xffffa28200000fab, 27
    mov     x2, v0.d[1]
    CKX     x2, 0x7ffff50cffffffeb, 28

    mov     v18.16b, v5.16b              /* Vm>=v16: 5-bit Rm proof */
    ldr     x10, =w_d
    ldr     q0, [x10]
    udot    v0.4s, v4.16b, v18.4b[1]
    mov     x2, v0.d[0]
    CKX     x2, 0x1bd030000bfff, 29
    mov     x2, v0.d[1]
    CKX     x2, 0x800183ef0000037b, 30

    /* ================= FEAT_FCMA: FCMLA/FCADD ================= */
    ldr     x10, =f4_n
    ldr     q1, [x10]                    /* n pairs (2,3) (0.5,-4) */
    ldr     x10, =f4_m
    ldr     q2, [x10]                    /* m pairs (5,7) (-6,1.5) */
    ldr     x14, =f4_d                   /* d pairs (100,200) (10,20) */

    ldr     q0, [x14]
    fcmla   v0.4s, v1.4s, v2.4s, #0
    mov     x2, v0.d[0]
    CKX     x2, 0x4356000042dc0000, 31
    mov     x2, v0.d[1]
    CKX     x2, 0x41a6000040e00000, 32
    ldr     q0, [x14]
    fcmla   v0.4s, v1.4s, v2.4s, #90
    mov     x2, v0.d[0]
    CKX     x2, 0x43570000429e0000, 33
    mov     x2, v0.d[1]
    CKX     x2, 0x4230000041800000, 34
    ldr     q0, [x14]
    fcmla   v0.4s, v1.4s, v2.4s, #180
    mov     x2, v0.d[0]
    CKX     x2, 0x433a000042b40000, 35
    mov     x2, v0.d[1]
    CKX     x2, 0x419a000041500000, 36
    ldr     q0, [x14]
    fcmla   v0.4s, v1.4s, v2.4s, #270
    mov     x2, v0.d[0]
    CKX     x2, 0x4339000042f20000, 37
    mov     x2, v0.d[1]
    CKX     x2, 0xc080000040800000, 38

    fcadd   v0.4s, v1.4s, v2.4s, #90
    mov     x2, v0.d[0]
    CKX     x2, 0x41000000c0a00000, 39
    mov     x2, v0.d[1]
    CKX     x2, 0xc1200000bf800000, 40
    fcadd   v0.4s, v1.4s, v2.4s, #270
    mov     x2, v0.d[0]
    CKX     x2, 0xc000000041100000, 41
    mov     x2, v0.d[1]
    CKX     x2, 0x4000000040000000, 42

    /* .2d forms */
    ldr     x10, =d2_n
    ldr     q1, [x10]
    ldr     x10, =d2_m
    ldr     q2, [x10]
    ldr     x10, =d2_d
    ldr     q0, [x10]
    fcmla   v0.2d, v1.2d, v2.2d, #90
    mov     x2, v0.d[0]
    CKX     x2, 0x4053c00000000000, 43
    mov     x2, v0.d[1]
    CKX     x2, 0x406ae00000000000, 44
    fcadd   v0.2d, v1.2d, v2.2d, #90
    mov     x2, v0.d[0]
    CKX     x2, 0xc014000000000000, 45
    mov     x2, v0.d[1]
    CKX     x2, 0x4020000000000000, 46

    /* per-line multiplies must be FUSED (FPMulAdd): (1+2^-12)^2 - 1 */
    ldr     x10, =fuse_n
    ldr     d1, [x10]
    mov     v2.16b, v1.16b
    ldr     x10, =fuse_d
    ldr     d0, [x10]
    fcmla   v0.2s, v1.2s, v2.2s, #0
    mov     x2, v0.d[0]
    CKX     x2, 0x3a000400, 47           /* unfused would give 0x3a000000 */

    /* .4h forms (FEAT_FP16 is advertised, so halves must work) */
    ldr     x10, =h4_n
    ldr     d1, [x10]
    ldr     x10, =h4_m
    ldr     d2, [x10]
    ldr     x13, =h4_d
    ldr     d0, [x13]
    fcmla   v0.4h, v1.4h, v2.4h, #270
    mov     x2, v0.d[0]
    CKX     x2, 0x5420514059c85790, 48
    fcadd   v0.4h, v1.4h, v2.4h, #270
    mov     x2, v0.d[0]
    CKX     x2, 0xc5004500c0004880, 49

    /* by-element: .4s idx=1 through v19 (5-bit Rm), .4h idx=3 (upper Vm half) */
    ldr     x10, =f4_n
    ldr     q1, [x10]
    ldr     x10, =f4_m
    ldr     q19, [x10]
    ldr     q0, [x14]
    fcmla   v0.4s, v1.4s, v19.s[1], #0
    mov     x2, v0.d[0]
    CKX     x2, 0x434b000042b00000, 50
    mov     x2, v0.d[1]
    CKX     x2, 0x41a6000040e00000, 51

    ldr     x10, =h8_n
    ldr     q1, [x10]
    ldr     x10, =h8_m
    ldr     q12, [x10]
    ldr     x10, =h8_d
    ldr     q0, [x10]
    fcmla   v0.8h, v1.8h, v12.h[3], #90  /* pair idx 3 = upper Vm half */
    mov     x2, v0.d[0]
    CKX     x2, 0x4d8056005c044fc0, 52
    mov     x2, v0.d[1]
    CKX     x2, 0x57c0d8085670d6c0, 53

    ldr     x10, =h8_n
    ldr     d1, [x10]
    ldr     x13, =h4_d
    ldr     d0, [x13]
    fcmla   v0.4h, v1.4h, v12.h[1], #90  /* Q=0 keeps pair idx in 0-1 */
    mov     x2, v0.d[0]
    CKX     x2, 0x514054805b185430, 54

    /* ================= FEAT_FHM: FMLAL/FMLSL ================= */
    ldr     x10, =h8_n
    ldr     q1, [x10]                    /* f16 (2,3,1,-2 | 4,5,-3,6) */
    ldr     x10, =h8_m
    ldr     q2, [x10]                    /* f16 (5,7,9,11 | 13,17,19,23) */
    ldr     x14, =f4_d                   /* f32 acc (100,200,10,20) */

    ldr     q0, [x14]
    fmlal   v0.4s, v1.4h, v2.4h
    mov     x2, v0.d[0]
    CKX     x2, 0x435d000042dc0000, 55
    mov     x2, v0.d[1]
    CKX     x2, 0xc000000041980000, 56
    ldr     q0, [x14]
    fmlsl   v0.4s, v1.4h, v2.4h
    mov     x2, v0.d[0]
    CKX     x2, 0x4333000042b40000, 57
    mov     x2, v0.d[1]
    CKX     x2, 0x422800003f800000, 58
    ldr     q0, [x14]
    fmlal2  v0.4s, v1.4h, v2.4h          /* reads h[4..7] */
    mov     x2, v0.d[0]
    CKX     x2, 0x438e800043180000, 59
    mov     x2, v0.d[1]
    CKX     x2, 0x431e0000c23c0000, 60
    ldr     q0, [x14]
    fmlsl2  v0.4s, v1.4h, v2.4h
    mov     x2, v0.d[0]
    CKX     x2, 0x42e6000042400000, 61
    mov     x2, v0.d[1]
    CKX     x2, 0xc2ec000042860000, 62

    ldr     q0, [x14]
    fmlal2  v0.2s, v1.2h, v2.2h          /* Q=0 "2" form reads h[2..3], NOT h[4..5] */
    mov     x2, v0.d[0]
    CKX     x2, 0x4332000042da0000, 63
    mov     x2, v0.d[1]
    CKX     x2, 0x0, 64

    ldr     q0, [x14]
    fmlal   v0.4s, v1.4h, v2.h[7]        /* by element: idx=H:L:M, 4-bit Rm */
    mov     x2, v0.d[0]
    CKX     x2, 0x4386800043120000, 65
    mov     x2, v0.d[1]
    CKX     x2, 0xc1d0000042040000, 66
    ldr     q0, [x14]
    fmlsl2  v0.4s, v1.4h, v2.h[5]
    mov     x2, v0.d[0]
    CKX     x2, 0x42e6000042000000, 67
    mov     x2, v0.d[1]
    CKX     x2, 0xc2a4000042740000, 68

    /* ============ vector FRINTX/FRINTI honor FPCR.RMode ============ */
    mrs     x4, fpcr
    movz    x5, #0x00C0, lsl #16         /* RMode = 0b11 (toward zero) */
    msr     fpcr, x5
    ldr     x10, =f_r
    ldr     d3, [x10]                    /* [1.5f, -1.5f] */
    frintx  v0.2s, v3.2s
    mov     x2, v0.d[0]
    CKX     x2, 0xbf8000003f800000, 19   /* [1.0, -1.0] under RZ */
    movz    x5, #0x0080, lsl #16         /* RMode = 0b10 (toward -inf) */
    msr     fpcr, x5
    frinti  v0.2s, v3.2s
    mov     x2, v0.d[0]
    CKX     x2, 0xc00000003f800000, 20   /* [1.0, -2.0] under RM */
    msr     fpcr, x4

    /* all good */
    movz    x0, #0
    b       done
fail:
    mov     x0, x11
done:
#ifdef USERMODE
    movz    x8, #93                      /* exit(x0) */
    svc     #0
#else
    hlt     #0
#endif

.data
.balign 16
v_a:    .hword 0x8000, 0x7FFF, 0x4000, 0xC000, 0x0001, 0xFFFF, 0x2000, 0xE000
v_b:    .hword 0x8000, 0x7FFF, 0x4000, 0x4000, 0x7FFF, 0xFFFF, 0x1000, 0x3000
v_d:    .hword 0x0000, 0x0001, 0xFFFF, 0x8000, 0x7FFF, 0x0000, 0x1234, 0x8765
w_a:    .word 0x80000000, 0x7FFFFFFF, 0x40000000, 0xC0000000
w_b:    .word 0x80000000, 0x7FFFFFFF, 0x40000000, 0x40000000
w_d:    .word 0x00000000, 0x00000001, 0xFFFFFFFF, 0x80000000
sc_s:   .word 0x00000001, 0x80000000, 0x7FFFFFFF
.balign 16
b_a:    .byte 0x80, 0xFF, 0x7F, 0x01, 0x80, 0x80, 0xFF, 0xFF
        .byte 0x00, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE, 0x10
b_b:    .byte 0x80, 0x7F, 0x80, 0xFF, 0x80, 0x01, 0xFF, 0x7F
        .byte 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
.balign 16
f4_n:   .float 2.0, 3.0, 0.5, -4.0
f4_m:   .float 5.0, 7.0, -6.0, 1.5
f4_d:   .float 100.0, 200.0, 10.0, 20.0
d2_n:   .double 2.0, 3.0
d2_m:   .double 5.0, 7.0
d2_d:   .double 100.0, 200.0
fuse_n: .word 0x3f800800, 0              /* (1+2^-12, 0.0f) */
fuse_d: .float -1.0, 0.0
h4_n:   .quad 0xc0003c0042004000         /* .4h pairs (2,3) (1,-2) */
h4_m:   .quad 0x4400420047004500         /* .4h pairs (5,7) (3,4) */
h4_d:   .quad 0x538052405a405640         /* .4h pairs (100,200) (50,60) */
h8_m:   .quad 0x4980488047004500, 0x4dc04cc04c404a80  /* (5,7)(9,11)(13,17)(19,23) */
h8_n:   .quad 0xc0003c0042004000, 0x4600c20045004400  /* (2,3)(1,-2)(4,5)(-3,6) */
h8_d:   .quad 0x538052405a405640, 0x4900488048004700  /* (100,200)(50,60)(7,8)(9,10) */
f_r:    .word 0x3FC00000, 0xBFC00000    /* 1.5f, -1.5f */
