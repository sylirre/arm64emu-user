/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* M19 self-test: ARMv8.3/8.4 GPR-side extensions — FEAT_LRCPC2 LDAPUR/STLUR
 * (full opc x size grid, sign/zero extension, negative and unaligned imm9,
 * SP base), FEAT_JSCVT FJCVTZS (result + NZCV corner battery) and
 * FEAT_FLAGM/FLAGM2 CFINV/RMIF/SETF8/SETF16/AXFLAG/XAFLAG. x0=0 on success,
 * else failing-check id. Expected values are hand-computed; the same file
 * builds as a Linux user binary with -DUSERMODE (exit code = x0) to
 * cross-check every value against real hardware semantics under
 * qemu-aarch64 -cpu max before trusting it as the emulator's reference. */
.arch armv8.5-a

.macro CKX reg, val, id
    movz    x11, #\id
    ldr     x9, =\val
    cmp     \reg, x9
    b.ne    fail
.endm

.text
.global _start
_start:
    /* ================= FEAT_LRCPC2: LDAPUR (load grid) ================= */
    ldr     x10, =d64                    /* 0x8899AABBCCDDEEFF, then 0x..77 */

    ldapur  x2, [x10]
    CKX     x2, 0x8899AABBCCDDEEFF, 1
    ldapur  w2, [x10]
    CKX     x2, 0xCCDDEEFF, 2
    ldapurb w2, [x10]
    CKX     x2, 0xFF, 3
    ldapurh w2, [x10]
    CKX     x2, 0xEEFF, 4
    ldapursb x2, [x10]
    CKX     x2, 0xFFFFFFFFFFFFFFFF, 5
    ldapursb w2, [x10]                   /* sign-extend to 32, zero upper */
    CKX     x2, 0xFFFFFFFF, 6
    ldapursh x2, [x10]
    CKX     x2, 0xFFFFFFFFFFFFEEFF, 7
    ldapursh w2, [x10]
    CKX     x2, 0xFFFFEEFF, 8
    ldapursw x2, [x10]
    CKX     x2, 0xFFFFFFFFCCDDEEFF, 9
    ldapursb x2, [x10, #8]               /* 0x77: positive, no over-extension */
    CKX     x2, 0x77, 10
#ifndef USERMODE
    /* qemu <= 8.2 decodes the LDAPUR/STLUR imm9 as unsigned (a64.decode
     * "imm:9", fixed upstream to "imm:s9"), so negative offsets are oracle-
     * checked only by inspection: the emulator shares the sign_extend imm9
     * path with the qemu-validated LDUR/STUR forms. */
    add     x12, x10, #8
    ldapur  x2, [x12, #-8]               /* negative imm9 */
    CKX     x2, 0x8899AABBCCDDEEFF, 11
#endif
    ldapur  w2, [x10, #5]                /* unaligned: bytes 5..8 */
    CKX     x2, 0x778899AA, 12

    /* ================= FEAT_LRCPC2: STLUR (store grid) ================= */
    ldr     x12, =d64b
    ldr     x1, =0x1122334455667788
    stlur   x1, [x12]
    ldr     x2, [x12]
    CKX     x2, 0x1122334455667788, 13
    ldr     x1, =0xDEADBEEF
    stlur   w1, [x12, #4]
    ldr     x2, [x12]
    CKX     x2, 0xDEADBEEF55667788, 14
    movz    x1, #0xCAFE
    stlurh  w1, [x12, #2]
    ldr     x2, [x12]
    CKX     x2, 0xDEADBEEFCAFE7788, 15
    movz    x1, #0x55
    stlurb  w1, [x12, #7]
    ldr     x2, [x12]
    CKX     x2, 0x55ADBEEFCAFE7788, 16
#ifndef USERMODE
    ldr     x13, =d64c                   /* negative imm9 store (see note above) */
    add     x13, x13, #8
    ldr     x1, =0x0BADF00D
    stlur   w1, [x13, #-4]
    ldr     x2, [x13, #-8]
    CKX     x2, 0x0BADF00DAAAAAAAA, 17
#endif

    /* ---- SP as base register (d64 is 16-byte aligned) ---- */
    mov     x20, sp
    mov     sp, x10
    ldapur  x2, [sp]
    mov     sp, x20
    CKX     x2, 0x8899AABBCCDDEEFF, 18

    /* ================= FEAT_JSCVT: FJCVTZS ================= */
    /* Each case: poison NZCV (all four set), convert, then fold result and
     * flags into one word: (Wd << 4) | NZCV-nibble. Z alone must survive. */
.macro JCV off, val, id
    ldr     d0, [x15, #\off]
    msr     nzcv, x6
    fjcvtzs w2, d0
    mrs     x3, nzcv
    lsr     x3, x3, #28
    orr     x2, x3, x2, lsl #4
    CKX     x2, \val, \id
.endm
    ldr     x15, =jdat
    movz    x6, #0xF000, lsl #16         /* NZCV poison */
    JCV     0,   0x4, 19                 /* 0.0: exact */
    JCV     8,   0x0, 20                 /* -0.0: "inexact" for JS, Z=0 */
    JCV     16,  0x14, 21                /* 1.0 */
    JCV     24,  0xffffffff4, 22         /* -1.0 wraps to 0xFFFFFFFF, exact */
    JCV     32,  0x0, 23                 /* 0.5: truncates, inexact */
    JCV     40,  0xffffffff0, 24         /* -1.5 */
    JCV     48,  0x7fffffff4, 25         /* INT32_MAX */
    JCV     56,  0x800000004, 26         /* INT32_MIN */
    JCV     64,  0x800000000, 27         /* 2^31 wraps, Z=0 */
    JCV     72,  0x7fffffff0, 28         /* -(2^31+1) wraps */
    JCV     80,  0x50, 29                /* 2^32+5 -> 5 */
    JCV     88,  0x10, 30                /* 2^52+1 -> 1 */
    JCV     96,  0x0, 31                 /* 2^63 */
    JCV     104, 0x0, 32                 /* -2^63 */
    JCV     112, 0x0, 33                 /* 2^80: low 32 bits clear */
    JCV     120, 0x800000000, 34         /* 2^63+2^31 */
    JCV     128, 0xc00000000, 35         /* -(2^63+5*2^30) */
    JCV     136, 0x0, 36                 /* NaN -> 0 */
    JCV     144, 0x0, 37                 /* +Inf -> 0 */
    JCV     152, 0x0, 38                 /* -Inf -> 0 */
    JCV     160, 0x0, 39                 /* smallest subnormal */
    JCV     168, 0x800000000, 40         /* 2^83+2^31 */

    /* scalar FCVTNS ties must round to EVEN (FCVTAS ties away) */
    ldr     d0, [x15, #176]              /* 2.5 */
    fcvtns  w2, d0
    CKX     x2, 2, 41
    fcvtas  w2, d0
    CKX     x2, 3, 42
    ldr     d0, [x15, #184]              /* 3.5 */
    fcvtns  w2, d0
    CKX     x2, 4, 43

    /* ================= FEAT_FLAGM/FLAGM2 ================= */
    /* CFINV: C toggles, everything else survives */
    msr     nzcv, xzr
    cfinv
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x2, 44
    msr     nzcv, x6                     /* x6 = all-flags poison */
    cfinv
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0xd, 45

    /* AXFLAG/XAFLAG: pure 4-bit functions — run all 16 input nibbles and
     * fold every output nibble into one 64-bit accumulator. */
.macro FLGALL op, val, id
    movz    x4, #0
    movz    x5, #0
1:  lsl     x3, x5, #28
    msr     nzcv, x3
    \op
    mrs     x3, nzcv
    lsr     x3, x3, #28
    orr     x4, x3, x4, lsl #4
    add     x5, x5, #1
    cmp     x5, #16
    b.ne    1b
    CKX     x4, \val, \id
.endm
    FLGALL  axflag, 0x424446404244464, 46
    FLGALL  xaflag, 0x8822336688223366, 47

    /* RMIF: rotate + masked flag insert */
    movz    x1, #0xA
    msr     nzcv, xzr
    rmif    x1, #0, #0xF                 /* whole nibble from x1<3:0> */
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0xa, 48
    movz    x1, #1
    orr     x1, x1, #0x8000000000000000  /* ROR 63 -> tmp<3:0> = 0b0011 */
    msr     nzcv, xzr
    rmif    x1, #63, #0x3
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x3, 49
    mov     x1, #-1                      /* tmp nibble 0xF, mask 0b0101 */
    msr     nzcv, xzr
    rmif    x1, #0, #0x5
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x5, 50
    movz    x1, #0xA5
    msr     nzcv, x6                     /* poison: unmasked bits survive */
    rmif    x1, #4, #0xF
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0xa, 51

    /* SETF8/SETF16: N/Z/V from the narrow value, C unchanged */
    movz    w1, #0
    msr     nzcv, xzr
    setf8   w1
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x4, 52                  /* zero: Z set even from Z=0 */
    movz    w1, #0x80
    msr     nzcv, x6
    setf8   w1
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0xb, 53                  /* N=1, V=1, Z cleared, C kept */
    movz    w1, #0x180
    msr     nzcv, xzr
    setf8   w1
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x8, 54                  /* bit8==bit7 -> V=0 */
    movz    w1, #0x100
    msr     nzcv, xzr
    setf8   w1
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x5, 55                  /* low byte zero but bit8 -> Z=1,V=1 */
    movz    w1, #0x8000
    msr     nzcv, xzr
    setf16  w1
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x9, 56
    movz    w1, #0x8000
    orr     w1, w1, #0x10000
    msr     nzcv, xzr
    setf16  w1
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x8, 57
    movz    w1, #0xFFFF, lsl #16
    msr     nzcv, x6
    setf16  w1
    mrs     x3, nzcv
    lsr     x3, x3, #28
    CKX     x3, 0x7, 58                  /* low half zero, bit16 -> Z,V; C kept */

#ifndef USERMODE
    /* Advertised-contract pin: the ID nibbles must match what this file
     * exercises. Emulator-only — a Linux host sanitizes EL0 ID-reg reads. */
    mrs     x2, id_aa64isar0_el1
    CKX     x2, 0x21100110212120, 59
    mrs     x2, id_aa64isar1_el1
    CKX     x2, 0x211000, 60
#endif

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
d64:    .quad 0x8899AABBCCDDEEFF
        .quad 0x0011223344556677
d64b:   .quad 0xAAAAAAAAAAAAAAAA        /* STLUR grid target */
d64c:   .quad 0xAAAAAAAAAAAAAAAA        /* negative-offset store target */
jdat:   .quad 0x0000000000000000        /*  0.0  */
        .quad 0x8000000000000000        /* -0.0  */
        .quad 0x3FF0000000000000        /*  1.0  */
        .quad 0xBFF0000000000000        /* -1.0  */
        .quad 0x3FE0000000000000        /*  0.5  */
        .quad 0xBFF8000000000000        /* -1.5  */
        .quad 0x41DFFFFFFFC00000        /*  2147483647.0 */
        .quad 0xC1E0000000000000        /* -2147483648.0 */
        .quad 0x41E0000000000000        /*  2^31 */
        .quad 0xC1E0000000200000        /* -(2^31+1) */
        .quad 0x41F0000000500000        /*  2^32+5 */
        .quad 0x4330000000000001        /*  2^52+1 */
        .quad 0x43E0000000000000        /*  2^63 */
        .quad 0xC3E0000000000000        /* -2^63 */
        .quad 0x44F0000000000000        /*  2^80 */
        .quad 0x43E0000000100000        /*  2^63+2^31 */
        .quad 0xC3E0000000280000        /* -(2^63+5*2^30) */
        .quad 0x7FF8000000000000        /*  NaN  */
        .quad 0x7FF0000000000000        /*  +Inf */
        .quad 0xFFF0000000000000        /*  -Inf */
        .quad 0x0000000000000001        /*  min subnormal */
        .quad 0x4520000000000001        /*  2^83+2^31 */
        .quad 0x4004000000000000        /*  2.5 (FCVTNS tie) */
        .quad 0x400C000000000000        /*  3.5 (FCVTNS tie) */
