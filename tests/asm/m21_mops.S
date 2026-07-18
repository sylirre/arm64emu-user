/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* M21 self-test: FEAT_MOPS memory copy/set (CPYx/CPYFx/SETx).
 *
 * Pins the guest-visible "Option A" contract the implementation shares with
 * qemu: SETP/CPYP transform the registers to final-Xd[,Xs] / Xn=-(remaining)
 * form and write NZCV=0000, performing up to the next page boundary; M does
 * the whole-page middle (and preserves NZCV); E the sub-page tail. Covers
 * multi-page SET with per-stage Xn pins, whole-op-in-P small sets, zero size,
 * XZR as SET value, forward CPYF across pages (exact per-stage Xn), backward
 * overlapping CPY (Xd/Xs stay in input form, Xn positive), forward-direction
 * choice for a dst<src overlap, and M/E NOP-on-Xn==0 even with PSTATE.C set.
 * Emulator-only (#ifndef USERMODE): the EC 0x27 mismatch exception ISS values
 * (wrong-option from M/E with C=1, epilogue with a page or more remaining)
 * and the UNDEF battery (SETG*, rd==rn, SET stage 0b11, size!=0, Rs==31 CPY).
 *
 * NZCV discipline: the check macros use CMP, which sets C — an Option B
 * indicator that would (correctly!) make the next M/E stage trap. So NZCV is
 * captured into x13 immediately after each stage and rewritten to a C=0 value
 * before the next one.
 *
 * x0=0 on success, else failing-check id. Builds with -DUSERMODE as a Linux
 * user binary (exit code = x0) to validate every constant under
 * qemu-aarch64 -cpu max first. */
.arch armv9.3-a

.macro CKX reg, val, id
    movz    x11, #\id
    ldr     x9, =\val
    cmp     \reg, x9
    b.ne    fail
.endm

.macro CKR reg, ref, id
    movz    x11, #\id
    cmp     \reg, \ref
    b.ne    fail
.endm

.text
.global _start
_start:
#ifndef USERMODE
    /* exception vectors at 0x40010000 (sync handler records the full ESR) */
    movz    x0, #0x4001, lsl #16
    msr     vbar_el1, x0
    isb
#endif

    /* ============ A: SETP/SETM/SETE, 0x3023 bytes from page+0x100 ========= */
    ldr     x20, =sbuf + 0x100
    mov     x0, x20
    ldr     x1, =0x3023
    mov     x2, #0xcd
    movz    x9, #0xf000, lsl #16         /* all of NZCV set (C=1: P ignores) */
    msr     nzcv, x9
    setp    [x0]!, x1!, x2
    mrs     x13, nzcv                    /* capture before any CMP */
    movz    x9, #0x3023
    add     x9, x20, x9
    CKR     x0, x9, 1                    /* Xd -> final address */
    CKX     x1, 0xFFFFFFFFFFFFDEDD, 2    /* Xn = -(0x3023-0xf00): P to boundary */
    CKX     x13, 0, 3                    /* NZCV=0000: Option A */
    ldrb    w13, [x20]
    movz    x10, #0xeff
    ldrb    w12, [x20, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12
    movz    x10, #0xf00
    ldrb    w12, [x20, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12                /* [0]:[0xeff]:[0xf00] */
    CKX     x13, 0xcdcd00, 4
    movz    x9, #0x9000, lsl #16         /* N|V (C=0): prove M preserves NZCV */
    msr     nzcv, x9
    setm    [x0]!, x1!, x2
    mrs     x13, nzcv
    CKX     x1, 0xFFFFFFFFFFFFFEDD, 5    /* Xn = -0x123: M leaves the tail */
    CKX     x13, 0x90000000, 6           /* M preserved NZCV */
    movz    x10, #0x2eff
    ldrb    w13, [x20, x10]
    movz    x10, #0x2f00
    ldrb    w12, [x20, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12                /* [0x2eff]:[0x2f00] */
    CKX     x13, 0xcd00, 7
    movz    x9, #0x9000, lsl #16
    msr     nzcv, x9
    sete    [x0]!, x1!, x2
    mrs     x13, nzcv
    CKX     x1, 0, 8
    movz    x9, #0x3023
    add     x9, x20, x9
    CKR     x0, x9, 9                    /* Xd untouched by M/E */
    CKX     x13, 0x90000000, 10          /* E preserved NZCV */
    movz    x10, #0x3022
    ldrb    w13, [x20, x10]
    movz    x10, #0x3023
    ldrb    w12, [x20, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12                /* [0x3022]:[0x3023] */
    CKX     x13, 0xcd00, 11

    /* ============ B: whole set in P; M/E NOP on Xn==0 even with C=1 ======= */
    ldr     x19, =sbuf + 0x200
    mov     x0, x19
    mov     x1, #0x40
    mov     x2, #0x7e
    setp    [x0]!, x1!, x2
    CKX     x1, 0, 12
    add     x9, x19, #0x40
    CKR     x0, x9, 13
    ldrb    w13, [x19]
    ldrb    w12, [x19, #0x3f]
    lsl     x13, x13, #8
    orr     x13, x13, x12
    ldrb    w12, [x19, #0x40]
    lsl     x13, x13, #8
    orr     x13, x13, x12                /* [0]:[0x3f]:[0x40] (0xcd from A) */
    CKX     x13, 0x7e7ecd, 14
    movz    x9, #0x2000, lsl #16         /* C=1: an Option B state ... */
    msr     nzcv, x9
    setm    [x0]!, x1!, x2               /* ... but Xn==0 NOPs before checks */
    sete    [x0]!, x1!, x2
    mrs     x13, nzcv
    CKX     x13, 0x20000000, 15
    CKX     x1, 0, 16

    /* ============ C: zero-size SETP; XZR as the value register =========== */
    mov     x0, x19
    mov     x1, #0
    movz    x9, #0xf000, lsl #16
    msr     nzcv, x9
    setp    [x0]!, x1!, x2
    mrs     x13, nzcv
    CKR     x0, x19, 17                  /* Xd unchanged */
    CKX     x1, 0, 18
    CKX     x13, 0, 19                   /* NZCV still written */
    ldrb    w13, [x19]
    CKX     x13, 0x7e, 20                /* memory untouched */
    mov     x0, x19
    mov     x1, #4
    setp    [x0]!, x1!, xzr              /* Rs=31 is XZR: fill with zero */
    ldrb    w13, [x19]
    CKX     x13, 0, 21

    /* ============ D: CPYF forward, 0x2000 bytes across pages ============== */
    ldr     x17, =cbuf + 0x80            /* source */
    ldr     x16, =dbuf + 0x40            /* destination */
    mov     x0, x17                      /* pattern-fill the source... */
    ldr     x1, =0x2000
    mov     x2, #0x55
    setp    [x0]!, x1!, x2
    msr     nzcv, xzr
    setm    [x0]!, x1!, x2
    msr     nzcv, xzr
    sete    [x0]!, x1!, x2
    mov     w9, #0x11                    /* ...with end/middle markers */
    strb    w9, [x17]
    mov     w9, #0x77
    movz    x10, #0x1000
    strb    w9, [x17, x10]
    mov     w9, #0x99
    movz    x10, #0x1fff
    strb    w9, [x17, x10]

    mov     x0, x16
    mov     x1, x17
    ldr     x2, =0x2000
    movz    x9, #0xf000, lsl #16
    msr     nzcv, x9
    cpyfp   [x0]!, [x1]!, x2!
    mrs     x13, nzcv
    movz    x9, #0x2000
    add     x9, x16, x9
    CKR     x0, x9, 22
    movz    x9, #0x2000
    add     x9, x17, x9
    CKR     x1, x9, 23
    CKX     x2, 0xFFFFFFFFFFFFEF80, 24   /* P did min(0xfc0,0xf80)=0xf80 */
    CKX     x13, 0, 25
    msr     nzcv, xzr
    cpyfm   [x0]!, [x1]!, x2!
    CKX     x2, 0xFFFFFFFFFFFFFF80, 26   /* 0x40 + 0xfc0 page-bounded steps */
    msr     nzcv, xzr
    cpyfe   [x0]!, [x1]!, x2!
    CKX     x2, 0, 27
    ldrb    w13, [x16]
    movz    x10, #0x1000
    ldrb    w12, [x16, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12
    movz    x10, #0x1fff
    ldrb    w12, [x16, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12                /* markers landed */
    CKX     x13, 0x117799, 28
    ldurb   w13, [x16, #-1]
    movz    x10, #0x2000
    ldrb    w12, [x16, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12                /* no under/overrun */
    CKX     x13, 0, 29

    /* ============ E: CPY backward (dst = src+0x40 overlap), 0x2000 ======== */
    add     x15, x17, #0x40              /* dst above src: must go backward */
    mov     x0, x15
    mov     x1, x17
    ldr     x2, =0x2000
    msr     nzcv, xzr
    cpyp    [x0]!, [x1]!, x2!
    mrs     x13, nzcv
    CKR     x0, x15, 30                  /* input form kept: Xd unchanged */
    CKR     x1, x17, 31                  /* Xs unchanged */
    CKX     x2, 0x1f80, 32               /* Xn positive = backward, P did 0x80 */
    CKX     x13, 0, 33
    msr     nzcv, xzr
    cpym    [x0]!, [x1]!, x2!
    CKX     x2, 0xf80, 34
    msr     nzcv, xzr
    cpye    [x0]!, [x1]!, x2!
    CKX     x2, 0, 35
    ldrb    w13, [x15]
    movz    x10, #0x1000
    ldrb    w12, [x15, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12
    movz    x10, #0x1fff
    ldrb    w12, [x15, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12                /* overlap-correct (memmove) result */
    CKX     x13, 0x117799, 36

    /* ============ F: CPY dst<src overlap: forward is chosen =============== */
    sub     x14, x16, #0x30              /* dst = D-result - 0x30 */
    mov     x0, x14
    mov     x1, x16                      /* src = D result (0x11/0x55...) */
    ldr     x2, =0x800
    msr     nzcv, xzr
    cpyp    [x0]!, [x1]!, x2!
    CKX     x2, 0, 37                    /* forward, all within one P stage */
    add     x9, x14, #0x800
    CKR     x0, x9, 38
    add     x9, x16, #0x800
    CKR     x1, x9, 39
    ldrb    w13, [x14]
    movz    x10, #0x7ff
    ldrb    w12, [x14, x10]
    lsl     x13, x13, #8
    orr     x13, x13, x12
    CKX     x13, 0x1155, 40
    cpym    [x0]!, [x1]!, x2!            /* Xn==0: NOPs (even with C set) */
    cpye    [x0]!, [x1]!, x2!
    CKX     x2, 0, 41

#ifndef USERMODE
    /* ============ G: EC 0x27 mismatch exceptions + UNDEF battery ==========
     * The sync handler stores the full ESR in x21 and skips the instruction.
     * Expected ESR values follow the EC 0x27 ISS layout (isSET[24],
     * options[22:19], fromEpilogue[18], wrongOption[17], OptionA[16],
     * destreg[14:10], srcreg[9:5], sizereg[4:0]); UNDEFs read 0x02000000
     * (EC_UNKNOWN with IL). */
    mov     x0, x19
    mov     x1, #-0x100
    mov     x2, #0xab
    movz    x9, #0x2000, lsl #16         /* C=1: Option B state */
    msr     nzcv, x9
    movz    x21, #0xffff
    setm    [x0]!, x1!, x2               /* wrong option from M */
    CKX     x21, 0x9F030041, 42
    CKX     x1, 0xFFFFFFFFFFFFFF00, 43   /* registers untouched */

    msr     nzcv, xzr
    mov     x0, x20
    mov     x1, #-0x2000
    movz    x21, #0xffff
    sete    [x0]!, x1!, x2               /* a page or more left for E */
    CKX     x21, 0x9F050041, 44
    CKX     x1, 0xFFFFFFFFFFFFE000, 45

    movz    x9, #0x2000, lsl #16
    msr     nzcv, x9
    mov     x0, x16
    mov     x1, x17
    mov     x2, #-0x100
    movz    x21, #0xffff
    cpye    [x0]!, [x1]!, x2!            /* wrong option from CPY epilogue */
    CKX     x21, 0x9E070022, 46
    msr     nzcv, xzr

    movz    x21, #0xffff
    .inst   0x1dc20420                   /* SETGP: MTE tag form, UNDEF */
    CKX     x21, 0x02000000, 47
    movz    x21, #0xffff
    .inst   0x19c20400                   /* SETP with rd==rn==x0 */
    CKX     x21, 0x02000000, 48
    movz    x21, #0xffff
    .inst   0x19c2c420                   /* SET stage 0b11 unallocated */
    CKX     x21, 0x02000000, 49
    movz    x21, #0xffff
    .inst   0x59c20420                   /* size!=0 unallocated */
    CKX     x21, 0x02000000, 50
    movz    x21, #0xffff
    .inst   0x1d1f0440                   /* CPYP with Rs==31 */
    CKX     x21, 0x02000000, 51

    movz    x21, #0xffff                 /* valid neighbour must not trap */
    mov     x0, x19
    mov     x1, #8
    mov     x2, #0x33
    setp    [x0]!, x1!, x2
    CKX     x21, 0xffff, 52

    /* advertised-contract pin: ID_AA64ISAR2_EL1.MOPS == 1 */
    mrs     x2, id_aa64isar2_el1
    CKX     x2, 0x10000, 53
#endif

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

#ifndef USERMODE
    /* vector table base = 0x40010000; sync from current EL/SP_ELx at +0x200.
     * Record the full ESR (EC + the EC 0x27 ISS under test), skip the insn. */
    .org    0x10200
    mrs     x21, esr_el1
    mrs     x22, elr_el1
    add     x22, x22, #4
    msr     elr_el1, x22
    eret
#endif

.data
.balign 4096
sbuf:   .skip 0x4000                     /* SET target (A/B/C) */
cbuf:   .skip 0x3000                     /* CPY source / backward-overlap area */
dbuf:   .skip 0x3000                     /* CPYF destination / forward-overlap */
