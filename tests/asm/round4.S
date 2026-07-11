// Round-4 JIT coverage: AdvSIMD scalar 3-same integer (D-form ADD/SUB and
// the six compares), scalar shift-imm (SHL/SSHR/USHR/SSRA/USRA incl. the
// #64 clamp edges), vector SSRA/USRA at every size, and the
// ADC/ADCS/SBC/SBCS family incl. NGC(S) — engineered to enter through every
// x86 lazy-flag state (live add/sub/logic flags and the materialized word).
// Differential: a running checksum is dumped per section; qemu-aarch64 is
// the oracle.
    .globl _start

// checksum: x19 <- mix(x19, \r)
.macro mix r
    eor x19, x19, \r
    ror x19, x19, #13
    add x19, x19, \r
.endm
.macro mixv v
    umov x17, \v\().d[0]
    mix x17
    umov x17, \v\().d[1]
    mix x17
.endm
// fold the current NZCV into the checksum (consumes flags four ways; the
// mix ops themselves are flag-transparent)
.macro mixf
    cset x16, mi
    mix x16
    cset x16, eq
    mix x16
    cset x16, hs
    mix x16
    cset x16, vs
    mix x16
.endm
// close a section: append checksum to the output buffer at x21
.macro sect
    str x19, [x21], #8
.endm

_start:
    mov x19, #0
    adrp x20, buf
    add x20, x20, :lo12:buf         // x20 = scratch buffer
    adrp x21, out
    add x21, x21, :lo12:out         // x21 = checksum output cursor

    // ---- section 1: scalar 3-same integer, D-form ----
    movz x1, #0x8000, lsl #48       // INT64_MIN
    movz x2, #0x7fff, lsl #48
    movk x2, #0xffff, lsl #32
    movk x2, #0xffff, lsl #16
    movk x2, #0xffff                // INT64_MAX
    movz x3, #0xdead, lsl #48
    movk x3, #0xbeef, lsl #32
    movk x3, #0x8421, lsl #16
    movk x3, #0x9ab5
    dup v0.2d, x1                   // d[1] nonzero: clear-high must show
    dup v1.2d, x2
    dup v2.2d, x3                   // junk in every dest lane
    dup v3.2d, x3
    add d2, d0, d1                  // MIN + MAX = -1
    mixv v2
    sub d3, d0, d1                  // MIN - MAX = 1
    mixv v3
    dup v4.2d, x3
    add d4, d4, d4                  // rd == rn == rm
    mixv v4
    fmov d5, x3
    add d5, d5, d1
    mixv v5
    sub d6, d1, d1                  // equal -> 0
    mixv v6
    // all six compares at signed/unsigned boundaries
    cmgt d7, d1, d0                 // MAX > MIN signed: all-ones
    mixv v7
    cmgt d7, d0, d1
    mixv v7
    cmhi d7, d0, d1                 // MIN > MAX unsigned: all-ones
    mixv v7
    cmhi d7, d1, d0
    mixv v7
    cmge d7, d1, d1                 // equal: GE holds
    mixv v7
    cmge d7, d0, d1
    mixv v7
    cmhs d7, d0, d1
    mixv v7
    cmhs d7, d1, d0
    mixv v7
    cmeq d7, d1, d1
    mixv v7
    cmeq d7, d0, d1
    mixv v7
    cmtst d7, d0, d1                // MIN & MAX = 0
    mixv v7
    cmtst d7, d5, d5
    mixv v7
    movi v7.2d, #0
    cmeq d7, d7, d7                 // 0 == 0
    mixv v7
    sect

    // ---- section 2: scalar shift-imm, D-form ----
    movz x1, #0x8000, lsl #48
    movk x1, #0x0001                // sign bit + low bit
    movz x2, #0xffff, lsl #48
    movk x2, #0x0001                // negative accumulator seed
    fmov d0, x1
    dup v2.2d, x2                   // rd==rn seed (d[1] junk: clear-high)
    shl d5, d0, #0
    mixv v5
    shl d5, d0, #1
    mixv v5
    shl d5, d0, #63
    mixv v5
    sshr d6, d0, #1
    mixv v6
    sshr d6, d0, #63
    mixv v6
    sshr d6, d0, #64                // clamps to 63: sign fill
    mixv v6
    ushr d7, d0, #1
    mixv v7
    ushr d7, d0, #64                // 0
    mixv v7
    shl d2, d2, #4                  // rd == rn (accumulator seed pattern)
    mixv v2
    sect

    // ---- section 3: scalar + vector shift-accumulate ----
    movz x1, #0x8000, lsl #48
    movk x1, #0xbeef, lsl #16
    movk x1, #0x0001
    movz x2, #0xffff, lsl #48
    movk x2, #0x8001
    fmov d0, x1
    dup v1.2d, x1
    ins v1.d[1], x2
    // scalar accumulate (onto a negative accumulator, rd == rn, #64 edge)
    fmov d2, x2
    usra d2, d0, #1
    mixv v2
    fmov d3, x2
    ssra d3, d0, #1
    mixv v3
    fmov d4, x2
    usra d4, d0, #64                // shift-out: adds 0
    mixv v4
    fmov d5, x2
    ssra d5, d0, #64                // sign mask: adds -1
    mixv v5
    fmov d6, x1
    usra d6, d6, #7                 // rd == rn
    mixv v6
    // vector accumulate, every size, Q and non-Q, incl. the x86-declined
    // byte and SSRA.2d forms (they must round-trip the helper identically)
    dup v7.2d, x2
    usra v7.2d, v1.2d, #1
    mixv v7
    dup v7.2d, x2
    usra v7.2d, v1.2d, #63
    mixv v7
    dup v7.2d, x2
    usra v7.2d, v1.2d, #64
    mixv v7
    dup v7.2d, x2
    ssra v7.2d, v1.2d, #64
    mixv v7
    dup v7.2d, x2
    usra v7.4s, v1.4s, #17
    mixv v7
    dup v7.2d, x2
    ssra v7.4s, v1.4s, #32
    mixv v7
    dup v7.2d, x2
    usra v7.8h, v1.8h, #9
    mixv v7
    dup v7.2d, x2
    ssra v7.8h, v1.8h, #16
    mixv v7
    dup v7.2d, x2
    usra v7.16b, v1.16b, #3
    mixv v7
    dup v7.2d, x2
    ssra v7.16b, v1.16b, #8
    mixv v7
    dup v7.2d, x2
    usra v7.2s, v1.2s, #5           // non-Q: high half cleared
    mixv v7
    dup v7.2d, x2
    ssra v7.4h, v1.4h, #2
    mixv v7
    dup v7.2d, x2
    usra v7.8b, v1.8b, #1
    mixv v7
    sect

    // ---- section 4: ADC/ADCS/SBC/SBCS/NGC(S) through every flag state ----
    movn x0, #0                     // ~0
    mov x1, #1
    movz x2, #0x8000, lsl #48       // INT64_MIN
    // FL_ADD -> non-S ADC (flags must survive the carry consumption)
    adds x3, x0, x1                 // C=1 Z=1
    adc x4, x1, x1                  // 1+1+1 = 3
    mix x3
    mix x4
    mixf                            // still the ADDS flags
    // FL_ADD -> ADCS chain (multi-precision add), then flag-only ADCS
    adds x3, x0, x0
    adcs x4, x0, x1
    adcs x5, x1, x1
    mix x3
    mix x4
    mix x5
    mixf
    adds x3, x0, x1
    adcs xzr, x0, x1                // flag-only form
    mixf
    // aliasing shapes (d==a / d==b, commut and not)
    adds x6, x1, x1
    mov x7, #5
    mov x8, #9
    adc x7, x7, x8                  // d == a
    adc x8, x7, x8                  // d == b
    mix x7
    mix x8
    subs x6, x1, x0                 // borrow: C=0
    mov x7, #5
    mov x8, #9
    sbc x7, x7, x8                  // d == a
    sbc x8, x7, x8                  // d == b (non-commut RAX path)
    mix x7
    mix x8
    // FL_SUB -> SBCS chain and cmp->ADC
    subs x3, x1, x0                 // 1 - ~0: C=0
    sbcs x4, x1, x1                 // 1-1-1 = -1, borrow again
    sbcs x5, x0, x2
    mix x3
    mix x4
    mix x5
    mixf
    cmp x1, x0                      // C=0
    adc x4, x1, x1                  // 1+1+0
    mix x4
    mixf
    // FL_LOGIC -> ADC (C==0) and SBC (needs stc on x86)
    ands x3, x0, x2                 // C=0, N=1
    adc x4, x1, x1
    mix x3
    mix x4
    mixf
    ands x3, x0, x2
    sbc x4, x1, x1                  // 1-1-1 = -1
    mix x4
    mixf
    // FL_MEM: a load between producer and consumer materializes
    adds x3, x0, x1                 // C=1
    str x3, [x20]
    ldr x9, [x20]
    adc x4, x9, x1
    mix x4
    mixf
    // FCMP-produced C feeding ADC (ordered and unordered)
    fmov d0, x1                     // tiny denormal
    fmov d1, x2                     // -0.0
    fcmp d0, d1                     // greater: C=1
    adc x4, x1, x1
    mix x4
    mixf
    movz x9, #0x7ff8, lsl #48
    movk x9, #1                     // quiet NaN
    fmov d1, x9
    fcmp d0, d1                     // unordered: C=1 V=1
    adc x4, x1, x1
    adcs x5, x0, x1
    mix x4
    mix x5
    mixf
    // W forms: 32-bit carry and signed-overflow edges
    adds w3, w0, w1                 // 0xffffffff+1: C=1 Z=1
    adcs w4, w1, w1
    mix x3
    mix x4
    mixf
    mov w9, #0x80000000
    subs w3, w9, w1                 // signed overflow: V=1
    sbcs w4, w9, w1
    mix x3
    mix x4
    mixf
    adds w3, w0, w0
    adc w4, w0, w1
    mix x3
    mix x4
    // flags-dead ADCS (next ADDS overwrites without a reader)
    adds x3, x0, x1
    adcs x4, x1, x1
    adds x5, x1, x1
    mix x3
    mix x4
    mix x5
    mixf
    // NGC / NGCS
    subs x3, x1, x0                 // C=0
    ngc x4, x1                      // 0-1-1 = -2
    ngcs x5, x2
    mix x3
    mix x4
    mix x5
    mixf
    // HI/LS consumers after ADCS (x86 must re-materialize for these)
    adds x3, x0, x1
    adcs x4, x1, x1                 // C=0 (1+1+1 no carry-out)
    cset x16, hi
    mix x16
    cset x16, ls
    mix x16
    sect

    // ---- section 5: x86 SIMD-parity classes (a64 had them; the x86
    // backend gained MUL, ADDV/MAXV/MINV, 64-bit compares, byte shifts,
    // CNT/RBIT.v/REV*, S/UADDLP). Checksummed against qemu; the still-
    // declined forms (SSHR.b, SSRA.2d) ride along to prove the helper. ----
    movz x1, #0x80ff, lsl #48
    movk x1, #0x7f01, lsl #32
    movk x1, #0x00fe, lsl #16
    movk x1, #0x8001
    movz x2, #0x7f80, lsl #48
    movk x2, #0x0180, lsl #32
    movk x2, #0xff00, lsl #16
    movk x2, #0x7ffe
    dup v0.2d, x1
    ins v0.d[1], x2
    dup v1.2d, x2
    ins v1.d[0], x1
    // vector MUL, all sizes
    mul v2.16b, v0.16b, v1.16b
    mixv v2
    mul v2.8b, v0.8b, v1.8b
    mixv v2
    mul v3.8h, v0.8h, v1.8h
    mixv v3
    mul v3.4h, v0.4h, v1.4h
    mixv v3
    mul v4.4s, v0.4s, v1.4s
    mixv v4
    mul v4.2s, v0.2s, v1.2s
    mixv v4
    // across-lanes reductions
    addv b5, v0.16b
    mixv v5
    addv b5, v0.8b
    mixv v5
    addv h5, v0.8h
    mixv v5
    addv h5, v0.4h
    mixv v5
    addv s5, v0.4s
    mixv v5
    smaxv b6, v0.16b
    mixv v6
    umaxv b6, v0.16b
    mixv v6
    sminv b6, v0.8b
    mixv v6
    uminv b6, v0.8b
    mixv v6
    smaxv h6, v0.8h
    mixv v6
    uminv h6, v0.4h
    mixv v6
    sminv s6, v0.4s
    mixv v6
    umaxv s6, v0.4s
    mixv v6
    // 64-bit lane compares
    cmeq v7.2d, v0.2d, v1.2d
    mixv v7
    cmgt v7.2d, v0.2d, v1.2d
    mixv v7
    cmge v7.2d, v0.2d, v1.2d
    mixv v7
    cmhi v7.2d, v0.2d, v1.2d
    mixv v7
    cmhs v7.2d, v0.2d, v1.2d
    mixv v7
    cmtst v7.2d, v0.2d, v1.2d
    mixv v7
    movi v7.2d, #0
    cmeq v7.2d, v7.2d, v0.2d
    mixv v7
    // byte shifts (+ the declined SSHR.b/SSRA.b helper path)
    shl v2.16b, v0.16b, #3
    mixv v2
    shl v2.8b, v0.8b, #7
    mixv v2
    ushr v3.16b, v0.16b, #2
    mixv v3
    ushr v3.16b, v0.16b, #8
    mixv v3
    dup v4.2d, x2
    usra v4.16b, v0.16b, #3
    mixv v4
    sshr v5.16b, v0.16b, #5
    mixv v5
    dup v6.2d, x2
    ssra v6.16b, v0.16b, #6
    mixv v6
    // CNT / RBIT.v / REV*
    cnt v2.16b, v0.16b
    mixv v2
    cnt v2.8b, v0.8b
    mixv v2
    rbit v3.16b, v0.16b
    mixv v3
    rbit v3.8b, v0.8b
    mixv v3
    rev16 v4.16b, v0.16b
    mixv v4
    rev32 v4.16b, v0.16b
    mixv v4
    rev32 v4.8h, v0.8h
    mixv v4
    rev64 v5.16b, v0.16b
    mixv v5
    rev64 v5.8h, v0.8h
    mixv v5
    rev64 v5.4s, v0.4s
    mixv v5
    rev64 v5.4h, v0.4h
    mixv v5
    // pairwise widening adds
    saddlp v6.8h, v0.16b
    mixv v6
    saddlp v6.4h, v0.8b
    mixv v6
    saddlp v6.4s, v0.8h
    mixv v6
    uaddlp v7.8h, v0.16b
    mixv v7
    uaddlp v7.4s, v0.8h
    mixv v7
    uaddlp v7.2d, v0.4s
    mixv v7
    uaddlp v7.2s, v0.4h
    mixv v7
    saddlp v7.2d, v0.4s             // declined on x86: helper path
    mixv v7
    sect

    // dump checksums
    mov x0, #1                      // fd 1
    adrp x1, out
    add x1, x1, :lo12:out
    sub x2, x21, x1                 // length
    mov x8, #64                     // write
    svc #0
    mov x0, #0
    mov x8, #93                     // exit
    svc #0

    .bss
    .balign 64
buf:
    .skip 256
out:
    .skip 128
