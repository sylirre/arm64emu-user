// Round-3 JIT coverage: bitfield leftovers (SBFIZ/BFI/BFXIL), pre/post and
// register-offset load/store forms, LDRSW literal, LDPSW/LDNP/STNP, S-sized
// vector pairs, SIMD register-offset and non-Q writeback forms, contiguous
// LD1/ST1, DC ZVA, LSE min/max, vector SMAX/UMAX/SMIN/UMIN. Differential:
// a running checksum is dumped per section; qemu-aarch64 is the oracle.
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
// close a section: append checksum to the output buffer at x21
.macro sect
    str x19, [x21], #8
.endm

_start:
    mov x19, #0
    adrp x20, buf
    add x20, x20, :lo12:buf         // x20 = 64B-aligned scratch buffer
    adrp x21, out
    add x21, x21, :lo12:out         // x21 = checksum output cursor

    // ---- section 1: SBFIZ / BFI / BFXIL, 64- and 32-bit ----
    movz x1, #0xdead, lsl #48
    movk x1, #0xbeef, lsl #32
    movk x1, #0x8421, lsl #16
    movk x1, #0x9ab5
    sbfiz x2, x1, #2, #32           // the gzip index idiom
    mix x2
    sbfiz x3, x1, #17, #9
    mix x3
    sbfiz w4, w1, #3, #17
    mix x4
    sbfiz x5, x1, #1, #63
    mix x5
    mov x6, x1
    sbfiz x6, x6, #5, #11           // rd == rn
    mix x6
    movz x7, #0x5a5a, lsl #16
    movk x7, #0xa5a5
    mov x8, x7
    bfi x8, x1, #12, #20
    mix x8
    mov w9, w7
    bfi w9, w1, #4, #9
    mix x9
    mov x10, x7
    bfxil x10, x1, #7, #23
    mix x10
    mov w11, w7
    bfxil w11, w1, #0, #32          // full-width insert
    mix x11
    mov x12, x7
    bfxil x12, x12, #9, #31         // rd == rn
    mix x12
    bfi x7, xzr, #8, #16            // zero source
    mix x7
    sect

    // ---- section 2: pre/post-indexed sub-word and signed forms ----
    movz x1, #0x8843, lsl #16
    movk x1, #0x91c7
    str x1, [x20]
    str x1, [x20, #8]
    mov x0, x20
    ldrb w2, [x0, #1]!              // LDRB pre (hot in coreutils)
    mix x2
    mix x0
    ldrb w3, [x0], #3
    mix x3
    mix x0
    ldrh w4, [x0, #-2]!             // LDRH pre, negative imm
    mix x4
    mix x0
    ldrh w5, [x0], #2
    mix x5
    mix x0
    ldrsb x6, [x0, #1]!
    mix x6
    ldrsb w7, [x0], #-1
    mix x7
    ldrsh x8, [x0, #2]!
    mix x8
    ldrsh w9, [x0], #2
    mix x9
    ldrsw x10, [x0, #-4]!
    mix x10
    ldrsw x11, [x0], #4
    mix x11
    mix x0
    mov x0, x20
    mov w1, #0xe7
    strb w1, [x0, #5]!              // STRB pre
    mix x0
    mov w1, #0xbeb1
    strh w1, [x0, #3]!              // STRH pre
    strh w1, [x0], #-6
    mix x0
    ldr x2, [x20]
    mix x2
    ldr x2, [x20, #8]
    mix x2
    // base-clobber hazard: writeback wins over the loaded value
    str x20, [x20]
    mov x2, x20
    ldr x2, [x2, #8]!               // rd == rn pre
    mix x2
    mov x3, x20
    ldr x3, [x3], #16               // rd == rn post
    mix x3
    mov x4, x20
    ldrb w4, [x4], #1               // rd == rn post, 32-bit sub-word
    mix x4
    sect

    // ---- section 3: register-offset signed + SIMD, LDRSW literal ----
    mov w1, #24
    mov x2, #-8
    ldrsw x3, [x20, w1, sxtw]
    mix x3
    ldrsw x4, [x20, w1, uxtw #2]
    mix x4
    add x0, x20, #16
    ldrsb x5, [x0, x2]              // negative 64-bit register offset
    mix x5
    ldrsh x6, [x20, w1, sxtw #1]
    mix x6
    ldrsb w7, [x20, w1, uxtw]
    mix x7
    ldrsh w8, [x20, x1]
    mix x8
    ldr q0, [x20, x1]               // SIMD register offset
    mixv v0
    ldr d1, [x20, w1, uxtw #3]
    mixv v1
    ldr s2, [x20, x1, lsl #2]
    mixv v2
    ldr h3, [x20, x1]
    mixv v3
    ldr b4, [x20, x1]
    mixv v4
    str q0, [x20, x1, lsl #0]
    str d1, [x20, w1, sxtw]
    ldr x9, [x20, #24]
    mix x9
    ldrsw x10, lit0                 // LDRSW (literal)
    mix x10
    sect

    // ---- section 4: SIMD pre/post writeback (non-Q sizes) ----
    mov x0, x20
    ldr d5, [x0, #8]!
    mixv v5
    mix x0
    ldr s6, [x0], #4
    mixv v6
    ldr h7, [x0, #2]!
    mixv v7
    ldr b8, [x0], #-3
    mixv v8
    mix x0
    str d5, [x0, #16]!
    str s6, [x0], #8
    str h7, [x0, #-2]!
    str b8, [x0], #1
    mix x0
    ldr x1, [x20, #16]
    mix x1
    ldr x1, [x20, #24]
    mix x1
    sect

    // ---- section 5: pair leftovers: LDPSW, LDNP/STNP, S pairs ----
    movz x1, #0x8000, lsl #16       // negative word
    movk x1, #0x1234
    orr x2, x1, #0xff
    stp w1, w2, [x20]
    ldpsw x3, x4, [x20]
    mix x3
    mix x4
    mov x0, x20
    ldpsw x5, x6, [x0], #8          // post
    mix x5
    mix x6
    mix x0
    mov x0, x20
    ldpsw x7, x8, [x0, #8]!         // pre (only w-pair at +8: garbage but deterministic)
    mix x7
    mix x0
    stnp x1, x2, [x20, #16]
    ldnp x9, x10, [x20, #16]
    mix x9
    mix x10
    stnp w2, w1, [x20, #32]
    ldnp w11, w12, [x20, #32]
    mix x11
    mix x12
    ldr q0, [x20]
    stnp q0, q0, [x20, #32]
    ldnp q1, q2, [x20, #32]
    mixv v1
    mixv v2
    stp s0, s1, [x20, #16]          // S-sized vector pairs
    ldp s3, s4, [x20, #16]
    mixv v3
    mixv v4
    mov x0, x20
    ldp s5, s6, [x0], #8
    mixv v5
    mix x0
    mov x0, x20
    stp s3, s4, [x0, #24]!
    mix x0
    ldnp s7, s8, [x20, #24]
    mixv v7
    mixv v8
    sect

    // ---- section 6: contiguous LD1/ST1 multiple ----
    // fill 64B with a pattern first
    mov x0, x20
    movz x1, #0x0123, lsl #48
    movk x1, #0x4567, lsl #32
    movk x1, #0x89ab, lsl #16
    movk x1, #0xcdef
    mov x2, #8
1:  str x1, [x0], #8
    add x1, x1, #0x111
    subs x2, x2, #1
    b.ne 1b
    ld1 {v0.16b}, [x20]
    mixv v0
    ld1 {v1.16b, v2.16b}, [x20]
    mixv v1
    mixv v2
    ld1 {v3.4s, v4.4s, v5.4s}, [x20]
    mixv v3
    mixv v5
    ld1 {v6.2d, v7.2d, v8.2d, v9.2d}, [x20]
    mixv v6
    mixv v9
    ld1 {v10.8b}, [x20]             // 8-byte registers
    mixv v10
    ld1 {v11.8b, v12.8b}, [x20]
    mixv v12
    mov x0, x20
    ld1 {v13.16b, v14.16b}, [x0], #32      // post-index immediate
    mix x0
    mixv v13
    mov x0, x20
    mov x1, #24
    ld1 {v15.8b}, [x0], x1                 // post-index register
    mix x0
    mixv v15
    ld1 {v30.16b, v31.16b}, [x20]          // reg number wrap next
    mixv v30
    mixv v31
    mov x0, x20
    st1 {v0.16b}, [x0], #16
    st1 {v10.8b, v11.8b}, [x0], x1
    mix x0
    st1 {v3.4s, v4.4s, v5.4s}, [x20]
    ldr q0, [x20, #32]
    mixv v0
    sect

    // ---- section 7: DC ZVA ----
    // qemu's `max` CPU uses a 512-byte ZVA block (DCZID BS=7) while ours is
    // 64 bytes, so the ZVA gets its own 512B-aligned, 512B buffer and only
    // the first 64 bytes (zeroed under both sizes) are checked.
    adrp x22, zbuf
    add x22, x22, :lo12:zbuf
    mov x0, x22
    mov x1, #64
    movz x2, #0xa5a5
2:  strh w2, [x0], #2
    subs x1, x1, #2
    b.ne 2b
    add x0, x22, #17                // unaligned pointer: ZVA aligns down
    dc zva, x0
    ldr x1, [x22]
    mix x1
    ldr x1, [x22, #56]
    mix x1
    ldrb w1, [x22, #63]
    mix x1
    sect

    // ---- section 8: LSE min/max ----
    movz w1, #0x8000, lsl #16       // INT32_MIN as unsigned big value
    str w1, [x20]
    mov w2, #5
    ldsmax w2, w3, [x20]            // signed: 5 > INT32_MIN
    mix x3
    ldr w3, [x20]
    mix x3
    mov w2, #5
    ldumax w2, w4, [x20]            // unsigned: 0x80000000 wins
    mix x4
    ldr w4, [x20]
    mix x4
    mov w2, #-7
    ldsmin w2, w5, [x20]
    mix x5
    ldr w5, [x20]
    mix x5
    mov w2, #3
    ldumin w2, w6, [x20]
    mix x6
    ldr w6, [x20]
    mix x6
    // 64-bit, acquire/release flavors
    mov x1, #-1
    str x1, [x20, #8]
    mov x2, #100
    add x0, x20, #8
    ldsmaxa x2, x7, [x0]
    mix x7
    ldr x7, [x20, #8]
    mix x7
    add x0, x20, #8
    mov x2, #100
    ldumaxl x2, x8, [x0]
    mix x8
    mov x2, #-200
    ldsminal x2, x9, [x0]
    mix x9
    ldr x9, [x0]
    mix x9
    mov x2, #50
    lduminal x2, x10, [x0]
    ldr x10, [x0]
    mix x10
    // byte/halfword with sign boundaries
    mov w1, #0x80
    strb w1, [x20]
    mov w2, #0x7f
    ldsmaxb w2, w11, [x20]          // s8: 0x7f > 0x80(-128)
    mix x11
    ldrb w11, [x20]
    mix x11
    mov w2, #0x7f
    lduminb w2, w12, [x20]          // u8: 0x7f < 0x80
    ldrb w12, [x20]
    mix x12
    movz w1, #0x8000
    strh w1, [x20, #2]
    add x0, x20, #2
    mov w2, #0x7fff
    ldsmaxh w2, w13, [x0]
    mix x13
    ldrh w13, [x0]
    mix x13
    mov w2, #1
    ldsminh w2, w14, [x0]
    ldrh w14, [x0]
    mix x14
    mov w2, #0xffff
    ldumaxh w2, w15, [x0]
    ldrh w15, [x0]
    mix x15
    // ST-forms (Rt = XZR)
    mov w2, #0x42
    stsmaxb w2, [x20]
    ldrb w16, [x20]
    mix x16
    stumin w2, [x20]
    ldr w17, [x20]
    mix x17
    sect

    // ---- section 9: vector SMAX/UMAX/SMIN/UMIN three-same ----
    movz x1, #0x80ff, lsl #48
    movk x1, #0x7f01, lsl #32
    movk x1, #0x00fe, lsl #16
    movk x1, #0x8001
    dup v0.2d, x1
    movz x2, #0x7f80, lsl #48
    movk x2, #0x0180, lsl #32
    movk x2, #0xff00, lsl #16
    movk x2, #0x7ffe
    dup v1.2d, x2
    smax v2.16b, v0.16b, v1.16b
    mixv v2
    umax v3.16b, v0.16b, v1.16b
    mixv v3
    smin v4.16b, v0.16b, v1.16b
    mixv v4
    umin v5.16b, v0.16b, v1.16b
    mixv v5
    smax v6.8h, v0.8h, v1.8h
    mixv v6
    umax v7.8h, v0.8h, v1.8h
    mixv v7
    smin v8.8h, v0.8h, v1.8h
    mixv v8
    umin v9.8h, v0.8h, v1.8h
    mixv v9
    smax v10.4s, v0.4s, v1.4s
    mixv v10
    umax v11.4s, v0.4s, v1.4s
    mixv v11
    smin v12.4s, v0.4s, v1.4s
    mixv v12
    umin v13.4s, v0.4s, v1.4s
    mixv v13
    smax v14.8b, v0.8b, v1.8b       // 64-bit forms zero the top half
    mixv v14
    umin v15.4h, v0.4h, v1.4h
    mixv v15
    smin v16.2s, v0.2s, v1.2s
    mixv v16
    sect

    // ---- section 10: RBIT ----
    movz x1, #0x8001, lsl #48
    movk x1, #0xf00f, lsl #32
    movk x1, #0x1234, lsl #16
    movk x1, #0xa5c3
    rbit x2, x1
    mix x2
    rbit w3, w1
    mix x3
    rbit x4, xzr
    mix x4
    mov x5, x1
    rbit x5, x5                     // rd == rn
    mix x5
    rbit w6, wzr
    mix x6
    sect

    // ---- section 11: scalar FP (FMA family, conversions, FCCMP, minmax) --
    // Inputs avoid the interpreter's documented approximations vs real ARM
    // (unfused FMA rounding on x86 hosts, NaN->int = host C, min/max NaN/±0),
    // exercising plumbing: register routing, signs, widths, saturation.
    adrp x0, cst0
    add x0, x0, :lo12:cst0          // (SIMD literal loads: undefined in the
    ldr d0, [x0]                    //  core interpreter, so address + ldr)
    ldr d1, [x0, #8]
    ldr d2, [x0, #16]
    fmadd d3, d0, d1, d2
    mixv v3
    fmsub d4, d0, d1, d2
    mixv v4
    fnmadd d5, d0, d1, d2
    mixv v5
    fnmsub d6, d0, d1, d2
    mixv v6
    fcvt s7, d1                     // -7.25f: s7*s7 exact in float, so the
    mixv v7                         // unfused-x86 FMA matches fused qemu
    fmadd s8, s7, s7, s7
    mixv v8
    fnmsub s9, s7, s7, s7
    mixv v9
    fcvt d10, s7
    mixv v10
    // int -> fp, incl. the u64 top-bit halving path and rounding lsb
    movz x1, #0x8000, lsl #48
    movk x1, #0x0001                // 2^63 + 1: u64 path rounds
    ucvtf d11, x1
    mixv v11
    scvtf d12, x1                   // negative s64
    mixv v12
    ucvtf s13, x1
    mixv v13
    scvtf s14, w1                   // w = 1
    mixv v14
    mov w2, #-19
    scvtf d15, w2
    mixv v15
    ucvtf d16, w2                   // big u32
    mixv v16
    // fp -> int: exact, fractional, saturating (no NaN: host-C behavior)
    fcvtzs x3, d0
    mix x3
    fcvtzu x4, d0
    mix x4
    fcvtzs w5, d0
    mix x5
    fcvtzu w6, d0
    mix x6
    fcvtzs x7, s7
    mix x7
    ldr d17, [x0, #24]              // 1e20: saturates everything
    fcvtzs x8, d17
    mix x8
    fcvtzu x9, d17
    mix x9
    fcvtzs w10, d17
    mix x10
    fcvtzu w11, d17
    mix x11
    fneg d18, d17
    fcvtzs x12, d18
    mix x12
    fcvtzu x13, d18
    mix x13
    fcvtzs w14, d18
    mix x14
    // FCCMP: taken and not-taken paths, then read flags via cset
    fcmp d0, d1                     // d0 vs d1: sets flags
    fccmp d1, d2, #0xb, ge          // ge? compare : nzcv=0xb
    cset x15, lt
    mix x15
    fccmp d1, d2, #0x4, lt
    cset x16, eq
    mix x16
    fccmpe s7, s7, #0x1, al
    cset x15, vs
    mix x15
    // scalar FMAX/FMIN on ordinary distinct values
    fmax d19, d0, d1
    mixv v19
    fmin d20, d0, d1
    mixv v20
    fmaxnm d21, d1, d2
    mixv v21
    fminnm s22, s7, s8
    mixv v22
    sect

    // ---- section 12: vector coverage (compares, misc, narrows, FP) ----
    movz x1, #0x80ff, lsl #48
    movk x1, #0x7f01, lsl #32
    movk x1, #0x00fe, lsl #16
    movk x1, #0x8001
    dup v0.2d, x1
    movz x2, #0x7f80, lsl #48
    movk x2, #0x0180, lsl #32
    movk x2, #0xff00, lsl #16
    movk x2, #0x7ffe
    dup v1.2d, x2
    ins v0.d[0], x2
    // three-same compare extensions
    cmtst v2.16b, v0.16b, v1.16b
    mixv v2
    cmtst v2.4s, v0.4s, v1.4s
    mixv v2
    cmhi v3.16b, v0.16b, v1.16b
    mixv v3
    cmhi v3.8h, v0.8h, v1.8h
    mixv v3
    cmhs v4.4s, v0.4s, v1.4s
    mixv v4
    cmge v5.16b, v0.16b, v1.16b
    mixv v5
    cmge v5.4h, v0.4h, v1.4h
    mixv v5
    // two-reg misc
    cmeq v6.16b, v0.16b, #0
    mixv v6
    cmgt v6.8h, v0.8h, #0
    mixv v6
    cmlt v7.4s, v0.4s, #0
    mixv v7
    cmge v7.16b, v0.16b, #0
    mixv v7
    cmle v8.8h, v0.8h, #0
    mixv v8
    cmeq v8.2d, v0.2d, #0
    mixv v8
    abs v9.16b, v0.16b
    mixv v9
    abs v9.4s, v0.4s
    mixv v9
    neg v10.8h, v0.8h
    mixv v10
    neg v10.2d, v0.2d
    mixv v10
    mvn v11.16b, v0.16b
    mixv v11
    rbit v11.16b, v0.16b
    mixv v11
    cnt v12.8b, v0.8b
    mixv v12
    clz v12.4s, v0.4s
    mixv v12
    cls v13.8h, v0.8h
    mixv v13
    rev16 v13.16b, v0.16b
    mixv v13
    rev32 v14.8h, v0.8h
    mixv v14
    rev64 v14.4s, v0.4s
    mixv v14
    saddlp v15.4s, v0.8h
    mixv v15
    uaddlp v15.8h, v0.16b
    mixv v15
    shll v16.8h, v0.8b, #8
    mixv v16
    xtn v16.8b, v0.8h
    mixv v16
    xtn v17.4h, v0.4s
    mixv v17
    xtn v17.2s, v0.2d
    mixv v17
    mov v18.16b, v1.16b
    xtn2 v18.16b, v0.8h
    mixv v18
    mov v18.16b, v1.16b
    xtn2 v18.4s, v0.2d
    mixv v18
    // narrowing / widening shifts
    shrn v19.8b, v0.8h, #3
    mixv v19
    shrn v19.4h, v0.4s, #9
    mixv v19
    shrn v20.2s, v0.2d, #17
    mixv v20
    mov v21.16b, v1.16b
    shrn2 v21.16b, v0.8h, #2
    mixv v21
    ushll v22.8h, v0.8b, #3
    mixv v22
    ushll2 v22.8h, v0.16b, #0
    mixv v22
    ushll v23.4s, v0.4h, #7
    mixv v23
    ushll v23.2d, v0.2s, #11
    mixv v23
    sshll v24.8h, v0.8b, #2
    mixv v24
    sshll2 v24.4s, v0.8h, #5
    mixv v24
    sshll v25.2d, v0.2s, #1
    mixv v25
    // mul, pairwise, across-lanes
    mul v26.16b, v0.16b, v1.16b
    mixv v26
    mul v26.8h, v0.8h, v1.8h
    mixv v26
    mul v26.4s, v0.4s, v1.4s
    mixv v26
    addp v27.16b, v0.16b, v1.16b
    mixv v27
    addp v27.4s, v0.4s, v1.4s
    mixv v27
    addp v27.2d, v0.2d, v1.2d
    mixv v27
    umaxp v28.16b, v0.16b, v1.16b
    mixv v28
    uminp v28.8h, v0.8h, v1.8h
    mixv v28
    smaxp v29.4s, v0.4s, v1.4s
    mixv v29
    sminp v29.8b, v0.8b, v1.8b
    mixv v29
    addv b30, v0.16b
    mixv v30
    addv h30, v0.8h
    mixv v30
    addv s30, v0.4s
    mixv v30
    uminv b31, v1.16b
    mixv v31
    umaxv h31, v1.8h
    mixv v31
    sminv s31, v0.4s
    mixv v31
    smaxv b31, v0.8b
    mixv v31
    sect

    // ---- section 13: vector FP (exact values; compares may see NaN) ----
    adrp x0, cst0
    add x0, x0, :lo12:cst0
    ldr d0, [x0]
    ldr d1, [x0, #8]
    ldr d2, [x0, #16]
    dup v3.2d, v0.d[0]
    ins v3.d[1], v1.d[0]            // v3 = {1234.5625, -7.25}
    dup v4.2d, v2.d[0]
    ins v4.d[0], v1.d[0]            // v4 = {-7.25, 0.4375}
    fcvtn v5.2s, v3.2d
    fcvtn2 v5.4s, v4.2d             // v5 = 4 floats (helper path: ok)
    dup v6.4s, v5.s[1]
    ins v6.s[2], v5.s[3]
    fadd v7.2d, v3.2d, v4.2d
    mixv v7
    fsub v7.4s, v5.4s, v6.4s
    mixv v7
    fmul v8.2d, v3.2d, v4.2d
    mixv v8
    fmul v8.2s, v5.2s, v6.2s
    mixv v8
    fdiv v9.4s, v5.4s, v6.4s
    mixv v9
    fabd v9.2d, v3.2d, v4.2d
    mixv v9
    fmla v10.2d, v3.2d, v4.2d       // v10 accumulates (exact products)
    mixv v10
    fmls v10.4s, v5.4s, v6.4s
    mixv v10
    fcmeq v11.2d, v3.2d, v4.2d
    mixv v11
    fcmge v11.4s, v5.4s, v6.4s
    mixv v11
    fcmgt v12.2d, v3.2d, v4.2d
    mixv v12
    facge v12.4s, v5.4s, v6.4s
    mixv v12
    facgt v13.2d, v3.2d, v4.2d
    mixv v13
    // compares against a NaN operand (mask semantics are exact)
    movz x1, #0x7ff8, lsl #48
    dup v14.2d, x1                  // quiet NaN lanes
    fcmeq v15.2d, v3.2d, v14.2d
    mixv v15
    fcmgt v15.4s, v5.4s, v14.4s
    mixv v15
    fcmeq v16.4s, v14.4s, v14.4s
    mixv v16
    sect

    // ---- dump checksums and exit ----
    mov x0, #1                      // fd 1
    adrp x1, out
    add x1, x1, :lo12:out
    sub x2, x21, x1                 // length
    mov x8, #64                     // write
    svc #0
    mov x0, #0
    mov x8, #93                     // exit
    svc #0

    .balign 8
lit0:
    .word 0x80f01234                // negative for LDRSW literal
    .word 0
cst0:
    .double 1234.5625
cst1:
    .double -7.25
cst2:
    .double 0.4375
cbig:
    .double 1e20

    .bss
    .balign 512
zbuf:
    .skip 512                       // DC ZVA target (see section 7)
buf:
    .skip 256
out:
    .skip 128
