// Pre-decode torture test: exercises the instruction forms the decode cache
// specializes (src/predecode.c), with edge operands — SP bases/destinations,
// XZR sources/destinations, negative and unscaled offsets, writeback, pair
// and vector forms, both outcomes of every conditional. Every result is
// folded into an FNV-style hash printed at exit; the suite diffs the output
// against qemu, so any semantic divergence in any handler changes the hash.
    .globl _start

// fold \reg into the hash in x19 (x22 holds the FNV prime)
.macro ACC reg
    eor x19, x19, \reg
    mul x19, x19, x22
.endm
// fold current NZCV in via cset (both taken/not-taken cset outcomes matter)
.macro ACCF
    cset x21, eq
    ACC x21
    cset x21, cs
    ACC x21
    cset x21, mi
    ACC x21
    cset x21, vs
    ACC x21
.endm

_start:
    movz x22, #0x01b3               // FNV prime 0x100000001b3
    movk x22, #0x0100, lsl #32
    movz x19, #0xcbf2               // seed
    sub sp, sp, #544                // scratch buffer
    mov x21, sp                     // zero it all: reads of never-stored
    mov x1, #34                     // bytes must be deterministic
1:  stp xzr, xzr, [x21], #16
    subs x1, x1, #1
    b.ne 1b
    add x20, sp, #32                // buffer base (16-aligned, room below)
    movi v1.16b, #0x3c              // deterministic vector source

// ---- move wide / PC-relative ----
    movz x0, #0xbeef
    movk x0, #0xdead, lsl #16
    movk x0, #0x5678, lsl #32
    movk x0, #0x1234, lsl #48
    ACC x0
    movn x1, #0x00ff, lsl #16
    ACC x1
    movn w2, #0xffff
    ACC x2
    movz w3, #0xabcd, lsl #16
    movk w3, #0x9876
    ACC x3
    adr x4, _start
    adrp x5, _start
    sub x6, x4, x5                  // page offset of _start: layout-stable
    ACC x6
    ldr x7, =0x0123456789abcdef     // literal pool load (LDR literal)
    ACC x7

// ---- add/sub imm, flags, SP forms ----
    add x0, x0, #0xfff
    ACC x0
    sub x0, x0, #0xabc, lsl #12
    ACC x0
    add w1, w2, #4095
    ACC x1
    sub sp, sp, #64                 // SP as Rd and Rn
    add x1, sp, #48
    mov x21, sp
    sub x2, x1, x21
    ACC x2
    add sp, sp, #64
    adds x3, x7, #1
    ACCF
    subs w4, w2, #0x123
    ACCF
    ACC x4
    cmp x7, #0                      // SUBS with Rd=XZR
    ACCF
    cmn w2, #1
    ACCF

// ---- logical imm (bitmask decode), ANDS ----
    and x5, x7, #0x5555555555555555
    ACC x5
    orr x5, x7, #0xff00ff00ff00ff00
    ACC x5
    eor w6, w2, #0x0f0f0f0f
    ACC x6
    ands x6, x7, #0xf0f0f0f0f0f0f0f0
    ACCF
    ACC x6
    tst w2, #0x80000000             // ANDS Rd=XZR
    ACCF
    mov x21, sp                     // logical imm Rd=SP
    orr sp, x21, #0xf
    mov x1, sp
    mov sp, x21
    sub x1, x1, x21
    ACC x1

// ---- bitfield aliases / extr ----
    lsl x8, x7, #17
    ACC x8
    lsr x8, x7, #43
    ACC x8
    asr x8, x0, #7
    ACC x8
    lsl w9, w7, #9
    ACC x9
    lsr w9, w0, #21
    ACC x9
    asr w9, w0, #3
    ACC x9
    ubfx x10, x7, #13, #27
    ACC x10
    sbfx x10, x0, #9, #31
    ACC x10
    ubfx w11, w7, #5, #11
    ACC x11
    sbfx w11, w0, #2, #17
    ACC x11
    ubfiz x12, x7, #21, #19
    ACC x12
    ubfiz w12, w7, #11, #13
    ACC x12
    uxtb w13, w0
    ACC x13
    uxth w13, w0
    ACC x13
    sxtb x14, w0
    ACC x14
    sxth x14, w0
    ACC x14
    sxtw x14, w0
    ACC x14
    sxtb w15, w0
    ACC x15
    extr x16, x7, x0, #29
    ACC x16
    ror x16, x7, #51                // EXTR Rn==Rm
    ACC x16
    extr w17, w7, w0, #13
    ACC x17
    ror w17, w7, #23
    ACC x17

// ---- logical / add-sub register (LSL0, shifted, extended) ----
    and x1, x7, x0
    ACC x1
    bic x1, x7, x0
    ACC x1
    orr x1, x7, x0, lsl #11
    ACC x1
    orn x1, x7, x0, lsr #3
    ACC x1
    eor x1, x7, x0, asr #33
    ACC x1
    eon x1, x7, x0, ror #7
    ACC x1
    ands x1, x7, x0, lsl #2
    ACCF
    ACC x1
    bics w1, w7, w0, lsr #5
    ACCF
    ACC x1
    mvn w2, w0
    ACC x2
    mov x2, x0                      // ORR Rn=XZR
    ACC x2
    add x3, x7, x0
    ACC x3
    sub x3, x7, x0, lsl #4
    ACC x3
    adds w3, w7, w0, lsr #9
    ACCF
    ACC x3
    subs x3, x7, x0, asr #21
    ACCF
    ACC x3
    cmp x7, x0                      // SUBS reg, Rd=XZR
    ACCF
    neg x3, x0                      // SUB Rn=XZR
    ACC x3
    mov x21, sp
    add x4, sp, w0, uxtw #2         // extended reg, SP base
    sub x4, x4, x21
    ACC x4
    add w4, w7, w0, sxth #1
    ACC x4
    subs x4, x7, w0, sxtw #3        // flag-setting extended
    ACCF
    ACC x4
    adds x4, x7, x0, uxtx #4
    ACCF
    ACC x4

// ---- mul / div / variable shifts / clz / rev ----
    mul x5, x7, x0
    ACC x5
    madd x5, x7, x0, x19
    ACC x5
    msub x5, x7, x0, x19
    ACC x5
    mul w5, w7, w0
    ACC x5
    smull x5, w7, w0
    ACC x5
    umull x5, w7, w0
    ACC x5
    smnegl x5, w7, w0
    ACC x5
    umsubl x5, w7, w0, x19
    ACC x5
    smulh x5, x7, x0
    ACC x5
    umulh x5, x7, x0
    ACC x5
    udiv x6, x7, x0
    ACC x6
    sdiv x6, x0, x7
    ACC x6
    mov x21, #0
    udiv x6, x7, x21                // divide by zero -> 0
    ACC x6
    sdiv x6, x7, x21
    ACC x6
    mov x21, #-1
    mov x8, #0x8000000000000000     // INT64_MIN / -1 -> INT64_MIN
    sdiv x6, x8, x21
    ACC x6
    mov w9, #0x80000000
    sdiv w6, w9, w21
    ACC x6
    lsl x6, x7, x0                  // LSLV: amount mod 64
    ACC x6
    lsr w6, w7, w0
    ACC x6
    asr x6, x0, x7
    ACC x6
    ror w6, w7, w0
    ACC x6
    clz x6, x0
    ACC x6
    clz w6, w2
    ACC x6
    clz x6, xzr                     // CLZ(0) = 64
    ACC x6
    rev x6, x7
    ACC x6
    rev w6, w7
    ACC x6

// ---- csel family / ccmp (both cond outcomes each) ----
    cmp x7, x0
    csel x1, x7, x0, lo
    ACC x1
    csel x1, x7, x0, hs
    ACC x1
    csinc w1, w7, w0, eq
    ACC x1
    csinv x1, x7, x0, ne
    ACC x1
    csneg x1, x7, x0, gt
    ACC x1
    cinc x1, x7, lt
    ACC x1
    csetm x1, pl
    ACC x1
    cmp x7, x7
    ccmp x7, #13, #0xb, eq          // cond true: real compare
    ACCF
    ccmp x7, #13, #0xb, ne          // cond false: nzcv immediate
    ACCF
    ccmn w7, w0, #0x5, hs           // register form
    ACCF
    ccmp x0, x7, #0xf, lt
    ACCF

// ---- loads/stores: offsets, writeback, pairs, literal, vector ----
    str x7, [x20]
    str w0, [x20, #8]
    strh w0, [x20, #12]
    strb w0, [x20, #14]
    str xzr, [x20, #16]             // store of XZR
    ldr x1, [x20]
    ACC x1
    ldr w1, [x20, #8]
    ACC x1
    ldrh w1, [x20, #12]
    ACC x1
    ldrb w1, [x20, #14]
    ACC x1
    ldr x1, [x20, #16]
    ACC x1
    str x7, [sp]
    .inst 0xf94003ff                // ldr xzr, [sp] : load discarded
    ldrsb x1, [x20, #14]            // sign-extending loads
    ACC x1
    ldrsb w1, [x20, #14]
    ACC x1
    ldrsh x1, [x20, #12]
    ACC x1
    ldrsh w1, [x20, #12]
    ACC x1
    ldrsw x1, [x20, #8]
    ACC x1
    prfm pldl1keep, [x20]           // PRFM: no-op
    add x2, x20, #32
    ldur x1, [x2, #-24]             // unscaled negative offsets
    ACC x1
    stur w7, [x2, #-4]
    ldur w1, [x2, #-4]
    ACC x1
    // pre/post writeback (base register updates folded in too)
    mov x3, x20
    str x7, [x3], #8
    str w7, [x3], #4
    strb w7, [x3], #1
    sub x4, x3, x20
    ACC x4
    mov x3, x20
    ldr x1, [x3], #8
    ACC x1
    ldr w1, [x3], #4
    ACC x1
    ldrb w1, [x3], #1
    ACC x1
    sub x4, x3, x20
    ACC x4
    str x0, [x3, #16]!              // unaligned pre-index (base = x20+13)
    sub x4, x3, x20
    ACC x4
    ldr x1, [x3], #-16
    ACC x1
    ldr w1, [x3, #8]!
    ACC x1
    sub x3, x3, x20
    ACC x3
    // register-offset addressing
    mov x5, #3
    str x7, [x20, x5, lsl #3]
    ldr x1, [x20, x5, lsl #3]
    ACC x1
    mov w5, #40
    ldr w1, [x20, w5, uxtw]
    ACC x1
    str h1, [x20, #48]
    add x6, x20, #64
    mov w5, #-16
    ldr x1, [x6, w5, sxtw]          // negative extended index -> [x20+48]
    ACC x1
    mov w5, #24
    ldrh w1, [x20, w5, uxtw #1]     // shifted halfword index -> [x20+48]
    ACC x1
    // pairs: offset / pre / post, 64 and 32, incl. negative pre-offset
    stp x7, x0, [x20, #64]
    ldp x1, x2, [x20, #64]
    ACC x1
    ACC x2
    stp w7, w0, [x20, #80]
    ldp w1, w2, [x20, #80]
    ACC x1
    ACC x2
    add x3, x20, #128
    stp x0, x7, [x3, #-32]!
    sub x4, x3, x20
    ACC x4
    ldp x1, x2, [x3], #32
    ACC x1
    ACC x2
    sub x4, x3, x20
    ACC x4
    stnp x7, x0, [x20, #96]
    ldnp x2, x1, [x20, #96]
    ACC x1
    ACC x2
    // vector loads/stores: b/h/s/d/q, pairs, writeback
    str q1, [x20, #112]
    ldr q2, [x20, #112]
    str q2, [x20, #128]
    ldr x1, [x20, #128]
    ACC x1
    ldr x1, [x20, #136]
    ACC x1
    str d1, [x20, #144]
    ldr d3, [x20, #144]
    str d3, [x20, #152]
    ldr x1, [x20, #152]
    ACC x1
    str s1, [x20, #160]
    ldr s3, [x20, #160]
    str h1, [x20, #164]
    ldr h3, [x20, #164]
    str b1, [x20, #166]
    ldr b3, [x20, #166]
    str q3, [x20, #176]             // s/h/b loads zero the high bits
    ldp x1, x2, [x20, #176]
    ACC x1
    ACC x2
    stur q1, [x20, #-16]            // unscaled vector (zeroed slack below x20)
    ldur q3, [x20, #-16]
    str q3, [x20, #192]
    ldr x1, [x20, #192]
    ACC x1
    mov x3, x20
    str q1, [x3], #16               // vector post/pre writeback
    ldr q4, [x3, #-16]
    str q4, [x20, #208]
    ldr x1, [x20, #208]
    ACC x1
    sub x4, x3, x20
    ACC x4
    stp q1, q2, [x20, #224]
    ldp q4, q5, [x20, #224]
    stp q4, q5, [x20, #256]
    ldr x1, [x20, #256]
    ACC x1
    ldr x1, [x20, #280]
    ACC x1
    stp d1, d2, [x20, #288]
    ldp d4, d5, [x20, #288]
    stp d4, d5, [x20, #304]
    ldr x1, [x20, #304]
    ACC x1
    add x3, x20, #352
    stp q1, q2, [x3, #-32]!
    sub x4, x3, x20
    ACC x4
    ldp q4, q5, [x3], #32
    sub x4, x3, x20
    ACC x4
    stp d1, d2, [x3], #16
    sub x4, x3, x20
    ACC x4
    ldp d4, d5, [x3, #-16]!
    sub x4, x3, x20
    ACC x4

// ---- branches: cbz/cbnz/tbz/tbnz both ways, b.cond loop, bl/br/blr ----
    mov x1, #0
    cbz x1, 20f
    ACC x22                         // must be skipped
20: cbnz x1, 21f
    mov x2, #77
    ACC x2
21: mov w1, #1
    cbz w1, 22f
    cbnz w1, 23f
22: ACC x22                         // must be skipped
23: tbz x7, #0, 24f                 // bit 0 of ...ef = 1 -> not taken
    mov x2, #88
    ACC x2
24: tbnz x7, #4, 25f                // bit 4 of ...ef = 0 -> not taken
    mov x2, #99
    ACC x2
25: tbz x7, #63, 26f                // high bit (uses bit31 of encoding)
    ACC x22
26: mov x1, #10                     // countdown loop: b.cond backward edge
27: ACC x1
    subs x1, x1, #1
    b.ne 27b
    bl 28f                          // BL: x30 = return address
    ACC x2
    b 29f
28: mov x2, #123
    ret                             // RET
29: adr x1, 30f
    blr x1                          // BLR
    b 31f
30: mov x2, #456
    ACC x2
    ret
31: adr x1, 32f
    br x1                           // BR
    ACC x22                         // must be skipped
32: nop
    yield

// ---- report: print hash as 16 hex digits + newline ----
    adr x4, hexbuf
    mov x5, #16
33: sub x5, x5, #1
    lsr x6, x19, #60
    add w6, w6, #'0'
    cmp w6, #'9'
    b.le 34f
    add w6, w6, #39                 // 'a'-'0'-10
34: strb w6, [x4], #1
    lsl x19, x19, #4
    cbnz x5, 33b
    mov w6, #'\n'
    strb w6, [x4]
    mov x0, #1
    adr x1, hexbuf
    mov x2, #17
    mov x8, #64                     // write
    svc #0
    mov x0, #0
    mov x8, #94                     // exit_group
    svc #0

    .data
    .balign 16
hexbuf: .space 24
