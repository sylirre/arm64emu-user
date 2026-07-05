// SIMD: vector add, across-lanes reductions, min/max — all width-exact and
// independent of DCZID block size. exit code = number of failed checks.
    .globl _start
_start:
    mov x19, #0
    adr x0, v1
    ld1 {v0.16b}, [x0]
    adr x0, v2
    ld1 {v1.16b}, [x0]
    add v2.16b, v0.16b, v1.16b   // each lane = i + (16-i) = 16
    addv b3, v2.16b              // sum = 16*16 = 256; low byte = 0
    umov w4, v3.b[0]
    cbz w4, 1f
    add x19, x19, #1
1:  // UADDLV widens the accumulator: full sum = 256 (no byte truncation)
    uaddlv h5, v2.16b
    umov w6, v5.h[0]
    mov w7, #256
    cmp w6, w7
    b.eq 2f
    add x19, x19, #1
2:  // SMAX vector
    movi v8.16b, #10
    movi v9.16b, #20
    smax v10.16b, v8.16b, v9.16b
    umov w11, v10.b[0]
    cmp w11, #20
    b.eq 3f
    add x19, x19, #1
3:  mov x0, x19
    mov x8, #94
    svc #0
    .balign 16
v1: .byte 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
v2: .byte 16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1
