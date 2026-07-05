// ALU + flags + exclusives self-test: writes PASS/FAIL, exits with #errors
    .globl _start
_start:
    mov x19, #0                 // error count
    sub sp, sp, #32
    mov x21, sp                 // scratch
    // adds/flags
    mov x0, #-1
    adds x1, x0, #1             // 0, C=1 Z=1
    b.ne 1f
    b.cs 2f
1:  add x19, x19, #1
2:  // exclusive load/store
    mov x3, x21
    ldxr w4, [x3]
    add w4, w4, #5
    stxr w5, w4, [x3]
    cbnz w5, 3f                 // must succeed
    ldr w6, [x3]
    cmp w6, #47                 // 42+5
    b.eq 4f
3:  add x19, x19, #1
4:  // clrex then stxr must fail
    ldxr w4, [x3]
    clrex
    stxr w5, w4, [x3]
    cbz w5, 5f                  // failure expected => w5 != 0
    b 6f
5:  add x19, x19, #1
6:  // bitfield / rev
    movz x7, #0xcdef
    movk x7, #0x90ab, lsl #16
    movk x7, #0x5678, lsl #32
    movk x7, #0x1234, lsl #48
    rev x8, x7
    movz x9, #0x3412
    movk x9, #0x7856, lsl #16
    movk x9, #0xab90, lsl #32
    movk x9, #0xefcd, lsl #48
    cmp x8, x9
    b.eq 7f
    add x19, x19, #1
7:  // report
    cbnz x19, fail
    mov x0, #1
    adr x1, ok
    mov x2, #5
    mov x8, #64
    svc #0
    mov x0, #0
    b out
fail:
    mov x0, #1
    adr x1, bad
    mov x2, #5
    mov x8, #64
    svc #0
    mov x0, x19
out:
    mov x8, #94
    svc #0

    .balign 8
ok:  .ascii "PASS\n"
bad: .ascii "FAIL\n"
