// TBI0 regression: an EL0 data access through a top-byte-tagged pointer must
// behave as if the tag were absent (TCR_EL1.TBI0=1 on Linux). Bionic's scudo
// allocator relies on this. Store a sentinel through a tagged pointer, then read
// it back through both the clean and the tagged pointer; all must agree.
// write(1,"OK\n",3)+exit(0) on success, "BAD\n"+exit(1) on mismatch. Diffed
// against qemu-aarch64, which models TBI. On an emulator without TBI the store
// faults (guest fatal signal 11) instead, diverging from qemu.
    .globl _start
_start:
    sub  x0, sp, #16                 // clean pointer to a mapped stack slot
    orr  x1, x0, #0xff00000000000000 // tagged pointer: top byte 0xff, low 56 bits equal

    movz x2, #0xbeef                 // sentinel = 0x12345678deadbeef
    movk x2, #0xdead, lsl #16
    movk x2, #0x5678, lsl #32
    movk x2, #0x1234, lsl #48

    str  x2, [x1]                    // store THROUGH the tagged pointer
    ldr  x3, [x0]                    // read back via the clean pointer
    ldr  x4, [x1]                    // read back via the tagged pointer

    cmp  x3, x2
    b.ne fail
    cmp  x4, x2
    b.ne fail

    mov  x0, #1                      // success: write(1, "OK\n", 3)
    adr  x1, okmsg
    mov  x2, #3
    mov  x8, #64
    svc  #0
    mov  x0, #0                      // exit_group(0)
    mov  x8, #94
    svc  #0

fail:
    mov  x0, #1                      // write(1, "BAD\n", 4)
    adr  x1, badmsg
    mov  x2, #4
    mov  x8, #64
    svc  #0
    mov  x0, #1                      // exit_group(1)
    mov  x8, #94
    svc  #0

okmsg:
    .ascii "OK\n"
badmsg:
    .ascii "BAD\n"
