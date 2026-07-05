// Exercise the LSE atomic ops and check results. exit code = #errors.
    .globl _start
_start:
    mov x19, #0
    sub sp, sp, #32
    mov x20, sp
    // LDADD: mem=10, add 5 -> old=10, mem=15
    mov w0, #10
    str w0, [x20]
    mov w1, #5
    ldadd w1, w2, [x20]     // w2 = old = 10
    cmp w2, #10
    b.eq 1f
    add x19, x19, #1
1:  ldr w3, [x20]
    cmp w3, #15
    b.eq 2f
    add x19, x19, #1
2:  // SWP: swap 99 in, get 15 out
    mov w1, #99
    swp w1, w4, [x20]
    cmp w4, #15
    b.eq 3f
    add x19, x19, #1
3:  ldr w3, [x20]
    cmp w3, #99
    b.eq 4f
    add x19, x19, #1
4:  // LDSET: set bits 0xf0 -> 99|0xf0
    mov w0, #99
    str w0, [x20]
    mov w1, #0xf0
    ldset w1, w2, [x20]
    ldr w3, [x20]
    mov w5, #99
    orr w5, w5, #0xf0
    cmp w3, w5
    b.eq 5f
    add x19, x19, #1
5:  // LDCLR: clear low nibble
    mov w1, #0x0f
    ldclr w1, w2, [x20]
    ldr w3, [x20]
    tst w3, #0x0f
    b.eq 6f                 // low nibble should be clear
    add x19, x19, #1
6:  // LDUMAX: max(current, 0x1000)
    mov w0, #1
    str w0, [x20]
    mov w1, #0x1000
    ldumax w1, w2, [x20]
    ldr w3, [x20]
    cmp w3, w1
    b.eq 7f
    add x19, x19, #1
7:  // CAS success + fail
    mov w0, #42
    str w0, [x20]
    mov w1, #42            // expected
    mov w2, #77            // new
    cas w1, w2, [x20]      // should swap; w1=old=42
    cmp w1, #42
    b.eq 8f
    add x19, x19, #1
8:  ldr w3, [x20]
    cmp w3, #77
    b.eq 9f
    add x19, x19, #1
9:  mov w1, #1            // wrong expected
    mov w2, #123
    cas w1, w2, [x20]     // should NOT swap; w1=old=77
    cmp w1, #77
    b.eq 10f
    add x19, x19, #1
10: ldr w3, [x20]
    cmp w3, #77           // unchanged
    b.eq 11f
    add x19, x19, #1
11: // LDADD 64-bit (build 0x100000000 via movk)
    movz x0, #1, lsl #32
    str x0, [x20]
    mov x1, #7
    ldadd x1, x2, [x20]
    ldr x3, [x20]
    movz x4, #1, lsl #32
    add x4, x4, #7
    cmp x3, x4
    b.eq done
    add x19, x19, #1
done:
    mov x0, x19
    mov x8, #94
    svc #0

