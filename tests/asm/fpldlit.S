// LDR (literal), SIMD&FP variant: LDR St/Dt/Qt, <label>. This is what LuaJIT
// emits to load FP constants from a per-run literal pool; the emulator used to
// UNDEF (SIGILL) on it. Each size is checked against the same bytes loaded via
// the integer literal load. exit code = number of failed checks.
    .globl _start
_start:
    mov x19, #0

    // LDR St (opc=00, V=1): 4-byte load into S0
    ldr s0, lit_s
    fmov w0, s0
    ldr w1, lit_s
    cmp w0, w1
    b.eq 1f
    add x19, x19, #1
1:  // LDR Dt (opc=01, V=1): 8-byte load into D1 — the exact form that faulted
    ldr d1, lit_d
    fmov x0, d1
    ldr x1, lit_d
    cmp x0, x1
    b.eq 2f
    add x19, x19, #1
2:  // LDR Qt (opc=10, V=1): 16-byte load into Q2
    ldr q2, lit_q
    umov x0, v2.d[0]
    umov x2, v2.d[1]
    ldr x1, lit_q
    ldr x3, lit_q+8
    cmp x0, x1
    b.ne 3f
    cmp x2, x3
    b.eq 4f
3:  add x19, x19, #1
4:  mov x0, x19
    mov x8, #94                 // exit
    svc #0

    .balign 16
lit_s: .word 0x40490fdb                 // ~3.14159f
lit_d: .quad 0x400921fb54442d18         // pi (double)
lit_q: .quad 0x0011223344556677
       .quad 0x8899aabbccddeeff
