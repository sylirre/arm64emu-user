// write(1, msg, len); exit_group(42)
    .globl _start
_start:
    mov x0, #1
    adr x1, msg
    mov x2, #14
    mov x8, #64        // write
    svc #0
    mov x0, #42
    mov x8, #94        // exit_group
    svc #0
msg:
    .ascii "hello, world!\n"
