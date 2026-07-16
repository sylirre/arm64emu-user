/* Self-checking software-breakpoint test (emulator-only): the tracer POKETEXTs a
 * BRK over a known instruction in the tracee, expects a SIGTRAP ptrace-stop with
 * pc at the breakpoint and si_code TRAP_BRKPT, restores the original instruction,
 * and lets the tracee run to a clean exit. Exercises the read-only code-page
 * force-write, the JIT self-modifying-code invalidation, and the routing of a
 * synchronous BRK fault to the tracer. Runs under the interpreter and --jit
 * (qemu-user's ptrace emulation is too incomplete to be a differential oracle). */
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#ifndef TRAP_BRKPT
#define TRAP_BRKPT 1                   /* si_code for a breakpoint SIGTRAP */
#endif

#define BRK_INSN 0xD4200000UL          /* BRK #0 */
#define CHILD_OK 7

extern char bp_label[];

/* A leaf function with a global label at a single, re-executable instruction.
 * The volatile asm output is opaque to the compiler, so `v == 42` in the caller
 * is a real runtime check (not constant-folded) — replacing the instruction with
 * a BRK and restoring it must actually take effect for the child to exit OK. */
__attribute__((noinline)) static int compute(void) {
    int r;
    __asm__ volatile(
        ".globl bp_label\n"
        "bp_label:\n\t"
        "mov %w0, #42\n"
        : "=r"(r) : : );
    return r;
}

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(void) {
    unsigned long addr = (unsigned long)(uintptr_t)bp_label;

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);           /* park until the tracer sets the bp */
        int v = compute();                 /* runs the (restored) bp instruction */
        _exit(v == 42 ? CHILD_OK : 8);
    }

    int status;
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid(initial)");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return fail("initial stop not SIGSTOP");

    /* Read the 8-byte word at the label and splice a BRK over its low (bp_label)
     * instruction, preserving the following one. */
    errno = 0;
    long orig = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);
    if (orig == -1 && errno) return fail("PEEKTEXT code");
    long patched =
        (long)(((unsigned long)orig & 0xffffffff00000000UL) | BRK_INSN);
    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)patched) != 0)
        return fail("POKETEXT breakpoint (code page)");

    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) return fail("CONT to breakpoint");
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid(breakpoint)");
    if (WIFEXITED(status)) return fail("ran past breakpoint (no trap)");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        return fail("breakpoint stop not SIGTRAP");

    struct user_regs_struct regs;
    struct iovec iov = { &regs, sizeof regs };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0)
        return fail("GETREGSET at breakpoint");
    if (regs.pc != addr) return fail("breakpoint pc != breakpoint address");

    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) != 0) return fail("GETSIGINFO");
    if (si.si_code != TRAP_BRKPT) return fail("si_code != TRAP_BRKPT");

    /* Restore the original instruction and run the tracee to completion. */
    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)orig) != 0)
        return fail("POKETEXT restore");
    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) return fail("CONT to exit");
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid(exit)");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != CHILD_OK)
        return fail("wrong child exit after breakpoint");

    printf("OK\n");
    return 0;
}
