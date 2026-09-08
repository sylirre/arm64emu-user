/* The stack a new image gets is its RLIMIT_STACK (src/elf.c), self-checking.
 *
 * A kernel's stack VMA grows on demand and can never pass that limit
 * (acct_stack_growth), so the limit is the size of the stack the program ends
 * up with: lowering it before an exec is how a shell bounds what the program
 * may recurse to, and raising it is how a deeply recursive one is given room.
 * This emulator lays the stack out in one piece at exec time, so it has to
 * read the same limit to arrive at the same answer -- it used to map a fixed
 * 8 MB and ignore it in both directions.
 *
 * qemu-user cannot be the oracle: it sizes the guest stack from its own -s
 * option (8 MB by default) and pays no attention to the guest's RLIMIT_STACK
 * either. Every band below was measured against a real kernel, with this same
 * program built for the host: 14 frames at 64 KB, 252 at 1 MB, 2030 at 8 MB
 * and 16255 at 64 MB, against 15 / 253 / 2031 / 16256 here -- one frame apart,
 * which is the argv block differing in length.
 *
 * The bands are wide because a frame is "about 4 KB": what the compiler adds
 * to the padding array is its own business, and the emulator and the kernel
 * need only agree on the size of the stack, not on how it is spent. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define MB (1024UL * 1024UL)

static int outfd;
static unsigned long depth;

/* ~4 KB of stack per frame, touched so the page is really used. The depth is
 * rewritten in place after every frame, so what the parent reads back once the
 * child has died is how far it got. Reading the padding again after the call
 * keeps the frame live across it, which is what stops -O2 turning the whole
 * thing into a loop that never overflows anything. */
static __attribute__((noinline)) void recurse(void) {
    volatile char pad[4096];
    pad[0] = 1;
    pad[4095] = 1;
    depth++;
    if (pwrite(outfd, (void *)&depth, sizeof depth, 0) != sizeof depth) return;
    if (depth > 40000) return;                  /* 160 MB: nothing will kill us */
    recurse();
    if (pad[0] != 1 || pad[4095] != 1) depth = 0;
}

/* RLIMIT_STACK, then exec: the shell's `ulimit -s N; ./prog`. Returns the
 * depth the new image reached before it died, or 0 if it did not die. */
static unsigned long probe(const char *self, unsigned long stk) {
    unsigned long zero = 0, got = 0;
    char fdbuf[16];
    int fd = (int)syscall(SYS_memfd_create, "depth", 0u);

    if (fd < 0) return 0;
    if (pwrite(fd, &zero, sizeof zero, 0) != (ssize_t)sizeof zero) return 0;
    snprintf(fdbuf, sizeof fdbuf, "%d", fd);
    pid_t p = fork();
    if (p == 0) {
        struct rlimit rl = { stk, stk };
        char *av[] = { (char *)self, (char *)"child", fdbuf, NULL };
        char *ev[] = { NULL };
        if (setrlimit(RLIMIT_STACK, &rl) != 0) _exit(126);
        execve(self, av, ev);
        _exit(127);
    }
    int st = 0;
    if (waitpid(p, &st, 0) < 0) return 0;
    if (pread(fd, &got, sizeof got, 0) != (ssize_t)sizeof got) got = 0;
    close(fd);
    return WIFSIGNALED(st) ? got : 0;    /* it has to die of the overflow */
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "child") == 0) {
        outfd = atoi(argv[2]);
        recurse();
        return 0;
    }
    if ((int)syscall(SYS_memfd_create, "probe", 0u) < 0) {
        printf("SKIP: no memfd to carry the depth across the exec\n");
        return 0;
    }

    unsigned long tiny = probe(argv[0], 64 * 1024);
    unsigned long small = probe(argv[0], 1 * MB);
    unsigned long deflt = probe(argv[0], 8 * MB);
    unsigned long large = probe(argv[0], 32 * MB);

    /* Each band is the limit divided by a frame of about 4 KB, loosely. */
    printf("tiny=%d\n", tiny > 0 && tiny < 32);
    printf("small=%d\n", small > 150 && small < 400);
    printf("default=%d\n", deflt > 1500 && deflt < 2500);
    printf("large=%d\n", large > 6000 && large < 9500);
    /* ...and, whatever the frame really costs, more limit is more stack. */
    printf("scales=%d\n", tiny < small && small < deflt && deflt < large);
    printf("done\n");
    return 0;
}
