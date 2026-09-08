/* execve(2)'s argument-limit accounting (src/elf.c), self-checking.
 *
 * qemu-user is not an oracle here. A guest execve under it becomes a host
 * execve whose argv carries qemu's own prefix and whose budget comes from the
 * host process's own RLIMIT_STACK, so the boundary it reports is not the one
 * the guest asked about. The emulator builds the new image's stack itself, so
 * the boundary is entirely its own to enforce -- and every number below was
 * measured against a real kernel first (fork, setrlimit, execve /bin/true with
 * a binary-searched argument count).
 *
 * What a kernel measures (bprm_stack_limits): a quarter of RLIMIT_STACK,
 * capped at three quarters of the 8 MB reference stack and floored at ARG_MAX,
 * and then the *pointer table* -- (max(argc,1) + envc) slots of 8 bytes -- is
 * taken out of that budget before the strings are. argv strings, envp strings
 * and the execfn all share what is left; anything past it is E2BIG.
 *
 * The cases are sized with tens of kilobytes of margin on either side of the
 * boundary, so nothing here depends on the exact length of the path the
 * emulator resolves for the execfn. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define MB            (1024UL * 1024UL)
#define ARG_MAX_BYTES 131072UL           /* uapi ARG_MAX: a fixed constant */
#define STK_LIM       (8UL * MB)         /* the kernel's reference stack */

#define EXEC_OK 42                       /* what the new image exits with */

static unsigned long budget(unsigned long stk) {
    unsigned long limit = STK_LIM / 4 * 3;

    if (stk / 4 < limit) limit = stk / 4;
    if (limit < ARG_MAX_BYTES) limit = ARG_MAX_BYTES;
    return limit;
}

static char **vec(int n, int len, const char *first, const char *second) {
    char **v = calloc((size_t)n + 3, sizeof *v);
    char *s = malloc((size_t)len + 1);

    if (!v || !s) return NULL;
    memset(s, 'a', (size_t)len);
    s[len] = '\0';
    int k = 0;
    if (first) v[k++] = (char *)first;
    if (second) v[k++] = (char *)second;
    for (int i = 0; i < n; i++) v[k++] = s;
    v[k] = NULL;
    return v;
}

/* One execve, in a child so a success does not end the test: RLIMIT_STACK is
 * @stk, argv is self + a marker + @nargs strings of @arglen bytes, envp is
 * @nenv strings of @envlen. "ok" when the new image ran. */
static const char *attempt(const char *self, unsigned long stk,
                           int nargs, int arglen, int nenv, int envlen) {
    static char out[32];
    pid_t p = fork();

    if (p < 0) return "forkfail";
    if (p == 0) {
        struct rlimit rl = { stk, stk };
        char **av, **ev;
        if (setrlimit(RLIMIT_STACK, &rl) != 0) _exit(120);
        av = vec(nargs, arglen, self, "x");
        ev = vec(nenv, envlen, NULL, NULL);
        if (!av || !ev) _exit(121);
        execve(self, av, ev);
        _exit(errno == E2BIG ? 122 : 123);
    }
    int st = 0;
    if (waitpid(p, &st, 0) < 0 || !WIFEXITED(st)) return "crash";
    switch (WEXITSTATUS(st)) {
    case EXEC_OK: return "ok";
    case 122:     return "e2big";
    case 120:     return "rlimfail";
    case 121:     return "nomem";
    default:      snprintf(out, sizeof out, "exit%d", WEXITSTATUS(st)); return out;
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "x") == 0) return EXEC_OK;

    const char *self = argv[0];
    unsigned long l8 = budget(8 * MB);            /* 2 MB: a quarter of 8 MB */

    /* Comfortably inside the budget. */
    printf("fits=%s\n", attempt(self, 8 * MB, 1000, 100, 0, 0));

    /* The pointer table is what puts this one over: 8180 strings of 252 bytes
     * are ~35 KB short of the budget, and their 8182 pointers are ~65 KB, so
     * the strings fit and the argument list does not. Counting only the string
     * bytes admitted it -- and the image was already built by the time the
     * stack it had to fit in ran out. Split across argv and envp, since the
     * table a kernel charges for covers both. */
    printf("strings_only=%d\n", 8180UL * 252UL < l8);
    printf("ptrtab=%s\n", attempt(self, 8 * MB, 4090, 251, 4090, 251));

    /* ...and the strings still count on their own. */
    printf("strings=%s\n", attempt(self, 8 * MB, 4090, 519, 0, 0));

    /* ARG_MAX is a floor under the budget however small the stack limit is: a
     * quarter of 256 KB is 64 KB, but 109 KB of arguments still go through. */
    printf("floor=%s\n", attempt(self, 256 * 1024, 1000, 100, 0, 0));

    /* ...and three quarters of the reference stack is the ceiling over it,
     * however large the limit is: a quarter of 64 MB is 16 MB, but the budget
     * is 6 MB, so 5.2 MB of arguments go through and 7.3 MB do not. */
    printf("cap_ok=%s\n", attempt(self, 64 * MB, 40, 129999, 0, 0));
    printf("cap_over=%s\n", attempt(self, 64 * MB, 56, 129999, 0, 0));

    printf("done\n");
    return 0;
}
