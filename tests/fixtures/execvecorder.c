/* The order execve(2) reads argv and envp in (src/sys_proc.c), self-checking.
 *
 * A kernel reads the two vectors in a fixed sequence (do_execveat_common):
 *
 *   count(argv), count(envp)   walk each pointer array to its NULL: EFAULT
 *   bprm_stack_limits          the pointer table against the budget: E2BIG
 *   copy_strings(envp)         envp's strings, LAST to first, then
 *   copy_strings(argv)         argv's, last to first -- each one EFAULT when
 *                              it cannot be read, E2BIG when it is longer than
 *                              MAX_ARG_STRLEN or overruns the one budget the
 *                              filename, envp and argv share
 *
 * so when more than one thing is wrong with a list, which of them the caller
 * hears about is decided by that order. This emulator imported argv whole and
 * then envp whole, each string in first-to-last order and each vector against
 * a budget of its own -- the E2BIG and EFAULT rows below came back the other
 * way round, and the staging could hold two budgets' worth before the refusal.
 *
 * qemu-user is not the oracle here (it copies the vectors in its own execve
 * emulation). Every row is what a real kernel answers, measured with this same
 * program built for the host. The image is a memfd that is no executable
 * format at all, so a list that passes comes back ENOEXEC and nothing runs. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* A 1 MB stack limit makes the budget a quarter of it: 256 KB. */
#define STK         (1UL << 20)
#define STRLEN_MAX  131072           /* MAX_ARG_STRLEN, NUL included */
#define MANY        40000            /* 320 KB of pointer table: over */

static const char *ename(int e) {
    switch (e) {
    case ENOEXEC: return "enoexec";
    case E2BIG:   return "e2big";
    case EFAULT:  return "efault";
    default:      return "other";
    }
}

static int img = -1;
static char *bad;                    /* a page nobody can read */
static char *toolong;                /* no NUL within MAX_ARG_STRLEN */
static char *fat;                    /* 100 KB: three of them overrun */

/* One execveat of the image, in a child so a success could not end the test:
 * what it was refused with. */
static const char *attempt(char **av, char **ev) {
    int pf[2];
    if (pipe(pf)) return "pipefail";
    pid_t p = fork();
    if (p == 0) {
        struct rlimit rl = { STK, STK };
        close(pf[0]);
        setrlimit(RLIMIT_STACK, &rl);
        syscall(SYS_execveat, img, "", av, ev, AT_EMPTY_PATH);
        int e = errno;
        ssize_t w = write(pf[1], &e, sizeof e);
        (void)w;
        _exit(99);
    }
    close(pf[1]);
    int e = 0;
    ssize_t got = read(pf[0], &e, sizeof e);
    close(pf[0]);
    int st = 0;
    waitpid(p, &st, 0);
    if (got != (ssize_t)sizeof e) return WIFSIGNALED(st) ? "signal" : "ran";
    return ename(e);
}

/* A NULL-terminated list: `n` copies of `s` after the given head entries. */
static char **list(int n, char *s, char *h0, char *h1, char *h2) {
    char **v = calloc((size_t)n + 4, sizeof *v);
    int k = 0;
    if (!v) exit(98);
    if (h0) v[k++] = h0;
    if (h1) v[k++] = h1;
    if (h2) v[k++] = h2;
    for (int i = 0; i < n; i++) v[k++] = s;
    v[k] = NULL;
    return v;
}

int main(void) {
    img = (int)syscall(SYS_memfd_create, "img", 0u);
    if (img < 0 || write(img, "not an elf\n", 11) != 11) {
        printf("SKIP: no memfd to carry an unloadable image\n");
        return 0;
    }
    bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    toolong = malloc(STRLEN_MAX + 1);
    fat = malloc(100000 + 1);
    if (bad == MAP_FAILED || !toolong || !fat) return 1;
    memset(toolong, 'l', STRLEN_MAX);
    toolong[STRLEN_MAX] = '\0';
    memset(fat, 'f', 100000);
    fat[100000] = '\0';

    /* A pointer array that runs into an unreadable page with no NULL: MANY
     * entries fill it right up to the guard. */
    size_t arr_len = (size_t)MANY * sizeof(char *);
    size_t arr_map = (arr_len + 4095) / 4096 * 4096 + 4096;
    char *arr_base = mmap(NULL, arr_map, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arr_base == MAP_FAILED) return 1;
    mprotect(arr_base + arr_map - 4096, 4096, PROT_NONE);
    char **runon = (char **)(arr_base + arr_map - 4096 - arr_len);
    for (int i = 0; i < MANY; i++) runon[i] = (char *)"a";

    char *empty[] = { NULL };
    char *one[] = { (char *)"x", NULL };

    /* Control: a list that fits reaches the image, which is no format. */
    printf("fits=%s\n", attempt(one, empty));
    /* envp is copied before argv: its overrun is the answer, not the
     * unreadable argv string the copy never reached. */
    printf("argv_bad_env_big=%s\n",
           attempt(list(0, NULL, "x", bad, NULL), list(3, fat, NULL, NULL, NULL)));
    /* ...and an unreadable envp string beats an argv that overruns. */
    printf("env_bad_argv_big=%s\n",
           attempt(list(3, fat, "x", NULL, NULL), list(0, NULL, "e", bad, NULL)));
    /* Last to first within a vector: the unreadable argv[2] is met before
     * the over-long argv[1], and the over-long argv[2] before the unreadable
     * argv[1]. */
    printf("argv_last_bad=%s\n",
           attempt(list(0, NULL, "x", toolong, bad), empty));
    printf("argv_last_long=%s\n",
           attempt(list(0, NULL, "x", bad, toolong), empty));
    /* The same within envp, and envp's over-long string ahead of argv's
     * unreadable one. */
    printf("env_last_bad=%s\n",
           attempt(one, list(0, NULL, toolong, bad, NULL)));
    printf("env_long_argv_bad=%s\n",
           attempt(list(0, NULL, "x", bad, NULL), list(0, NULL, toolong, NULL, NULL)));
    /* Both arrays are walked to their NULL before any string is read: an
     * unreadable envp ARRAY is EFAULT even when argv overruns the budget... */
    printf("env_array_bad_argv_big=%s\n",
           attempt(list(3, fat, "x", NULL, NULL), (char **)bad));
    /* ...and an argv array running into an unreadable page is EFAULT even
     * though its entries alone are far more than the budget holds. */
    printf("argv_array_runon=%s\n", attempt(runon, empty));
    /* The pointer table is measured before any string is copied: too many
     * pointers is E2BIG even when one of the strings is unreadable. */
    printf("ptrtab_over_str_bad=%s\n",
           attempt(list(MANY, (char *)"a", "x", bad, NULL), empty));
    /* One budget for both: each vector fits on its own, the pair does not. */
    printf("pair_over=%s\n",
           attempt(list(2, fat, "x", NULL, NULL), list(2, fat, NULL, NULL, NULL)));
    /* A string exactly MAX_ARG_STRLEN long, NUL included, is not too long. */
    toolong[STRLEN_MAX - 1] = '\0';
    printf("strlen_max=%s\n", attempt(list(0, NULL, "x", toolong, NULL), empty));
    printf("done\n");
    return 0;
}
