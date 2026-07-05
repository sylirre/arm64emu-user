/* arm64chroot: run an AArch64 Linux program from a rootfs directory under a
 * pure-interpreter user-space emulator.
 *
 *   arm64chroot [options] <rootfs> <program> [args...]
 *
 * Options:
 *   -strace      log syscalls to stderr
 *   -d           per-instruction trace (very verbose)
 *   -E VAR=VAL   set an environment variable for the guest (repeatable)
 *   -0 ARG0      set argv[0] for the guest program
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "machine.h"
#include "thread.h"

struct Machine g_machine;

extern char **environ;

static void usage(void) {
    fprintf(stderr,
            "usage: arm64chroot [-strace] [-d] [-E VAR=VAL]... [-0 argv0] "
            "<rootfs> <program> [args...]\n");
    exit(2);
}

int main(int argc, char **argv) {
    struct Machine *m = &g_machine;
    const char *argv0 = NULL;
    char **extra_env = NULL;
    int n_extra = 0;

    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "-strace")) m->strace = 1;
        else if (!strcmp(argv[i], "-d")) { g_trace = 1; g_debug_hooks = 1; }
        else if (!strcmp(argv[i], "-0") && i + 1 < argc) argv0 = argv[++i];
        else if (!strcmp(argv[i], "-E") && i + 1 < argc) {
            extra_env = realloc(extra_env, sizeof(char *) * (size_t)(n_extra + 1));
            extra_env[n_extra++] = argv[++i];
        } else if (!strcmp(argv[i], "--")) { i++; break; }
        else usage();
    }
    if (argc - i < 2) usage();

    const char *rootfs = argv[i];
    const char *prog = argv[i + 1];
    char **gargv_in = &argv[i + 1];

    if (!realpath(rootfs, m->rootfs)) {
        fprintf(stderr, "arm64chroot: rootfs '%s': not found\n", rootfs);
        return 126;
    }
    if (!strcmp(m->rootfs, "/")) m->rootfs[0] = 0;   /* rootfs "/": no prefix */

    /* Guest cwd: the host cwd when it lies inside the rootfs, else "/". */
    strcpy(m->cwd, "/");
    char hcwd[PATH_MAX];
    if (getcwd(hcwd, sizeof hcwd)) {
        size_t rl = strlen(m->rootfs);
        if (!strncmp(hcwd, m->rootfs, rl) && (hcwd[rl] == '/' || hcwd[rl] == 0))
            strcpy(m->cwd, hcwd[rl] ? hcwd + rl : "/");
    }

    /* Guest argv: program args as given; argv[0] overridable. */
    int gargc = 0;
    while (gargv_in[gargc]) gargc++;
    char **gargv = malloc(sizeof(char *) * (size_t)(gargc + 1));
    for (int k = 0; k < gargc; k++) gargv[k] = gargv_in[k];
    gargv[gargc] = NULL;
    if (argv0) gargv[0] = (char *)argv0;

    /* Guest environ: host environment plus -E overrides. */
    int henvc = 0;
    while (environ[henvc]) henvc++;
    char **genv = malloc(sizeof(char *) * (size_t)(henvc + n_extra + 1));
    int ge = 0;
    for (int k = 0; k < henvc; k++) genv[ge++] = environ[k];
    for (int k = 0; k < n_extra; k++) genv[ge++] = extra_env[k];
    genv[ge] = NULL;

    as_init(&m->as);
    m->cpu.m = m;
    g_tls.tid = getpid();     /* main thread tid == pid */
    m->next_tid = getpid();

    /* Route the initial exec through do_execve so shebang scripts and PATH-less
     * relative programs behave exactly as an in-guest execve would. */
    if (argv0) gargv[0] = (char *)argv0;
    u64 r = do_execve(&m->cpu, prog, gargv, genv);
    if ((s64)r < 0) {
        fprintf(stderr, "arm64chroot: cannot execute %s: %s\n", prog,
                strerror((int)-(s64)r));
        return 126;
    }

    return emu_loop(&m->cpu);
}
