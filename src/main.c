/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* arm64chroot: run an AArch64 Linux program from a rootfs directory under a
 * pure-interpreter user-space emulator.
 *
 *   arm64chroot [options] <rootfs> <program> [args...]
 *
 * Options:
 *   -strace          log syscalls to stderr
 *   -d               per-instruction trace (very verbose)
 *   -E VAR=VAL       set an environment variable for the guest (repeatable)
 *   -0 ARG0          set argv[0] for the guest program
 *   -fake-id [ID]    fake identity (fakeroot-style); ID = uid | uid:gid,
 *                    default 0:0 (root)
 */
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "machine.h"
#include "thread.h"

extern int g_predecode;   /* predecode.c: decoded-instruction cache enable */

struct Machine g_machine;

extern char **environ;

static void usage(void) {
    fprintf(stderr,
            "usage: arm64chroot [-strace] [-d] [-nopd] [-E VAR=VAL]... [-0 argv0] "
            "[-fake-id [uid[:gid]]] <rootfs> <program> [args...]\n");
    exit(2);
}

/* Recognize a fake-id spec: "N" or "N:N" (all digits). */
static int is_id_spec(const char *s) {
    if (!s || !*s) return 0;
    int seen_colon = 0, digits = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ':') {
            if (seen_colon || !digits) return 0;
            seen_colon = 1; digits = 0;
        } else if (isdigit((unsigned char)*p)) {
            digits = 1;
        } else return 0;
    }
    return digits;
}

/* Parse "N" (uid, gid defaults to uid) or "N:M" into *uid,*gid. */
static void parse_id_spec(const char *s, u32 *uid, u32 *gid) {
    char *end;
    unsigned long u = strtoul(s, &end, 10);
    *uid = (u32)u;
    if (*end == ':') *gid = (u32)strtoul(end + 1, NULL, 10);
    else *gid = (u32)u;   /* single value applies to both */
}

int main(int argc, char **argv) {
    struct Machine *m = &g_machine;
    const char *argv0 = NULL;
    char **extra_env = NULL;
    int n_extra = 0;

    u32 fake_uid = 0, fake_gid = 0;

    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "-strace")) m->strace = 1;
        else if (!strcmp(argv[i], "-d")) { g_trace = 1; g_debug_hooks = 1; }
        else if (!strcmp(argv[i], "-nopd")) g_predecode = 0;   /* decode cache off */
        else if (!strcmp(argv[i], "-0") && i + 1 < argc) argv0 = argv[++i];
        else if (!strcmp(argv[i], "-E") && i + 1 < argc) {
            extra_env = realloc(extra_env, sizeof(char *) * (size_t)(n_extra + 1));
            extra_env[n_extra++] = argv[++i];
        } else if (!strcmp(argv[i], "-fake-id")) {   /* optional space-separated ID */
            m->fake_id = 1;
            if (i + 1 < argc && is_id_spec(argv[i + 1]))
                parse_id_spec(argv[++i], &fake_uid, &fake_gid);
        } else if (!strncmp(argv[i], "-fake-id=", 9)) {   /* attached form */
            m->fake_id = 1;
            if (is_id_spec(argv[i] + 9)) parse_id_spec(argv[i] + 9, &fake_uid, &fake_gid);
            else usage();
        } else if (!strcmp(argv[i], "--")) { i++; break; }
        else usage();
    }
    if (argc - i < 2) usage();

    /* Capture the real invoking identity (stat remap source) and, in fake mode,
     * seed the credential set to the configured identity. */
    m->host_uid = getuid();
    m->host_gid = getgid();
    if (m->fake_id) {
        m->fake_uid = fake_uid;
        m->fake_gid = fake_gid;
        m->cred.ruid = m->cred.euid = m->cred.suid = m->cred.fsuid = fake_uid;
        m->cred.rgid = m->cred.egid = m->cred.sgid = m->cred.fsgid = fake_gid;
        m->cred.ngroups = 0;
    }

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
