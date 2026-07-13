/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* arm64chroot: run an AArch64 Linux program from a rootfs directory under a
 * pure-interpreter user-space emulator.
 *
 *   arm64chroot [options] <rootfs> <program> [args...]
 *
 * Options (run `arm64chroot --help` for the full reference incl. env vars):
 *   -h, --help              show detailed help and exit
 *       --strace            log syscalls to stderr
 *   -d, --debug             per-instruction trace (very verbose; forces --jit off)
 *   -j, --jit               translate hot basic blocks to native code (AArch64/x86-64)
 *       --no-predecode      disable the decoded-instruction cache (diagnostic; slower)
 *   -l, --link2symlink      emulate hardlinks with tracked symlinks where the host
 *                           forbids link() (e.g. Android/SELinux -> EXDEV). Android only.
 *       --shared-proc       key the shared guest-PID registry by rootfs so ps/top see
 *                           guest processes across emulator invocations
 *   -b, --bind SRC:DST[:ro] expose host directory `src` at guest path `dst`
 *                           (repeatable); :ro makes it read-only. Host paths may not
 *                           contain ':'.
 *   -E, --env VAR=VAL       set an environment variable for the guest (repeatable)
 *   -0, --argv0 ARG0        set argv[0] for the guest program
 *   -u, --fake-id[=ID]      fake identity (fakeroot-style); ID = uid | uid:gid,
 *                           default 0:0 (root)
 */
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "machine.h"
#include "thread.h"
#include "jit.h"

extern int g_predecode;   /* predecode.c: decoded-instruction cache enable */

struct Machine g_machine;

extern char **environ;

/* Terse synopsis for argument errors: one line to stderr, exit 2. The full
 * reference lives in help() below, reachable via -h/--help. */
static void usage(void) {
    fprintf(stderr,
            "usage: arm64chroot [options] <rootfs> <program> [args...]\n"
            "try 'arm64chroot --help' for details\n");
    exit(2);
}

/* Full reference help: purpose, usage, arguments, every option, environment
 * variables, and examples. Printed to stdout on -h/--help, exit 0. */
static void help(void) {
    fputs(
"arm64chroot -- run an AArch64 (ARM64) Linux program from a rootfs directory\n"
"under a pure user-space emulator (interpreter by default, optional --jit), with\n"
"proot-style rootfs containment. No privileges, kernel modules, or dependencies\n"
"beyond libc are required.\n"
"\n"
"Usage:\n"
"  arm64chroot [options] <rootfs> <program> [args...]\n"
"\n"
"Arguments:\n"
"  <rootfs>    directory tree holding an AArch64 userland (e.g. an Alpine or\n"
"              Debian arm64 root filesystem); '/' runs host-native aarch64\n"
"              binaries directly. Guest paths resolve inside the rootfs.\n"
"  <program>   guest program to execute (a path resolved inside the rootfs).\n"
"  args...     arguments passed on to the guest program.\n"
"\n"
"Options:\n"
"  -h, --help              show this help and exit\n"
"      --strace            log guest syscalls to stderr\n"
"  -d, --debug             per-instruction trace (very verbose; forces --jit off)\n"
"  -j, --jit               translate hot basic blocks to native code (AArch64 and\n"
"                          x86-64 hosts; falls back to the interpreter elsewhere)\n"
"      --no-predecode      disable the decoded-instruction cache (diagnostic;\n"
"                          slower)\n"
"  -l, --link2symlink      emulate hardlinks with tracked symlinks where the host\n"
"                          forbids link() (Android/SELinux -> EXDEV)\n"
"      --shared-proc       key the shared guest-PID registry by rootfs so that\n"
"                          ps/top see guest processes across emulator invocations\n"
"  -b, --bind SRC:DST[:ro] expose host directory SRC at guest path DST\n"
"                          (repeatable); append :ro for a read-only mount. Host\n"
"                          paths may not contain ':'.\n"
"  -E, --env VAR=VAL       set an environment variable for the guest (repeatable)\n"
"  -0, --argv0 ARG0        override argv[0] for the guest program\n"
"  -u, --fake-id[=ID]      present a fake identity (fakeroot-style); ID = uid or\n"
"                          uid:gid, default 0:0 (root)\n"
"      --                  stop option parsing\n"
"\n"
"Environment variables:\n"
"  Tuning:\n"
"    A64CHROOT_JIT_MB     per-thread JIT code-cache size in MiB (default 32,\n"
"                         clamped to 1-128)\n"
"    XDG_RUNTIME_DIR      first writable of these holds the --shared-proc\n"
"    TMPDIR               registry when /dev/shm is not writable; PREFIX is\n"
"    PREFIX               tried as $PREFIX/tmp (Termux)\n"
"  Diagnostics / developer (see docs/jit.md):\n"
"    A64_JIT_STATS        rank instruction words still run via the exec_a64\n"
"                         helper; =/path dumps the ranking to a file at exit\n"
"    A64_JIT_DUMP=PREFIX  write each translated block into a sparse code-cache\n"
"                         image (PREFIX.<pid>.<tid>.code plus a .map)\n"
"    A64_JIT_PDMAX=N      force predecode ops with id > N through the helper\n"
"                         (bisects a codegen bug to one instruction class)\n"
"    A64_JIT_SLOWMEM      force every inline memory op down its slow helper branch\n"
"    A64_JIT_NOFUSE       disable instruction / D-TLB-probe fusion\n"
"    A64_JIT_NOFP16       disable FP16 native codegen (AArch64 backend)\n"
"    A64_JIT_NOVRA        disable the V-register cache\n"
"    A64_JIT_SSE=2        force SSE2-baseline capability answers (x86-64)\n"
"    A64_PROCSTAT_FORCE_SYNTH  force the synthetic /proc/stat fallback\n"
"    A64_NETLINK_FORCE_BLOCK   force the netlink fallback path\n"
"\n"
"Examples:\n"
"  arm64chroot ./rootfs /bin/sh\n"
"  arm64chroot --jit --fake-id ./rootfs /bin/bash -l\n"
"  arm64chroot -b \"$PWD:/work\" --bind /etc/ssl:/etc/ssl:ro ./rootfs /bin/sh\n",
        stdout);
    exit(0);
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

/* Lexically canonicalize an absolute guest path (collapse '.', '..', '//',
 * strip trailing '/') into out (>= PATH_MAX) — the form -bind mount points are
 * matched against in path.c. Returns 0, or -1 on overflow. */
static int canon_guest(const char *in, char *out) {
    strcpy(out, "/");
    for (const char *p = in; *p;) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != '/') e++;
        size_t cl = (size_t)(e - p);
        if (cl == 1 && p[0] == '.') { p = e; continue; }
        if (cl == 2 && p[0] == '.' && p[1] == '.') {   /* pop, clamped at "/" */
            char *s = strrchr(out, '/');
            if (s == out) out[1] = 0; else *s = 0;
            p = e; continue;
        }
        size_t ol = strlen(out);
        if (ol + (ol > 1) + cl + 1 > PATH_MAX) return -1;
        if (ol > 1) out[ol++] = '/';
        memcpy(out + ol, p, cl);
        out[ol + cl] = 0;
        p = e;
    }
    return 0;
}

/* Parse and register a --bind mount "src:dst[:ro]": host directory src (realpath'd)
 * is exposed at absolute guest mount point dst; an optional trailing ":ro" (or
 * the default ":rw") marks it read-only. Host paths may not contain ':'. Fatal
 * on any malformed spec. */
static void add_bind(struct Machine *m, const char *spec) {
    if (m->n_binds >= BIND_MAX) {
        fprintf(stderr, "arm64chroot: too many --bind mounts (max %d)\n", BIND_MAX);
        exit(2);
    }
    char buf[2 * PATH_MAX];
    if (strlen(spec) + 1 > sizeof buf) {
        fprintf(stderr, "arm64chroot: --bind '%s': too long\n", spec);
        exit(2);
    }
    strcpy(buf, spec);
    char *colon = strchr(buf, ':');   /* first ':' splits src | dst[:ro] */
    if (!colon || colon == buf) {
        fprintf(stderr, "arm64chroot: --bind '%s': expected src:dst[:ro]\n", spec);
        exit(2);
    }
    *colon = 0;
    const char *src = buf;
    char *dst = colon + 1;
    int ro = 0;
    size_t dl = strlen(dst);
    if (dl >= 3 && !strcmp(dst + dl - 3, ":ro")) { ro = 1; dst[dl - 3] = 0; }
    else if (dl >= 3 && !strcmp(dst + dl - 3, ":rw")) { dst[dl - 3] = 0; }
    if (dst[0] != '/') {
        fprintf(stderr, "arm64chroot: --bind '%s': dst must be absolute\n", spec);
        exit(2);
    }
    int k = m->n_binds;
    if (!realpath(src, m->binds[k].host)) {
        fprintf(stderr, "arm64chroot: --bind src '%s': not found\n", src);
        exit(126);
    }
    if (!strcmp(m->binds[k].host, "/")) {
        fprintf(stderr, "arm64chroot: --bind '%s': cannot bind host root\n", spec);
        exit(2);
    }
    if (canon_guest(dst, m->binds[k].guest) < 0) {
        fprintf(stderr, "arm64chroot: --bind '%s': dst too long\n", spec);
        exit(2);
    }
    if (!strcmp(m->binds[k].guest, "/")) {
        fprintf(stderr, "arm64chroot: --bind '%s': cannot bind over guest root\n", spec);
        exit(2);
    }
    m->binds[k].ro = ro;
    m->n_binds++;
}

/* Sandbox diagnosis: report an inherited seccomp filter (Seccomp: 2 in
 * /proc/self/status — the Android app sandbox is the common case). Under one,
 * a blocked host syscall raises SIGSYS instead of returning ENOSYS; the net
 * armed in main() converts those, and this one-liner answers the first
 * question in any "works on one device, dies on another" report. */
static void seccomp_notice(void) {
    FILE *f = fopen("/proc/self/status", "re");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "Seccomp:", 8)) {
            if (atoi(line + 8) == 2)
                fprintf(stderr, "arm64chroot: seccomp filter active on this "
                                "process; trapped host syscalls return "
                                "ENOSYS\n");
            break;
        }
    }
    fclose(f);
}

/* --- command-line option parsing helpers ------------------------------- */

/* Fatal: a flag that takes no value was given one ("--help=x"). */
static void opt_no_value(const char *opt) {
    fprintf(stderr, "arm64chroot: option '%s' takes no value\n", opt);
    exit(2);
}

/* Value for a long value-taking option: "--opt=VAL" (val, possibly "") if a '='
 * was present, else the next argv token (consumed via *pi). Fatal if none. */
static char *long_value(const char *opt, char *val, char **argv, int argc, int *pi) {
    if (val) return val;
    if (*pi + 1 < argc) return argv[++*pi];
    fprintf(stderr, "arm64chroot: option '%s' requires an argument\n", opt);
    exit(2);
}

/* Value for a short value-taking option: the attached rest-of-token "-oVAL"
 * (rest) when non-empty, else the next argv token (consumed via *pi). */
static char *short_value(const char *opt, char *rest, char **argv, int argc, int *pi) {
    if (*rest) return rest;
    if (*pi + 1 < argc) return argv[++*pi];
    fprintf(stderr, "arm64chroot: option '%s' requires an argument\n", opt);
    exit(2);
}

/* Append a guest -E/--env "VAR=VAL" entry. */
static void push_env(char ***env, int *n, char *v) {
    *env = realloc(*env, sizeof(char *) * (size_t)(*n + 1));
    (*env)[(*n)++] = v;
}

/* Apply -u/--fake-id: enable fake identity and parse its optional ID. `attached`
 * is the text glued to the flag ("--fake-id=ID" or "-uID"), NULL/"" when none;
 * absent, the next argv token is taken as the ID iff it looks like an id-spec
 * (the "-u 1000:1000" space-separated form). A bad attached spec is fatal. */
static void set_fake_id(struct Machine *m, const char *attached,
                        char **argv, int argc, int *pi, u32 *uid, u32 *gid) {
    m->fake_id = 1;
    if (attached && *attached) {
        if (!is_id_spec(attached)) usage();
        parse_id_spec(attached, uid, gid);
    } else if (*pi + 1 < argc && is_id_spec(argv[*pi + 1])) {
        parse_id_spec(argv[++*pi], uid, gid);
    }
}

// JNI entrypoint used by https://github.com/sylirre/ghostty-android-terminal
#ifdef ANDROID_JNI
int arm64chroot_main(int argc, char **argv)
#else
int main(int argc, char **argv) {
#endif
    struct Machine *m = &g_machine;
    const char *argv0 = NULL;
    char **extra_env = NULL;
    int n_extra = 0;

    u32 fake_uid = 0, fake_gid = 0;

    /* GNU-style options: single-letter short (-j), --word long. Value-taking
     * options accept "-b VAL"/"-bVAL" and "--bind VAL"/"--bind=VAL"; no-arg
     * shorts bundle ("-dl"). Parsing stops at the first non-option, at "--", or
     * at the <rootfs> argument, so guest args are never consumed as options. */
    int i = 1;
    for (; i < argc; i++) {
        char *arg = argv[i];
        if (arg[0] != '-' || arg[1] == '\0') break;   /* positional (or lone "-") */
        if (!strcmp(arg, "--")) { i++; break; }        /* explicit end of options */

        if (arg[1] == '-') {                           /* long option: --name[=val] */
            char *eq = strchr(arg, '='), *val = NULL;
            if (eq) { *eq = '\0'; val = eq + 1; }      /* argv is writable */
            const char *n = arg + 2;
            if      (!strcmp(n, "help"))         { if (val) opt_no_value(arg); help(); }
            else if (!strcmp(n, "strace"))       { if (val) opt_no_value(arg); m->strace = 1; }
            else if (!strcmp(n, "debug"))        { if (val) opt_no_value(arg); g_trace = 1; g_debug_hooks = 1; }
            else if (!strcmp(n, "jit"))          { if (val) opt_no_value(arg); g_jit = 1; }
            else if (!strcmp(n, "no-predecode")) { if (val) opt_no_value(arg); g_predecode = 0; }
            else if (!strcmp(n, "link2symlink")) { if (val) opt_no_value(arg); m->link2symlink = 1; }
            else if (!strcmp(n, "shared-proc"))  { if (val) opt_no_value(arg); m->shared_proc = 1; }
            else if (!strcmp(n, "bind"))   add_bind(m, long_value("--bind", val, argv, argc, &i));
            else if (!strcmp(n, "env"))    push_env(&extra_env, &n_extra, long_value("--env", val, argv, argc, &i));
            else if (!strcmp(n, "argv0"))  argv0 = long_value("--argv0", val, argv, argc, &i);
            else if (!strcmp(n, "fake-id")) set_fake_id(m, val, argv, argc, &i, &fake_uid, &fake_gid);
            else usage();
        } else {                                       /* short cluster: -abc */
            for (char *p = arg + 1; *p; ) {
                char c = *p++;
                if      (c == 'h') help();
                else if (c == 'd') { g_trace = 1; g_debug_hooks = 1; }
                else if (c == 'j') g_jit = 1;
                else if (c == 'l') m->link2symlink = 1;
                else if (c == 'b') { add_bind(m, short_value("--bind", p, argv, argc, &i)); break; }
                else if (c == 'E') { push_env(&extra_env, &n_extra, short_value("--env", p, argv, argc, &i)); break; }
                else if (c == '0') { argv0 = short_value("--argv0", p, argv, argc, &i); break; }
                else if (c == 'u') { set_fake_id(m, p, argv, argc, &i, &fake_uid, &fake_gid); break; }
                else usage();
            }
        }
    }
    if (argc - i < 2) usage();

    /* -jit yields to per-instruction debug facilities and to hosts without a
     * code generator; the interpreter is always the correct fallback. */
    if (g_jit && g_debug_hooks) {
        fprintf(stderr, "arm64chroot: --jit disabled by per-instruction "
                        "debug flags, using interpreter\n");
        g_jit = 0;
    }
    if (g_jit && !jit_backend_available()) {
        fprintf(stderr, "arm64chroot: --jit has no backend for this host, "
                        "using interpreter\n");
        g_jit = 0;
    }

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

    /* Arm the SIGSYS net (seccomp trap -> -ENOSYS) before any guest work:
     * the ELF loader below already forwards host syscalls. */
    sig_install_sigsys_net();
    seccomp_notice();

    /* Shared guest-PID registry: must exist before the first do_execve (which
     * registers this process) and before any fork inherits the mapping. With
     * -shared-proc the registry is keyed by the rootfs so ps/top see the guest
     * processes of other emulator invocations of the same rootfs. */
    proctab_init(m->shared_proc ? m->rootfs : NULL);

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
