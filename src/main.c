/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* arm64chroot: run an AArch64 Linux program from a rootfs directory under a
 * pure-interpreter user-space emulator.
 *
 *   arm64chroot [options] <rootfs> <program> [args...]
 *
 * The full option / environment-variable reference lives in help() below
 * (reachable via -h/--help), which reflows it to the terminal width. Keep the
 * option strings there and the overview in README.md in sync.
 */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "machine.h"
#include "thread.h"
#include "jit.h"
#include "guest_abi.h"
#include "ptrace.h"
#include "sys.h"

extern int g_predecode;   /* predecode.c: decoded-instruction cache enable */

#define PROGRAM_VERSION "1.5.0"

struct Machine g_machine;

extern char **environ;

/* Did a -E/--env flag already set the key of `kv` ("KEY=" or "KEY=VALUE")? Such
 * a key is neither inherited from the host nor given a default -- the flag is
 * the whole answer for it. */
static int env_set_by_flag(char **extra, int n, const char *kv) {
    const char *eq = strchr(kv, '=');
    size_t kl = eq ? (size_t)(eq - kv) + 1 : strlen(kv);
    for (int j = 0; j < n; j++)
        if (!strncmp(extra[j], kv, kl)) return 1;
    return 0;
}

/* Terse synopsis for argument errors: one line to stderr, exit 2. The full
 * reference lives in help() below, reachable via -h/--help. */
static void usage(void) {
    fprintf(stderr,
            "usage: arm64chroot [options] <rootfs> <program> [args...]\n"
            "try 'arm64chroot --help' for details\n");
    exit(2);
}

/* Print the program version to stdout and exit 0 (-v/--version). */
static void version(void) {
    fputs("Version: " PROGRAM_VERSION "\n", stdout);
    fputs("GitHub: https://github.com/sylirre/arm64emu-user\n", stdout);
    exit(0);
}

/* --- help renderer: reflow the reference to the terminal width ---------
 * Layout mirrors the proot-distro help renderer: UPPERCASE sections framed by
 * blank lines, a two-column name/description table (one blank line between
 * entries) that collapses to a stacked layout on narrow PTYs, minus coloring. */

#define HELP_MIN_COLS 32   /* clamp for very narrow phone PTYs           */
#define HELP_MAX_COLS 92   /* clamp so wide terminals stay readable      */
#define HELP_NARROW   60   /* below this, name+description stack vertically */

/* A named entry (option / argument / env var) with its description. */
struct help_def { const char *name, *desc; };

/* Terminal width for help output, clamped to [HELP_MIN_COLS, HELP_MAX_COLS].
 * Help is written to stdout, so probe stdout first, then stdin/stderr, then
 * $COLUMNS (for redirected runs), finally a sane default. */
static int help_cols(void) {
    struct winsize ws;
    static const int fds[] = { 1, 0, 2 };   /* stdout, stdin, stderr */
    for (int i = 0; i < 3; i++) {
        if (ioctl(fds[i], TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
            int c = ws.ws_col;
            return c < HELP_MIN_COLS ? HELP_MIN_COLS
                 : c > HELP_MAX_COLS ? HELP_MAX_COLS : c;
        }
    }
    int c = 80;
    const char *cols = getenv("COLUMNS");
    if (cols && *cols) { int v = atoi(cols); if (v > 0) c = v; }
    return c < HELP_MIN_COLS ? HELP_MIN_COLS
         : c > HELP_MAX_COLS ? HELP_MAX_COLS : c;
}

/* Greedy word-wrap: emit *text* to *f* wrapped to *width* columns, every line
 * prefixed with *indent* spaces. Words are never split; a blank line in the
 * source ("\n\n") starts a new paragraph. When *skip_first* is set the leading
 * indent of the very first line is suppressed — the caller has already placed
 * the cursor at column *indent* (used by the two-column table for line 1). */
static void help_wrap(FILE *f, const char *text, int width, int indent,
                      int skip_first) {
    int avail = width - indent;
    if (avail < 8) avail = 8;
    const char *p = text;
    int col = 0;                 /* chars used on the current line (past indent) */
    int need_indent = !skip_first;
    while (*p) {
        if (p[0] == '\n' && p[1] == '\n') {   /* paragraph break */
            if (col) fputc('\n', f);
            fputc('\n', f);
            col = 0;
            need_indent = 1;
            p += 2;
            while (*p == ' ' || *p == '\n') p++;
            continue;
        }
        if (*p == ' ' || *p == '\n') { p++; continue; }
        const char *e = p;                    /* one word: [p, e) */
        while (*e && *e != ' ' && *e != '\n') e++;
        int wlen = (int)(e - p);
        if (col == 0) {
            if (need_indent) fprintf(f, "%*s", indent, "");
            fwrite(p, 1, wlen, f);
            col = wlen;
            need_indent = 1;      /* every subsequent line is indented */
        } else if (col + 1 + wlen <= avail) {
            fputc(' ', f);
            fwrite(p, 1, wlen, f);
            col += 1 + wlen;
        } else {
            fprintf(f, "\n%*s", indent, "");
            fwrite(p, 1, wlen, f);
            col = wlen;
        }
        p = e;
    }
    if (col) fputc('\n', f);
}

/* Render name/description pairs as an aligned two-column table, falling back
 * to a stacked layout (name on its own line, description indented below) when
 * the terminal is too narrow to give the description a usable column. Entries
 * are separated by one blank line (proot-distro options spacing). */
static void help_defs(FILE *f, const struct help_def *d, int n, int width) {
    size_t longest = 0;
    for (int i = 0; i < n; i++)
        if (strlen(d[i].name) > longest) longest = strlen(d[i].name);

    int cap = width / 3; if (cap < 16) cap = 16;
    int opt_col = (int)longest < cap ? (int)longest : cap;
    int desc_col = width - opt_col - 4;
    int stacked = width < HELP_NARROW || desc_col < 24;

    for (int i = 0; i < n; i++) {
        if (stacked) {
            fprintf(f, "  %s\n", d[i].name);
            help_wrap(f, d[i].desc, width, 4, 0);
        } else {
            int cont = 2 + opt_col + 2;   /* description column start */
            if ((int)strlen(d[i].name) <= opt_col) {
                /* Name and its 2-space pad place the cursor at column *cont*,
                 * so the first description line skips its own indent. */
                fprintf(f, "  %-*s  ", opt_col, d[i].name);
                help_wrap(f, d[i].desc, width, cont, 1);
            } else {
                fprintf(f, "  %s\n", d[i].name);
                help_wrap(f, d[i].desc, width, cont, 0);
            }
        }
        if (i != n - 1) fputc('\n', f);   /* one blank line between entries */
    }
}

/* Print shell examples, each prefixed with "  $ " and wrapped with a trailing
 * " \\" continuation so long command lines stay copy-pasteable. */
static void help_examples(FILE *f, const char *const *ex, int n, int width) {
    int avail = width - 6; if (avail < 8) avail = 8;   /* -4 prefix, -2 " \\" */
    for (int i = 0; i < n; i++) {
        const char *p = ex[i];
        int first = 1, col = 0;
        while (*p) {
            while (*p == ' ') p++;
            if (!*p) break;
            const char *e = p;
            while (*e && *e != ' ') e++;
            int wlen = (int)(e - p);
            if (col == 0) {
                fputs(first ? "  $ " : "    ", f);
                fwrite(p, 1, wlen, f);
                col = wlen;
            } else if (col + 1 + wlen <= avail) {
                fputc(' ', f);
                fwrite(p, 1, wlen, f);
                col += 1 + wlen;
            } else {
                fputs(" \\\n", f);
                fputs("    ", f);
                fwrite(p, 1, wlen, f);
                col = wlen;
                first = 0;
            }
            p = e;
        }
        fputc('\n', f);
    }
}

/* Blank line, an UPPERCASE section heading, then a blank line beneath it
 * (proot-distro section spacing; no rule, no color). */
static void help_section(FILE *f, const char *title) {
    fprintf(f, "\n%s\n\n", title);
}

/* Full reference help: purpose, usage, arguments, every option, environment
 * variables, and examples. Reflowed to the terminal width. Printed to stdout
 * on -h/--help, exit 0. */
static void help(void) {
    FILE *f = stdout;
    int w = help_cols();

    static const struct help_def args[] = {
        {"<rootfs>",  "Directory tree holding an AArch64 userland (e.g. an "
                      "Alpine or Debian ARM64 root filesystem); '/' runs "
                      "host-native aarch64 binaries directly. Guest paths "
                      "resolve inside the rootfs."},
        {"<program>", "Guest program to execute, absolute path inside the "
                      "rootfs."},
        {"args...",   "Arguments passed on to the guest program."},
    };
    static const struct help_def opts[] = {
        {"-h, --help",  "Show this help and exit."},
        {"-v, --version", "Show version and exit."},
        {"    --strace", "Log guest syscalls to stderr."},
        {"    --strace-full", "Like --strace, but decode arguments strace-style: "
                        "symbolic flags, quoted strings, structs, errno returns."},
        {"-d, --debug", "Per-instruction trace. Very verbose, disables JIT."},
        {"-j, --jit",   "Translate hot basic blocks to native code on AArch64, "
                        "x86-64, i686 and ARM32 hosts. Falls back to the "
                        "interpreter elsewhere."},
        {"    --no-predecode", "Disable the decoded-instruction cache "
                        "(diagnostic, slower)."},
        {"-l, --link2symlink", "Emulate hardlinks with tracked symlinks where "
                        "the host forbids link() (Android OS)."},
        {"    --shared-proc", "Share synthesized /proc view between multiple "
                        "emulator sessions within same rootfs."},
        {"    --no-dev", "Disable the synthesized /dev."},
        {"    --no-proc", "Disable the synthesized /proc."},
        {"-b, --bind SRC:DST[:ro]", "Expose host directory SRC at guest path "
                        "DST (repeatable). Append :ro for a read-only mount. "
                        "Host paths may not contain ':'."},
        {"-E, --env VAR=VAL", "Set a guest environment variable (repeatable), "
                        "overriding anything below that would set the same "
                        "name. The guest environment is otherwise built fresh: "
                        "TERM and COLORTERM are inherited from the host, PATH "
                        "defaults to "
                        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
                        "/sbin:/bin and HOME to /root, and every other host "
                        "variable is dropped as naming host locations."},
        {"-0, --argv0 ARG0", "Override argv[0] for the guest program"},
        {"-u, --fake-id[=ID]", "Present a fake user identity. Accepts values "
                        "like uid or uid:gid, default 0:0 (root)."},
        {"    --share-abstract-sockets", "Share abstract namespace sockets "
                        "of the host, disable per-rootfs socket isolation."},
        {"-w, --work-dir DIR", "Use a given absolute path of the guest as "
                        "current working directory. Default is '/'."},
        {"    --",      "Stop option parsing."},
    };
    static const struct help_def env_tune[] = {
        {"A64_JIT_MB", "Per-thread JIT code-cache size in MiB. Default "
                        "32, clamped to 1-128."},
        {"XDG_RUNTIME_DIR, TMPDIR", "First writable of these (or /dev/shm) holds "
                        "the backing directories of emulated tmpfs mounts, plus "
                        "the --shared-proc fallback registry file and System V "
                        "shm segment files when memfd_create is unavailable."},
    };
    static const struct help_def env_diag[] = {
        {"A64_JIT_STATS", "Rank instruction words still run via the exec_a64 "
                        "helper, =/path dumps the ranking to a file at exit."},
        {"A64_JIT_DUMP=PREFIX", "Write each translated block into a sparse "
                        "code-cache image (PREFIX.<pid>.<tid>.code plus a .map)."},
        {"A64_JIT_PDMAX=N", "Force predecode ops with id > N through the helper "
                        "(bisects a codegen bug to one instruction class)."},
        {"A64_JIT_SLOWMEM", "Force every inline memory op down its slow helper "
                        "branch."},
        {"A64_JIT_NOFUSE", "Disable instruction / D-TLB-probe fusion."},
        {"A64_JIT_NOFP16", "Disable FP16 native codegen (AArch64 backend)."},
        {"A64_JIT_NOVRA", "Disable the V-register cache."},
        {"A64_JIT_SSE=2", "Force SSE2-baseline capability answers (x86-64)."},
        {"A64_PROCSTAT_FORCE_SYNTH", "Force the synthetic /proc/stat fallback."},
        {"A64_PROCSTAT_HOTPLUG_SIM", "Walk the online-CPU count down on every "
                        "/proc/stat sample (simulates a host that hotplugs "
                        "cores, as Android does)."},
        {"A64_OVERFLOWID_FORCE_SYNTH", "Force the synthetic "
                        "/proc/sys/kernel/overflow{u,g}id fallback."},
        {"A64_NETLINK_FORCE_BLOCK", "Force the netlink fallback path."},
        {"A64_SHM_FORCE_FILE", "Force System V shm segments onto file backing "
                        "instead of an anonymous memfd (exercises the fallback "
                        "tier)."},
        {"A64_GETRANDOM_FORCE_DEV", "Force getrandom(2), and the guest's "
                        "AT_RANDOM seed, onto the /dev/urandom / /dev/random "
                        "fallback (the tier a host kernel without getrandom "
                        "is served by)."},
        {"A64_PAGEPROBE_FORCE_PIPE", "Probe a grown file mapping's pages "
                        "with a pipe instead of process_vm_readv (the tier a "
                        "host kernel older than 3.2 is served by)."},
        {"A64_MEMFD_FORCE_FILE", "Force guest memfd_create(2) onto the "
                        "unlinked-file fallback tier with broker-held seals "
                        "(what a host kernel without memfd_create is served "
                        "by)."},
        {"A64_SIGRT_MAX=N", "Reserve the emulator's own host signals below N "
                        "instead of at the top of the RT range (exercises the "
                        "tier a host that cannot deliver its top RT signals is "
                        "served by)."},
        {"A64_OWNFD_FORCE_DENY", "Refuse the path spelling of the emulator's "
                        "own fds (/proc/self/fd/N), as Android's policy does "
                        "for a memfd, so exec and open take the descriptor "
                        "fallback."},
        {"A64_TLBPUB_MAX=N", "Cap the published-epoch table at N slots "
                        "(exercises the tier a guest with more live threads "
                        "than it holds is served by: the retired-backing "
                        "quarantine stops draining)."},
    };
    static const char *const examples[] = {
        "arm64chroot ./rootfs /bin/sh",
        "arm64chroot --jit --fake-id ./rootfs /bin/bash -l",
        ("arm64chroot -b \"$PWD:/work\" --bind /etc/ssl:/etc/ssl:ro "
            "./rootfs /bin/su -l"),
    };

    help_section(f, "USAGE");
    help_wrap(f, "arm64chroot [options] <rootfs> <program> [args...]", w, 2, 0);

    help_section(f, "DESCRIPTION");
    help_wrap(f,
        "AArch64 Linux user-space emulator for running unprivileged, "
        "isolated chroot-like environments. Implements a full user ISA "
        "including FP, ASIMD, AES, PMULL, SHA*, CRC32, atomics. Supports "
        "~190 system calls which should be enough for most of workloads.\n\n"
        "Directory layout for /dev expose a minimal set of device nodes "
        "needed for correct functioning of guest programs. The /proc is "
        "almost entirely synthesized to provide process data correct "
        "from the view point of emulator.\n\n"
        "This utility can execute programs on file systems mounted with "
        "'noexec' option or where execution is not allowed by SELinux.",
    w, 2, 0);

    help_section(f, "ARGUMENTS");
    help_defs(f, args, (int)(sizeof args / sizeof *args), w);

    help_section(f, "OPTIONS");
    help_defs(f, opts, (int)(sizeof opts / sizeof *opts), w);

    help_section(f, "ENVIRONMENT");
    help_wrap(f, "Tuning:", w, 2, 0);
    fputc('\n', f);
    help_defs(f, env_tune, (int)(sizeof env_tune / sizeof *env_tune), w);
    fputc('\n', f);
    help_wrap(f, "Diagnostics, for development:", w, 2, 0);
    fputc('\n', f);
    help_defs(f, env_diag, (int)(sizeof env_diag / sizeof *env_diag), w);

    help_section(f, "EXAMPLES");
    help_examples(f, examples, (int)(sizeof examples / sizeof *examples), w);
    fputc('\n', f);   /* trailing blank line so output ends clear of the prompt */

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
        fprintf(stderr, "arm64chroot: --bind '%s': destination path must be absolute\n", spec);
        exit(2);
    }
    char host[PATH_MAX], guest[PATH_MAX];
    if (!realpath(src, host)) {
        fprintf(stderr, "arm64chroot: --bind source path '%s': not found\n", src);
        exit(126);
    }
    if (!strcmp(host, "/")) {
        fprintf(stderr, "arm64chroot: --bind '%s': cannot bind host root\n", spec);
        exit(2);
    }
    if (canon_guest(dst, guest) < 0) {
        fprintf(stderr, "arm64chroot: --bind '%s': destination path too long\n", spec);
        exit(2);
    }
    if (!strcmp(guest, "/")) {
        fprintf(stderr, "arm64chroot: --bind '%s': cannot bind over guest root\n", spec);
        exit(2);
    }
    /* Register into the shared bind table (same path the runtime mount(2) uses). */
    int r = bind_add(m, guest, host, ro);
    if (r == -ENOMEM) {
        fprintf(stderr, "arm64chroot: too many --bind mounts (max %d)\n", BIND_MAX);
        exit(2);
    }
    if (r < 0) {
        fprintf(stderr, "arm64chroot: --bind '%s': %s\n", spec, strerror(-r));
        exit(2);
    }
}

/* ---- fork safety: the emulator's lock hierarchy, written down once --------
 *
 * fork(2) duplicates the calling thread alone, so a mutex a *sibling* held at
 * that instant crosses into the child locked and owned by a thread that does
 * not exist there. One pthread_atfork triple settles all of them: prepare takes
 * every lock (which also means no sibling is mid-mutation, so the child
 * inherits a settled page table rather than a half-rewritten one), parent
 * releases them, and the child re-initializes rather than unlocks, because fork
 * gives the surviving thread a new tid and a recursive mutex's recorded owner no
 * longer matches it.
 *
 * The order below IS the emulator's lock hierarchy, outermost first, and this is
 * the only place it is stated. It must agree with the order real code nests
 * them in, or a fork deadlocks against a sibling coming the other way: prepare
 * would hold an inner lock and wait for an outer one while the sibling holds the
 * outer and waits for the inner. as_lock is innermost because any critical
 * section that touches guest memory takes it underneath its own lock —
 * copy_to/from_guest → translate() takes it on a D-TLB miss, and
 * nl_take_request does that on every guest netlink request while holding
 * nl_lock. casp16 sits just above it (a CASP retry can miss the D-TLB), and
 * pf_lock above est_lock (the refresh path already holds pf_lock).
 *
 * This used to be five separate registrations, one per module, which encoded the
 * same hierarchy in the *reverse* order of five adjacent calls — sorting them
 * was enough to deadlock every fork. tests/fixtures/forklock.c is the guard. */
static void emu_atfork_prepare(void) {
    jit_locks_take();        /* jit stats  — outermost */
    procfs_locks_take();     /* pf_lock, then est_lock */
    netlink_locks_take();    /* nl_lock    — taken above as_lock by real code */
    sig_locks_take();        /* sfd_lock */
    mem_locks_take();        /* casp16, then as_lock — innermost */
}
static void emu_atfork_parent(void) {
    mem_locks_drop();        /* innermost first, mirroring prepare */
    sig_locks_drop();
    netlink_locks_drop();
    procfs_locks_drop();
    jit_locks_drop();
}
static void emu_atfork_child(void) {
    mem_locks_reinit();
    sig_locks_reinit();
    netlink_locks_reinit();
    procfs_locks_reinit();
    jit_locks_reinit();
}
static void emu_atfork_init(void) {
    pthread_atfork(emu_atfork_prepare, emu_atfork_parent, emu_atfork_child);
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
    char **nv = realloc(*env, sizeof(char *) * (size_t)(*n + 1));
    if (!nv) { perror("arm64chroot: realloc"); exit(127); }
    *env = nv;
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
int main(int argc, char **argv)
#endif
{
    struct Machine *m = &g_machine;
    const char *argv0 = NULL;
    const char *work_dir = NULL;
    char **extra_env = NULL;
    int n_extra = 0;

    u32 fake_uid = 0, fake_gid = 0;

    /* Create the process-shared bind table before any --bind registration below
     * and before the first fork, so every guest process maps the same mounts. */
    bindtab_init();

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
            else if (!strcmp(n, "version"))      { if (val) opt_no_value(arg); version(); }
            else if (!strcmp(n, "strace"))       { if (val) opt_no_value(arg); m->strace = 1; }
            else if (!strcmp(n, "strace-full"))   { if (val) opt_no_value(arg); m->strace = 1; m->strace_full = 1; }
            else if (!strcmp(n, "debug"))        { if (val) opt_no_value(arg); g_trace = 1; g_debug_hooks = 1; }
            else if (!strcmp(n, "jit"))          { if (val) opt_no_value(arg); g_jit = 1; }
            else if (!strcmp(n, "no-predecode")) { if (val) opt_no_value(arg); g_predecode = 0; }
            else if (!strcmp(n, "link2symlink")) { if (val) opt_no_value(arg); m->link2symlink = 1; }
            else if (!strcmp(n, "shared-proc"))  { if (val) opt_no_value(arg); m->shared_proc = 1; }
            else if (!strcmp(n, "no-dev"))       { if (val) opt_no_value(arg); m->no_dev = 1; }
            else if (!strcmp(n, "no-proc"))      { if (val) opt_no_value(arg); m->no_proc = 1; }
            else if (!strcmp(n, "share-abstract-sockets")) { if (val) opt_no_value(arg); m->share_abstract = 1; }
            else if (!strcmp(n, "bind"))   add_bind(m, long_value("--bind", val, argv, argc, &i));
            else if (!strcmp(n, "env"))    push_env(&extra_env, &n_extra, long_value("--env", val, argv, argc, &i));
            else if (!strcmp(n, "argv0"))  argv0 = long_value("--argv0", val, argv, argc, &i);
            else if (!strcmp(n, "work-dir")) work_dir = long_value("--work-dir", val, argv, argc, &i);
            else if (!strcmp(n, "fake-id")) set_fake_id(m, val, argv, argc, &i, &fake_uid, &fake_gid);
            else usage();
        } else {                                       /* short cluster: -abc */
            for (char *p = arg + 1; *p; ) {
                char c = *p++;
                if      (c == 'h') help();
                else if (c == 'v') version();
                else if (c == 'd') { g_trace = 1; g_debug_hooks = 1; }
                else if (c == 'j') g_jit = 1;
                else if (c == 'l') m->link2symlink = 1;
                else if (c == 'b') { add_bind(m, short_value("--bind", p, argv, argc, &i)); break; }
                else if (c == 'E') { push_env(&extra_env, &n_extra, short_value("--env", p, argv, argc, &i)); break; }
                else if (c == '0') { argv0 = short_value("--argv0", p, argv, argc, &i); break; }
                else if (c == 'w') { work_dir = short_value("--work-dir", p, argv, argc, &i); break; }
                else if (c == 'u') { set_fake_id(m, p, argv, argc, &i, &fake_uid, &fake_gid); break; }
                else usage();
            }
        }
    }
    if (argc - i < 2) usage();

    /* -jit yields to per-instruction debug facilities and to hosts without a
     * code generator; the interpreter is always the correct fallback. */
    if (g_jit && g_debug_hooks) {
        fprintf(stderr, "arm64chroot: JIT disabled by per-instruction "
                        "debug flags, using interpreter\n");
        g_jit = 0;
    }
    if (g_jit && !jit_backend_available()) {
        fprintf(stderr, "arm64chroot: JIT has no backend for this host, "
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

    /* Per-rootfs tag spliced into guest abstract AF_UNIX socket names to isolate
     * them from the host and from other rootfs instances (sys_net.c). Same
     * rootfs -> same tag, so guest processes still rendezvous. The 0x01 lead
     * makes a collision with a real host abstract name essentially impossible. */
    m->abs_tag[0] = 0x01;
    int atn = snprintf(m->abs_tag + 1, sizeof m->abs_tag - 1, "a64%08x",
                       (unsigned)fnv1a32(m->rootfs));
    m->abs_tag_len = (u8)(1 + atn);

    /* Per-invocation nonce keying the System V shm broker's rendezvous when
     * --shared-proc is off (machine.h / proctab.c). The root pid makes it unique
     * among live invocations; mixing in the start time keeps a pid reused within
     * a dying daemon's grace window from rejoining the old namespace. Seeded once
     * here in the root process and fork-inherited, so one launch's whole process
     * tree shares one shm namespace while separate launches stay isolated. */
    struct timespec sts;
    clock_gettime(CLOCK_REALTIME, &sts);
    m->shm_session = ((u64)getpid() << 32) ^
                     ((u64)sts.tv_sec * 1000000000ull + (u64)sts.tv_nsec);

    /* Not chrooted initially: the guest root is the rootfs root. */
    strcpy(m->chroot_base, "/");

    /* Guest cwd: the host cwd when it lies inside the rootfs, else "/". */
    strcpy(m->cwd, "/");
    char hcwd[PATH_MAX];
    if (getcwd(hcwd, sizeof hcwd)) {
        size_t rl = strlen(m->rootfs);
        if (!strncmp(hcwd, m->rootfs, rl) && (hcwd[rl] == '/' || hcwd[rl] == 0))
            strcpy(m->cwd, hcwd[rl] ? hcwd + rl : "/");
    }

    /* -w/--work-dir overrides the initial cwd with a guest path (resolved inside
     * the rootfs, honoring -bind and symlinks). An absolute DIR resolves from
     * guest "/", a relative one against the default cwd above. Must land before
     * do_execve, which resolves <program> against m->cwd. Fatal on a bad path. */
    if (work_dir) {
        char host[PATH_MAX], canon[PATH_MAX];
        struct stat st;
        int r = path_resolve(m, G_AT_FDCWD, work_dir, 0, host, canon);
        if (r == 0 && stat(host, &st) < 0) r = -errno;
        else if (r == 0 && !S_ISDIR(st.st_mode)) r = -ENOTDIR;
        if (r < 0) {
            fprintf(stderr, "arm64chroot: work-dir '%s': %s\n",
                    work_dir, strerror(-r));
            return 126;
        }
        strcpy(m->cwd, canon);
    }

    /* Guest argv: program args as given; argv[0] overridable. */
    int gargc = 0;
    while (gargv_in[gargc]) gargc++;
    char **gargv = malloc(sizeof(char *) * (size_t)(gargc + 1));
    if (!gargv) { perror("arm64chroot: malloc"); exit(127); }
    for (int k = 0; k < gargc; k++) gargv[k] = gargv_in[k];
    gargv[gargc] = NULL;
    if (argv0) gargv[0] = (char *)argv0;

    /* Guest environ: a clean environment. Only the host's terminal-appearance
     * variables (TERM, COLORTERM) are inherited; every other host variable
     * (PATH, HOME, LD_*, XDG_*, ...) names host locations, not guest ones, and
     * is dropped. What the guest gets instead of the dropped PATH and HOME is
     * a pair of guest-side defaults (guest_default below), not the host's.
     * -E/--env entries come first and win: a host var is inherited, and a
     * default supplied, only when no -E entry already sets that key. (Emitting
     * both as duplicates is not enough -- getenv() would return the -E copy but
     * a shell importing envp keeps the *last* duplicate, i.e. the other value,
     * defeating the override.) Callers re-add anything else they need with -E.
     *
     * Dropping PATH without replacing it was not neutral: it left the guest with
     * no PATH at all, which nothing on a real system ever has. Programs that
     * search it themselves rather than going through execvp(3) then fail before
     * they exec anything -- gcc's collect2 looks for `ld` over COMPILER_PATH +
     * $PATH and dies with "cannot find 'ld'", so compiling in a Debian rootfs
     * needed an explicit -E PATH=... The values are the ones a login would set
     * for root: login.defs ENV_SUPATH, and root's home -- which is the identity
     * --fake-id presents, and the only one whose home directory a rootfs can be
     * assumed to have. */
    static const char *const host_keep[] = { "TERM=", "COLORTERM=" };
    static const char *const guest_default[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
    };
    int n_keep = (int)(sizeof host_keep / sizeof *host_keep);
    int n_def  = (int)(sizeof guest_default / sizeof *guest_default);
    char **genv = malloc(sizeof(char *) * (size_t)(n_extra + n_keep + n_def + 1));
    if (!genv) { perror("arm64chroot: malloc"); exit(127); }
    int ge = 0;
    for (int k = 0; k < n_extra; k++) genv[ge++] = extra_env[k];
    for (int k = 0; k < n_keep; k++) {
        if (env_set_by_flag(extra_env, n_extra, host_keep[k])) continue;
        size_t kl = strlen(host_keep[k]);
        for (char **e = environ; *e; e++)
            if (!strncmp(*e, host_keep[k], kl)) { genv[ge++] = *e; break; }
    }
    for (int k = 0; k < n_def; k++)
        if (!env_set_by_flag(extra_env, n_extra, guest_default[k]))
            genv[ge++] = (char *)guest_default[k];
    genv[ge] = NULL;

    rlim_init(m);     /* seed the guest's resource limits from the host's,
                       * before anything can consult or change them */
    as_init(&m->as);
    /* Before any handler is installed or can fire: on Bionic (emulated TLS)
     * the first access to a __thread variable mallocs, and a signal handler
     * must never be the first toucher (sig_tls_prewarm). */
    sig_tls_prewarm();
    as_bus_init();   /* host SIGBUS on a file truncated from outside this
                      * address space becomes the guest's own abort */
    m->cpu.m = m;
    g_tls.tid = getpid();     /* main thread tid == pid */

    /* Arm the SIGSYS net (seccomp trap -> -ENOSYS) before any guest work:
     * the ELF loader below already forwards host syscalls. */
    sig_install_sigsys_net();
    /* Which RT signals this host will let us reserve, before anything installs
     * a handler on one or sends one. A number the host accepts but never
     * delivers would turn the kick below -- and every other wake-up riding it
     * -- into a hang, so it is measured rather than assumed. */
    sig_probe_reserved();
    /* Arm the ptrace attach stop-kick net (reserved RT signal) so a later
     * PTRACE_ATTACH/SEIZE/INTERRUPT can stop this process cooperatively. */
    sig_install_kick_net();
    /* Make every process-local mutex fork-safe before there is a second thread
     * to hold one (mem.c carries the full story and the hang it cost). */
    mem_locks_init();
    emu_atfork_init();

#ifndef ANDROID_JNI
    // Suppress seccomp notice on Android JNI component builds.
    seccomp_notice();
#endif

    /* Shared guest-PID registry: must exist before the first do_execve (which
     * registers this process) and before any fork inherits the mapping. With
     * -shared-proc the registry is keyed by the rootfs so ps/top see the guest
     * processes of other emulator invocations of the same rootfs. */
    proctab_init(m->shared_proc ? m->rootfs : NULL);

    /* Backing directories of emulated tmpfs mounts (path.c) are removed when
     * this invocation ends; sweep what invocations killed before they could do
     * that left behind, so they cannot pile up. */
    tmpfs_sweep_stale();

    /* ptrace(2) tracer<->tracee link registry: same discipline — created before
     * the first fork so every guest process in the session maps it. */
    ptrace_init();

    /* What execve's CLOEXEC sweep may not close: read now, while the limit is
     * still the one this process started with and no guest code has run. */
    guest_fd_ceiling_init();
    /* Likewise for the host tasks in our thread group that are not ours: name
     * them now, while "this process has one thread" is still a fact. Everything
     * that reads the host task list as the guest thread list depends on it. */
    proc_foreign_sample();

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
