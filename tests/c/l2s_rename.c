/* -link2symlink: renaming an emulated hardlink out of its directory.
 *
 * The scheme points every "hardlink" name at a hidden backing file through a
 * symlink whose target is a bare same-directory basename, so moving a name to
 * another directory used to leave it dangling AND strand its reference — the
 * backing kept a link count nothing could release, so it was never reclaimed.
 *
 * This test is meaningful only under an emulator built with
 * -DA64_LINK2SYMLINK -DA64_L2S_FORCE and run with --link2symlink, which is
 * how run_tests.sh drives it (the android-sim variant). Under any other
 * emulator, and under qemu, link(2) is a real hardlink and every check below
 * still holds — st_nlink is the one thing that legitimately differs, so it is
 * reported only where the two agree.
 *
 * Every check prints PASS/FAIL with a name, so the failing case is named
 * rather than inferred from a digest.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

static int fails;

static void ck(const char *what, int ok) {
    printf("%-38s %s\n", what, ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

/* Contents of `p`, or NULL. */
static char *slurp(const char *p) {
    static char buf[128];
    int fd = open(p, O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) return NULL;
    buf[n] = '\0';
    return buf;
}

static int readable_with(const char *p, const char *want) {
    char *s = slurp(p);
    return s && !strcmp(s, want);
}

/* Count entries in `d` other than . and .. — the emulator hides its own
 * bookkeeping files from readdir, so a leftover backing shows up as a
 * directory that refuses to become empty rather than as a visible name. */
static int visible_entries(const char *d) {
    DIR *dp = opendir(d);
    if (!dp) return -1;
    struct dirent *de;
    int n = 0;
    while ((de = readdir(dp)))
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) n++;
    closedir(dp);
    return n;
}

static void mkfile(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror(p); exit(1); }
    if (write(fd, s, strlen(s)) < 0) { perror("write"); exit(1); }
    close(fd);
}

/* rmdir only succeeds once every hidden file is gone too, which is exactly
 * the property a stranded reference breaks. */
static int dir_reclaimable(const char *d) { return rmdir(d) == 0; }

static int exchange_cases(void);

int main(int argc, char **argv) {
    /* "exchange" selects the RENAME_EXCHANGE cases; see exchange_cases. */
    if (argc > 1 && !strcmp(argv[1], "exchange")) return exchange_cases();
    char base[] = "/tmp/l2sXXXXXX";
    if (!mkdtemp(base)) { perror("mkdtemp"); return 1; }
    char a[64], b[64], p[128], q[128], r[128];
    snprintf(a, sizeof a, "%s/a", base);
    snprintf(b, sizeof b, "%s/b", base);

    /* ---- 1. two names, one moved out: both must survive ---- */
    mkdir(a, 0755); mkdir(b, 0755);
    snprintf(p, sizeof p, "%s/f", a);
    snprintf(q, sizeof q, "%s/g", a);
    snprintf(r, sizeof r, "%s/g", b);
    mkfile(p, "CONTENT");
    ck("link same-dir", link(p, q) == 0);
    ck("both names readable", readable_with(p, "CONTENT") &&
                              readable_with(q, "CONTENT"));
    ck("cross-dir rename returns 0", rename(q, r) == 0);
    ck("moved name still readable", readable_with(r, "CONTENT"));
    ck("name left behind still readable", readable_with(p, "CONTENT"));

    /* Removing every visible name must reclaim the directory: a stranded
     * reference leaves the hidden backing behind and rmdir fails ENOTEMPTY. */
    ck("unlink moved name", unlink(r) == 0);
    ck("unlink remaining name", unlink(p) == 0);
    ck("source dir has no visible leftovers", visible_entries(a) == 0);
    ck("source dir reclaimable", dir_reclaimable(a));
    ck("dest dir reclaimable", dir_reclaimable(b));

    /* ---- 2. the only name moved out: contents and reclaim ---- */
    mkdir(a, 0755); mkdir(b, 0755);
    mkfile(p, "SOLO");
    ck("link then drop to one name", link(p, q) == 0 && unlink(q) == 0);
    ck("last name cross-dir rename", rename(p, r) == 0);
    ck("last name readable after move", readable_with(r, "SOLO"));
    ck("emptied source dir reclaimable", dir_reclaimable(a));
    ck("unlink after last-name move", unlink(r) == 0);
    ck("dest dir reclaimable (2)", dir_reclaimable(b));

    /* ---- 3. destination exists and is itself a linked name ---- */
    mkdir(a, 0755); mkdir(b, 0755);
    char b2[128];
    snprintf(b2, sizeof b2, "%s/h", b);
    mkfile(p, "SRC");
    mkfile(r, "DST");
    ck("link in source dir", link(p, q) == 0);
    ck("link in dest dir", link(r, b2) == 0);
    ck("rename over a linked name", rename(q, r) == 0);
    ck("replaced name has source data", readable_with(r, "SRC"));
    ck("dest group's other name intact", readable_with(b2, "DST"));
    ck("cleanup 3", unlink(p) == 0 && unlink(r) == 0 && unlink(b2) == 0);
    ck("source dir reclaimable (3)", dir_reclaimable(a));
    ck("dest dir reclaimable (3)", dir_reclaimable(b));

    /* ---- 4. same-directory rename must be untouched ---- */
    mkdir(a, 0755);
    char q2[128];
    snprintf(q2, sizeof q2, "%s/renamed", a);
    mkfile(p, "SAMEDIR");
    ck("link for same-dir rename", link(p, q) == 0);
    ck("same-dir rename returns 0", rename(q, q2) == 0);
    ck("same-dir renamed name readable", readable_with(q2, "SAMEDIR"));
    ck("same-dir original readable", readable_with(p, "SAMEDIR"));
    ck("cleanup 4", unlink(p) == 0 && unlink(q2) == 0);
    ck("same-dir source reclaimable", dir_reclaimable(a));

    /* ---- 5. a plain (unlinked) file crossing directories ---- */
    mkdir(a, 0755); mkdir(b, 0755);
    mkfile(p, "PLAIN");
    ck("plain cross-dir rename", rename(p, r) == 0);
    ck("plain file readable after move", readable_with(r, "PLAIN"));
    ck("plain source gone", access(p, F_OK) != 0 && errno == ENOENT);
    ck("cleanup 5", unlink(r) == 0);
    ck("plain dirs reclaimable", dir_reclaimable(a) && dir_reclaimable(b));

    rmdir(base);
    printf("l2s_rename: %d failed\n", fails);
    return fails != 0;
}

/* RENAME_EXCHANGE cases, run only when asked for by argv[1] (see main).
 *
 * The swap moves BOTH names, so a linked one leaves its directory just as a
 * plain rename does — and left to the host it landed dangling, with its
 * reference still counted, so the backing could never be reclaimed.
 *
 * Kept out of the default run because renameat2 flags are filesystem-dependent
 * and the two worlds do not share one there: the dynamic comparison runs qemu
 * against the host /tmp (tmpfs, which supports the flag) and the emulator
 * against the rootfs /tmp, which on a stacked filesystem such as ecryptfs
 * answers EINVAL. The caller runs this mode only where both sides see the same
 * /tmp. */
static int exchange_cases(void) {
    char base[] = "/tmp/l2sxXXXXXX";
    if (!mkdtemp(base)) { perror("mkdtemp"); return 1; }
    char a[64], b[64], p[128], q[128], q2[128], r[128];
    snprintf(a, sizeof a, "%s/a", base);
    snprintf(b, sizeof b, "%s/b", base);
    snprintf(p, sizeof p, "%s/f", a);
    snprintf(q, sizeof q, "%s/g", a);
    snprintf(q2, sizeof q2, "%s/h", a);
    snprintf(r, sizeof r, "%s/g", b);

    /* ---- 6. RENAME_EXCHANGE across directories ---- */
    mkdir(a, 0755); mkdir(b, 0755);
    mkfile(p, "XCHG_SRC");
    mkfile(r, "XCHG_DST");
    ck("link for exchange", link(p, q) == 0);
    ck("cross-dir exchange returns 0",
       syscall(SYS_renameat2, AT_FDCWD, q, AT_FDCWD, r, RENAME_EXCHANGE) == 0);
    ck("exchanged name has source data", readable_with(r, "XCHG_SRC"));
    ck("exchanged name has dest data", readable_with(q, "XCHG_DST"));
    ck("name left behind still readable", readable_with(p, "XCHG_SRC"));
    ck("cleanup 6", unlink(p) == 0 && unlink(q) == 0 && unlink(r) == 0);
    ck("exchange source has no leftovers", visible_entries(a) == 0);
    ck("exchange source reclaimable", dir_reclaimable(a));
    ck("exchange dest reclaimable", dir_reclaimable(b));

    /* ---- 7. same-directory exchange must be untouched: both symlink targets
     * still resolve, so nothing may be detached. ---- */
    mkdir(a, 0755);
    mkfile(p, "SAME_A");
    mkfile(q2, "SAME_B");
    ck("link for same-dir exchange", link(p, q) == 0);
    ck("same-dir exchange returns 0",
       syscall(SYS_renameat2, AT_FDCWD, q, AT_FDCWD, q2, RENAME_EXCHANGE) == 0);
    ck("same-dir exchanged has other data", readable_with(q, "SAME_B"));
    ck("same-dir exchanged has linked data", readable_with(q2, "SAME_A"));
    ck("same-dir link still shared", readable_with(p, "SAME_A"));
    ck("cleanup 7", unlink(p) == 0 && unlink(q) == 0 && unlink(q2) == 0);
    ck("same-dir exchange reclaimable", dir_reclaimable(a));

    rmdir(base);
    printf("l2s_exchange: %d failed\n", fails);
    return fails != 0;
}
