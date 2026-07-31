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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

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

int main(void) {
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
