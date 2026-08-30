/* "symlink/.." is not the symlink's parent. The kernel resolves the link first
 * and climbs from its TARGET, so with `a/b -> ../c` the path a/b/../x names
 * ../x relative to c, not relative to a.
 *
 * A resolver that folds ".." lexically gets a different existing file (row
 * dd_e: a/b/../e/x is e/x, while the fold says a/e/x -- both are there), or a
 * spurious ENOENT for the ordinary `bin -> real/bin` layout that names
 * ../lib. The emulator's optimistic route (path.c, path_resolve_pin) is
 * exactly such a fold, certified by a pin that walks only the components the
 * fold LEFT -- so a component a ".." cancels is gone before the pin can ask
 * whether it was a symlink, and the fold has to hand those paths to the
 * authoritative walk instead.
 *
 * The rows with no ".." are here for the other half of the contract: a
 * symlink still standing in the resolved path must make the pin refuse
 * (ELOOP) and fall back, rather than be walked past.
 *
 * The tree is built one level below the temp directory so that every ".."
 * lands somewhere this test owns; a `..` that climbed out would be reading
 * whatever the host has there. Not included: `lfile/..`, `dangling/..` and
 * `nodir/..`, where the kernel refuses (ENOTDIR/ENOENT) a component this
 * resolver cancels without looking at -- a divergence that predates the
 * optimistic route and belongs to the walk itself. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static char base[256];

static void mk(const char *rel, const char *data)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    ssize_t n = write(fd, data, strlen(data));
    (void)n;
    close(fd);
}

static void md(const char *rel)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    mkdir(p, 0755);
}

static void ln(const char *tgt, const char *rel)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    if (symlink(tgt, p) < 0) printf("symlink %s errno=%d\n", rel, errno);
}

/* Resolve one path under the tree and print what it reached, or the errno that
 * refused it. The label is fixed, so the two sides compare line for line. */
static void ask(const char *label, const char *rel)
{
    char p[512], buf[64];
    snprintf(p, sizeof p, "%s/r/%s", base, rel);
    errno = 0;
    int fd = open(p, O_RDONLY);
    if (fd < 0) { printf("%s errno=%d\n", label, errno); return; }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) { printf("%s read-errno=%d\n", label, errno); return; }
    buf[n] = 0;
    printf("%s %s\n", label, buf);
}

static void rm(const char *rel)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    if (unlink(p) < 0) rmdir(p);
}

int main(void)
{
    snprintf(base, sizeof base, "/tmp/ci_pdd.XXXXXX");
    if (!mkdtemp(base)) { printf("mkdtemp errno=%d\n", errno); return 0; }

    mk("x", "top-x");
    md("r");
    mk("r/x", "r-x");
    md("r/a"); mk("r/a/x", "a-x");
    md("r/a/e"); mk("r/a/e/x", "a-e-x");
    md("r/c"); mk("r/c/x", "c-x");
    md("r/c/c"); mk("r/c/c/x", "c-c-x");
    md("r/c/e"); mk("r/c/e/x", "c-e-x");
    md("r/e"); mk("r/e/x", "e-x");
    md("r/d"); mk("r/d/x", "d-x");
    ln("../c", "r/a/b");        /* a sibling directory, reached relatively */
    ln("..",   "r/d/lup");      /* the tree root, reached through a link */

    /* A ".." that cancels a symlink: the fold's answer and the kernel's are
     * different files, and both of them exist. */
    ask("dd_plain", "a/b/../x");
    ask("dd_dot",   "a/b/./../x");
    ask("dd_slash", "a//b//..//x");
    ask("dd_mid",   "a/./b/../x");
    ask("dd_deep",  "a/b/c/../x");
    ask("dd_deep2", "a/b/c/../../x");
    ask("dd_sub",   "a/b/e/../x");
    ask("dd_e",     "a/b/../e/x");
    ask("dd_up2",   "a/b/../../x");
    ask("dd_link",  "d/lup/x");
    ask("dd_linkup", "d/lup/../x");
    ask("dd_linkin", "d/lup/a/x");
    /* A trailing slash on the folded result still has to demand a directory. */
    ask("dd_trail", "a/b/../x/");
    /* No "..": the symlink is still in the resolved path, and the pin has to
     * refuse it rather than walk past it. */
    ask("nd_through", "a/b/x");
    ask("nd_plain",   "a/x");
    ask("nd_root",    "x");

    rm("r/d/lup"); rm("r/a/b");
    rm("r/d/x"); rm("r/d");
    rm("r/e/x"); rm("r/e");
    rm("r/c/e/x"); rm("r/c/e");
    rm("r/c/c/x"); rm("r/c/c");
    rm("r/c/x"); rm("r/c");
    rm("r/a/e/x"); rm("r/a/e");
    rm("r/a/x"); rm("r/a");
    rm("r/x"); rm("r");
    rm("x");
    rmdir(base);
    printf("done\n");
    return 0;
}
