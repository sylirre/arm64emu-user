/* Which madvise(2) advice values this kernel takes at all, and in what order
 * it judges them.
 *
 * do_madvise() calls madvise_behavior_valid() BEFORE it looks at the range, so
 * an advice value the kernel does not know is EINVAL whatever the range was --
 * an empty length that would otherwise be success, a range with a hole in it
 * that would otherwise be ENOMEM. Answering 0 to every unknown value (which is
 * what this emulator used to do) turns every guest feature probe into a false
 * "supported".
 *
 * The third argument is an `int`, so the high half of the register carries no
 * advice: 0x1_0000_0004 is MADV_DONTNEED, and the last rows go through
 * syscall(2) to say so -- the libc wrapper's prototype would truncate it here
 * instead of in the kernel.
 *
 * Self-checking rather than oracle-diffed: qemu-user emulates MADV_DONTNEED,
 * refuses MADV_WIPEONFORK/MADV_KEEPONFORK outright and ignores everything else,
 * so it answers 0 or EINVAL where a kernel does neither -- it is not a kernel
 * here. Every accepted row below is 0 on a real kernel for the mapping it is
 * given (a private anonymous read-write one), and every refused row is EINVAL
 * there; the block was checked by building this same program for the host and
 * running it natively, except for the four rows named below, which assert this
 * emulated kernel's configuration rather than the dev host's:
 *
 *   MADV_HWPOISON / MADV_SOFT_OFFLINE (100, 101) exist only with
 *   CONFIG_MEMORY_FAILURE, which this kernel does not offer -- and unlike the
 *   hints they change state, so accepting one would leave a guest waiting for
 *   a SIGBUS that cannot come. A host that has the option answers EPERM to an
 *   unprivileged caller instead of EINVAL.
 *
 *   MADV_GUARD_INSTALL / MADV_GUARD_REMOVE (102, 103) are 6.13, later than the
 *   6.1 this kernel advertises through uname; a current host takes them.
 *
 * Two accepted values are deliberately not given rows: MADV_REMOVE, which a
 * kernel refuses on anything but a writable shared file mapping, and
 * MADV_COLLAPSE, whose answer depends on the transparent-hugepage policy. The
 * KSM and hugepage hints do have rows and need CONFIG_KSM /
 * CONFIG_TRANSPARENT_HUGEPAGE to read 0 natively.
 *
 * Only the return values are asserted: the fixture is about which advice
 * values are taken, not about what each one does. What MADV_DONTNEED and
 * MADV_FREE do to the pages is tests/c/madvise.c's subject, and the range
 * checks themselves are tests/fixtures/madvhole.c's. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Named here rather than taken from the build host's headers: the guest
 * sysroot need not know the newer ones, and the invalid values have no name
 * anywhere. */
#define A_NORMAL            0
#define A_RANDOM            1
#define A_SEQUENTIAL        2
#define A_WILLNEED          3
#define A_DONTNEED          4
#define A_FREE              8
#define A_DONTFORK          10
#define A_DOFORK            11
#define A_MERGEABLE         12
#define A_UNMERGEABLE       13
#define A_HUGEPAGE          14
#define A_NOHUGEPAGE        15
#define A_DONTDUMP          16
#define A_DODUMP            17
#define A_WIPEONFORK        18
#define A_KEEPONFORK        19
#define A_COLD              20
#define A_PAGEOUT           21
#define A_POPULATE_READ     22
#define A_POPULATE_WRITE    23
#define A_DONTNEED_LOCKED   24
#define A_HWPOISON          100
#define A_SOFT_OFFLINE      101
#define A_GUARD_INSTALL     102
#define A_GUARD_REMOVE      103

static size_t pg;

static long adv(void *p, size_t len, long a)
{
    long r = syscall(__NR_madvise, p, len, a);
    return r < 0 ? -errno : r;
}

static void row(const char *name, long r)
{
    printf("%s=%ld\n", name, r);
}

static void ok(const char *name, void *m, long a)
{
    row(name, adv(m, pg, a));
}

int main(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) { printf("no pagesize\n"); return 1; }
    pg = (size_t)ps;

    char *m = mmap(NULL, pg, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memset(m, 'x', pg);

    /* The hint values, all taken. */
    ok("normal", m, A_NORMAL);
    ok("random", m, A_RANDOM);
    ok("sequential", m, A_SEQUENTIAL);
    ok("willneed", m, A_WILLNEED);
    ok("dontfork", m, A_DONTFORK);
    ok("dofork", m, A_DOFORK);
    ok("mergeable", m, A_MERGEABLE);
    ok("unmergeable", m, A_UNMERGEABLE);
    ok("hugepage", m, A_HUGEPAGE);
    ok("nohugepage", m, A_NOHUGEPAGE);
    ok("dontdump", m, A_DONTDUMP);
    ok("dodump", m, A_DODUMP);
    ok("wipeonfork", m, A_WIPEONFORK);
    ok("keeponfork", m, A_KEEPONFORK);
    ok("cold", m, A_COLD);
    ok("pageout", m, A_PAGEOUT);
    ok("populate_read", m, A_POPULATE_READ);
    ok("populate_write", m, A_POPULATE_WRITE);

    /* The three that discard. */
    ok("dontneed", m, A_DONTNEED);
    ok("free", m, A_FREE);
    ok("dontneed_locked", m, A_DONTNEED_LOCKED);

    /* Refused: the gaps in the numbering, the values past the last one this
     * kernel knows, and a negative one. */
    ok("gap5", m, 5);
    ok("gap6", m, 6);
    ok("gap7", m, 7);
    ok("past", m, 26);
    ok("far", m, 99);
    ok("hwpoison", m, A_HWPOISON);
    ok("soft_offline", m, A_SOFT_OFFLINE);
    ok("guard_install", m, A_GUARD_INSTALL);
    ok("guard_remove", m, A_GUARD_REMOVE);
    ok("neg", m, -1);
    ok("intmax", m, 0x7fffffff);

    /* The behaviour is judged before the range. Each bad-advice row is paired
     * with the answer the same range gives for an advice that IS valid, so
     * what the ordering costs is visible: an empty length is success and a
     * range with a hole in it is ENOMEM, but neither is reached. */
    row("ok_zerolen", adv(m, 0, A_NORMAL));
    row("bad_zerolen", adv(m, 0, 12345));

    char *h = mmap(NULL, 3 * pg, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (h == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    if (munmap(h + pg, pg) < 0) { printf("munmap failed\n"); return 1; }
    row("ok_hole", adv(h, 3 * pg, A_NORMAL));
    row("bad_hole", adv(h, 3 * pg, 12345));

    /* The high half of the register is not part of the advice. The first row
     * has to discard the page as MADV_DONTNEED, not merely be accepted. */
    memset(m, 'y', pg);
    row("hi32_dontneed", adv(m, pg, (long)0x100000004LL));
    printf("hi32_discarded=%d\n", m[0] == 0);
    row("hi32_bad", adv(m, pg, (long)0x100003039LL));
    printf("done\n");
    return 0;
}
