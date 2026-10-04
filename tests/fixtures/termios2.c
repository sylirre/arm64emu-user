/* The termios2 ioctls -- TCGETS2 0x802c542a, TCSETS2 0x402c542b, TCSETSW2
 * 0x402c542c, TCSETSF2 0x402c542d (src/sys_file.c ioctl_tab), self-checking.
 *
 * They carry a 44-byte struct termios2: the 36-byte termios plus c_ispeed and
 * c_ospeed, the way a terminal is given a rate no Bnnn constant names. The
 * layout is the same on every host the emulator runs on, so the commands go to
 * the host's tty as they stand. They were not whitelisted at all -- "unhandled
 * ioctl 0x802c542a" and an ENOTTY for any guest whose libc reads a terminal
 * with them (glibc's tcgetattr does in new releases) -- so such a program saw
 * no terminal where there was one.
 *
 * What is asked, over a real pty: the whole struct comes back and not a byte
 * past it (a canary after it), the first 36 bytes of it are what TCGETS
 * reports, each of the three setters carries all 44 bytes in (c_ospeed
 * included, a different rate each: a copy that stopped at 36 would leave it 0)
 * and the next TCGETS2 returns the rate and the VMIN/VTIME it was given,
 * an unmapped buffer is EFAULT both ways, and a descriptor that is no tty is
 * ENOTTY.
 *
 * qemu-user has no TCGETS2 in its ioctl table and answers ENOTTY, so it cannot
 * be the oracle (the C tests are) and it cannot host the emulator either:
 * NEEDS-HOST-SYSCALL: tcgets2
 * A host that has a kernel but refuses the ioctl on a pty -- an SELinux policy
 * that whitelists a slave's ioctls -- steps aside with a lone SKIP line. The
 * expected output is what this program prints built for the host and run on a
 * real kernel. */
#define _XOPEN_SOURCE 600
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define T_GETS   0x5401UL
#define T_GETS2  0x802c542aUL
#define T_SETS2  0x402c542bUL
#define T_SETSW2 0x402c542cUL
#define T_SETSF2 0x402c542dUL
#define T_CBAUD  0x100fU                   /* the rate field of c_cflag */
#define T_BOTHER 0x1000U                   /* ... holding "the rate is in c_ospeed" */

struct t2 {                                 /* kernel struct termios2 */
    unsigned c_iflag, c_oflag, c_cflag, c_lflag;
    unsigned char c_line, c_cc[19];
    unsigned c_ispeed, c_ospeed;
};

/* A termios2 with 8 bytes after it that nothing may write. */
struct guarded {
    struct t2 t;
    unsigned char tail[8];
};

static void poison(struct guarded *g) {
    memset(&g->t, 0xa5, sizeof g->t);
    memset(g->tail, 0x5a, sizeof g->tail);
}

static int tail_ok(const struct guarded *g) {
    for (unsigned i = 0; i < sizeof g->tail; i++)
        if (g->tail[i] != 0x5a) return 0;
    return 1;
}

/* One setter, then the read-back that must be what it was given. */
static void set_and_check(const char *name, unsigned long cmd, int s, struct guarded *g,
                          unsigned speed, unsigned vmin, unsigned vtime) {
    g->t.c_cflag = (g->t.c_cflag & ~T_CBAUD) | T_BOTHER;
    g->t.c_ispeed = speed;                  /* the kernel makes the input rate follow */
    g->t.c_ospeed = speed;                  /* the output one unless CIBAUD says else */
    g->t.c_cc[6] = (unsigned char)vmin;     /* VMIN */
    g->t.c_cc[5] = (unsigned char)vtime;    /* VTIME */
    errno = 0;
    int r = ioctl(s, cmd, &g->t);
    int e = r < 0 ? errno : 0;
    struct guarded b;
    poison(&b);
    int r2 = ioctl(s, T_GETS2, &b.t);
    int same = r2 == 0 && tail_ok(&b) &&
               b.t.c_ospeed == speed &&
               b.t.c_cc[6] == vmin && b.t.c_cc[5] == vtime &&
               (b.t.c_cflag & T_CBAUD) == T_BOTHER;
    printf("%s=%d errno=%d readback=%d\n", name, r, e, same);
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) != 0 || unlockpt(m) != 0) { puts("SKIP: no pty"); return 0; }
    char *sn = ptsname(m);
    int s = sn ? open(sn, O_RDWR | O_NOCTTY) : -1;
    if (s < 0) { puts("SKIP: no pty"); return 0; }

    struct guarded g;
    poison(&g);
    errno = 0;
    int r = ioctl(s, T_GETS2, &g.t);
    if (r < 0 && errno == EACCES) { puts("SKIP: the host refuses TCGETS2 on a pty (EACCES)"); return 0; }
    int e = r < 0 ? errno : 0;
    /* Every byte of the struct is written, the speeds (offsets 36..43) too. */
    int whole = r == 0 && g.t.c_ispeed != 0xa5a5a5a5u && g.t.c_ospeed != 0xa5a5a5a5u &&
                g.t.c_line != 0xa5;

    unsigned char old[36 + 8];
    memset(old, 0x5a, sizeof old);
    int r1 = ioctl(s, T_GETS, old);
    int prefix = r == 0 && r1 == 0 && memcmp(old, &g.t, 36) == 0;
    printf("get2=%d errno=%d whole=%d tail=%d prefix=%d\n", r, e, whole, tail_ok(&g), prefix);
    if (r < 0) return 0;

    set_and_check("set2", T_SETS2, s, &g, 123456, 7, 3);
    set_and_check("setsw2", T_SETSW2, s, &g, 230400, 5, 2);
    set_and_check("setsf2", T_SETSF2, s, &g, 345678, 9, 4);

    errno = 0;
    r = ioctl(s, T_GETS2, (void *)0);
    printf("get2_fault=%d errno=%d\n", r, r < 0 ? errno : 0);
    errno = 0;
    r = ioctl(s, T_SETS2, (void *)0);
    printf("set2_fault=%d errno=%d\n", r, r < 0 ? errno : 0);

    int p[2];
    if (pipe(p)) return 1;
    errno = 0;
    r = ioctl(p[0], T_GETS2, &g.t);
    printf("pipe=%d errno=%d\n", r, r < 0 ? errno : 0);

    puts("done");
    return 0;
}
