/* readlinkat's bufsiz is an int, judged before the path is looked at: zero
 * and every negative value are EINVAL, and the high half of the register is
 * dropped first. Read as a 64-bit count, -5 was a request the emulator
 * honoured -- it copied the whole target over a buffer the caller had sized
 * for nothing -- and the guest died of its own stack protector. Self-
 * checking because qemu-user answers EFAULT for the negative rows (its
 * user-memory lock fails on the enormous length); the values are a real
 * kernel's. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long rl(int dfd, const char *path, char *buf, long bufsiz) {
    long r = syscall(SYS_readlinkat, dfd, path, buf, bufsiz);
    return r < 0 ? -errno : r;
}

int main(void) {
    char dir[] = "/tmp/rlszXXXXXX";
    if (!mkdtemp(dir)) { printf("SKIP: no /tmp\n"); return 0; }
    char link[64];
    snprintf(link, sizeof link, "%s/l", dir);
    if (symlink("/target/of/link", link) < 0) { printf("symlink failed\n"); return 1; }
    char nolink[64];
    snprintf(nolink, sizeof nolink, "%s/nolink", dir);

    /* A buffer the guard bytes around would catch an overrun of. */
    char buf[64];
    memset(buf, 'G', sizeof buf);
    printf("neg=%ld guard=%d\n", rl(AT_FDCWD, link, buf, -5), buf[0] == 'G');
    printf("zero=%ld guard=%d\n", rl(AT_FDCWD, link, buf, 0), buf[0] == 'G');
    printf("intmin=%ld\n", rl(AT_FDCWD, link, buf, (long)-2147483648L));
    /* The high half is dropped before the sign is judged: 1<<32 is zero and
     * (1<<32)+1 a one-byte buffer. */
    printf("hi32_zero=%ld\n", rl(AT_FDCWD, link, buf, 1L << 32));
    long r = rl(AT_FDCWD, link, buf, (1L << 32) + 1);
    printf("hi32_one=%ld %c\n", r, r == 1 ? buf[0] : '?');
    /* Before the path: a missing link with a bad size is EINVAL, not ENOENT,
     * and a null buffer with a bad size never reaches the copy. */
    printf("neg_missing=%ld\n", rl(AT_FDCWD, nolink, buf, -1));
    printf("neg_null=%ld\n", rl(AT_FDCWD, link, NULL, -1));
    printf("zero_missing=%ld\n", rl(AT_FDCWD, nolink, buf, 0));
    /* The empty-path form on an O_PATH fd is judged the same way. */
    int lfd = open(link, O_PATH | O_NOFOLLOW);
    printf("empty_neg=%ld\n", lfd < 0 ? -errno : rl(lfd, "", buf, -3));
    printf("empty_zero=%ld\n", lfd < 0 ? -errno : rl(lfd, "", buf, 0));
    r = lfd < 0 ? -errno : rl(lfd, "", buf, 4);
    printf("empty_four=%ld %.4s\n", r, r == 4 ? buf : "?");
    /* Ordinary truncation still holds. */
    memset(buf, 0, sizeof buf);
    r = rl(AT_FDCWD, link, buf, 7);
    printf("seven=%ld %s\n", r, buf);
    r = rl(AT_FDCWD, link, buf, sizeof buf);
    printf("full=%ld %s\n", r, buf);
    if (lfd >= 0) close(lfd);
    unlink(link); rmdir(dir);
    printf("done\n");
    return 0;
}
