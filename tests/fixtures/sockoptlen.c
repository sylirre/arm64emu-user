/* setsockopt's optlen is an int, and the guest passes it in a 64-bit register.
 *
 * Self-checking: qemu-user never hands optlen to the host at all -- it decodes
 * each option it knows and re-issues it with a length of its own -- so it
 * answers 0 where a kernel answers EINVAL, and is no oracle for any of this.
 * The expectations below are the kernel's, measured against one.
 *
 * do_sock_setsockopt takes the register as an `int`: the high half is dropped,
 * and only then is a negative value refused with EINVAL. Both halves of that
 * matter to an emulator, which has to stage the option value in memory of its
 * own before it can pass it on:
 *
 *   - reading the register as a size_t and refusing anything too big to stage
 *     turned a length whose high bits are set -- but whose int value is an
 *     ordinary 8 KB -- into EINVAL, on a 64-bit host by size and on a 32-bit
 *     one by nothing but where the truncation happened to fall;
 *   - and an 8 KB option value is not too big for a kernel in the first place.
 *
 * SO_REUSEADDR is the subject because it reads only the first four bytes of
 * whatever it is given and ignores the rest, so the length is the only thing
 * under test. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The raw syscall, not the libc wrapper: the wrapper's parameter is a
 * socklen_t and would truncate the value before the kernel ever saw it. */
static int set_reuse(int fd, void *p, unsigned long len) {
    long r = syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_REUSEADDR, p, len);
    return r < 0 ? -errno : (int)r;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        printf("socketpair=-%d\n", errno);
        return 1;
    }
    static char opt[8192];
    memset(opt, 0, sizeof opt);
    opt[0] = 1;

    printf("plain=%d\n", set_reuse(sv[0], opt, sizeof opt));
    printf("hi32=%d\n", set_reuse(sv[0], opt, 0x100002000UL));
    printf("hi32_zero=%d\n", set_reuse(sv[0], opt, 0x100000000UL));
    printf("neg=%d\n", set_reuse(sv[0], opt, (unsigned long)(long)-4));
    printf("neg_min=%d\n", set_reuse(sv[0], opt, (unsigned long)(long)-1));

    /* And the option really was set by the accepted ones. */
    int val = 0;
    socklen_t vl = sizeof val;
    int r = getsockopt(sv[0], SOL_SOCKET, SO_REUSEADDR, &val, &vl);
    printf("get=%d on=%d len=%u\n", r ? -errno : 0, val != 0, vl);

    close(sv[0]);
    close(sv[1]);
    return 0;
}
