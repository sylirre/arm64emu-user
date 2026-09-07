/* SO_GET_FILTER: reading an attached classic-BPF program back.
 *
 * Self-checking: qemu-user answers EINVAL for the option, so it is no oracle
 * here; the expectations below are the kernel's own, measured against one.
 *
 * The option's contract is the point of the test. sk_get_filter takes the
 * caller's optlen as a BYTE count, compares it against the program's
 * INSTRUCTION count, then copies the whole program -- eight bytes per
 * instruction, however small the byte length was -- and reports the
 * instruction count back through optlen. So the caller's length bounds
 * nothing, and an emulator that staged the answer in a fixed 4 KB buffer had
 * its own stack written over by a program of more than 512 instructions.
 * 600 is deliberately on the far side of that.
 *
 * A socketpair is used rather than a UDP socket so the test needs no network
 * of any kind, and its second end doubles as the "no filter attached" case. */
#include <errno.h>
#include <linux/filter.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NINS 600
#define PROGB (NINS * (int)sizeof(struct sock_filter))

static struct sock_filter prog[NINS];
static unsigned char buf[BPF_MAXINSNS * sizeof(struct sock_filter)];

/* Bytes of `buf` the kernel touched, counting from the top of what it left
 * poisoned: 0 means it wrote nothing at all. */
static size_t written(void) {
    size_t hi = 0;
    for (size_t i = 0; i < sizeof buf; i++)
        if (buf[i] != 0xAA) hi = i + 1;
    return hi;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        printf("socketpair=-%d\n", errno);
        return 0;
    }
    for (int i = 0; i < NINS - 1; i++) {   /* A = i */
        prog[i].code = 0x00;               /* BPF_LD | BPF_W | BPF_IMM */
        prog[i].k = (unsigned)i;
    }
    prog[NINS - 1].code = 0x06;            /* BPF_RET | BPF_K */
    prog[NINS - 1].k = 0xffffffff;
    struct sock_fprog fp = { NINS, prog };
    printf("attach=%d\n",
           setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof fp)
               ? -errno : 0);

    /* An optlen of 0 asks only how many instructions there are: the count comes
     * back through optlen and not a byte is written. */
    memset(buf, 0xAA, sizeof buf);
    socklen_t l = 0;
    int r = getsockopt(sv[0], SOL_SOCKET, SO_GET_FILTER, buf, &l);
    printf("count=%d len=%u wrote=%zu\n", r ? -errno : 0, l, written());

    /* An optlen equal to the instruction COUNT is what the kernel accepts as
     * "big enough", and it then writes eight times that many bytes. */
    memset(buf, 0xAA, sizeof buf);
    l = NINS;
    r = getsockopt(sv[0], SOL_SOCKET, SO_GET_FILTER, buf, &l);
    printf("short=%d len=%u wrote=%zu match=%d\n", r ? -errno : 0, l, written(),
           written() == PROGB && memcmp(buf, prog, PROGB) == 0);

    /* And an optlen sized in bytes, the way a caller means it, answers the
     * same. */
    memset(buf, 0xAA, sizeof buf);
    l = PROGB;
    r = getsockopt(sv[0], SOL_SOCKET, SO_GET_FILTER, buf, &l);
    printf("full=%d len=%u wrote=%zu match=%d\n", r ? -errno : 0, l, written(),
           written() == PROGB && memcmp(buf, prog, PROGB) == 0);

    /* The other end never had a filter: a zero count, and nothing written. */
    memset(buf, 0xAA, sizeof buf);
    l = PROGB;
    r = getsockopt(sv[1], SOL_SOCKET, SO_GET_FILTER, buf, &l);
    printf("none=%d len=%u wrote=%zu\n", r ? -errno : 0, l, written());

    close(sv[0]);
    close(sv[1]);
    return 0;
}
