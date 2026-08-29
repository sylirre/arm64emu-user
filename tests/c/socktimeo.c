/* SO_RCVTIMEO/SO_SNDTIMEO carry a struct timeval: 16 bytes in the guest's
 * LP64 ABI but 8 in an ILP32 host's old-style one -- and a time64 32-bit
 * libc (musl 1.2+) renumbers the option outright. The emulator re-issues
 * these two options through the host libc's own macro and struct, so the
 * roundtrip and the timed recv below behave identically on every host tier
 * (LP64 hosts were already right by identity; the ILP32 build is what this
 * test exercises, via make test32).
 *
 * NEEDS-HOST-SYSCALL: sockopt-timeo
 * The ILP32 build is exercised under qemu-user, whose getsockopt answers
 * optlen 4 for this option and writes nothing at all -- so the value the
 * emulator has to convert never arrives, and no emulator change can conjure
 * it. See hostenv.sh; on real ARM32 silicon the probe passes and this runs.
 *
 * NEEDS-ORACLE: so_rcvtimeo
 * The same qemu build that cannot syncfs (see tests/c/mfdsync.c) also loses
 * this roundtrip: set 1.252 s, read back zeroes and a zero length, where the
 * host kernel hands the timeval straight back -- measured natively beside the
 * emulator, which matches the kernel. The marker is the fallback explanation;
 * a host CPU that can re-run the reference arbitrates first. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval tv = { 1, 250000 };
    printf("set_rcv=%d\n",
           setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) ? -errno : 0);
    struct timeval got;
    socklen_t gl = sizeof got;
    memset(&got, 0, sizeof got);
    printf("get_rcv=%d sec=%ld usec=%ld len=%u\n",
           getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &got, &gl) ? -errno : 0,
           (long)got.tv_sec, (long)got.tv_usec, (unsigned)gl);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0) {
        printf("bind=-%d\n", errno);   /* no loopback in this sandbox: agree on it */
        return 0;
    }
    char b[4];
    int r = (int)recv(s, b, sizeof b, 0);   /* empty socket: returns after ~1.25s */
    printf("recv_timeout=%d\n", r < 0 ? -errno : r);
    printf("short_len=%d\n",
           setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, 8) ? -errno : 0);
    struct timeval bad = { 0, 2000000 };
    printf("bad_usec=%d\n",
           setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &bad, sizeof bad) ? -errno : 0);
    close(s);
    return 0;
}
