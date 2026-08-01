/* SIOCGIFHWADDR on loopback. Split out of ifreq.c because this is the one
 * interface query a host can refuse: Android denies it to an unprivileged app,
 * and denies /sys/class/net too, so on such a host the oracle gets EPERM while
 * the emulator answers from its own synthesis -- a difference in the host's
 * permissions, not in the emulator. Hence the marker below, which skips this
 * where the oracle cannot perform the ioctl at all.
 *
 * What is being pinned is that the answer is the *kernel's* answer. Every Linux
 * reports loopback as ARPHRD_LOOPBACK (772) with an all-zero address, which is
 * why the emulator fills that in for lo whatever the host will say -- and why
 * it must report a refusal, rather than a zeroed sockaddr, for a real interface
 * whose address the host would not reveal. Returning success with sa_family 0
 * is a value no kernel produces and a guest cannot tell from a real one.
 *
 * NEEDS-HOST-IOCTL: SIOCGIFHWADDR */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { puts("no-socket"); return 0; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "lo");
    if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
        int zero = 1;
        for (int i = 0; i < 6; i++)
            if (ifr.ifr_hwaddr.sa_data[i]) zero = 0;
        printf("hwfam=%d hwzero=%d\n", ifr.ifr_hwaddr.sa_family, zero);
    }

    /* A name no host has: the errno must be the kernel's ENODEV, not a
     * successful lookup of nothing. */
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "nosuchif0");
    printf("absent=%d\n", ioctl(s, SIOCGIFHWADDR, &ifr) == 0);
    return 0;
}
