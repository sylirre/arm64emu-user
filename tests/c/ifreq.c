/* SIOCGIF* interface-query ioctls used by ifconfig / net-tools. The reported
 * bug was "unhandled ioctl 0x8912" (SIOCGIFCONF) and "0x8913" (SIOCGIFFLAGS):
 * arm64chroot must answer the read-only interface-query family from the host's
 * own interface table instead of warning and returning -ENOTTY. Differential vs
 * qemu-aarch64, scoped to the loopback interface -- identical on every Linux
 * host (index 1, 127.0.0.1/8, a versioned MTU constant, ARPHRD_LOOPBACK) so both worlds match
 * byte for byte. Tests run with rootfs "/", so the emulator's getifaddrs sees
 * the same host "lo" the kernel hands qemu. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static const char *a4(struct sockaddr *sa) {
    struct sockaddr_in *si = (struct sockaddr_in *) sa;
    return inet_ntoa(si->sin_addr);
}

static void set_lo(struct ifreq *ifr) {
    memset(ifr, 0, sizeof *ifr);
    strcpy(ifr->ifr_name, "lo");
}

int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { puts("no-socket"); return 0; }
    struct ifreq ifr;

    set_lo(&ifr);
    if (ioctl(s, SIOCGIFINDEX, &ifr) == 0)
        printf("index=%d\n", ifr.ifr_ifindex);

    set_lo(&ifr);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0)
        printf("flags=0x%x\n", ifr.ifr_flags & (IFF_UP | IFF_LOOPBACK | IFF_RUNNING));

    set_lo(&ifr);
    if (ioctl(s, SIOCGIFADDR, &ifr) == 0)
        printf("addr=%s\n", a4(&ifr.ifr_addr));

    set_lo(&ifr);
    if (ioctl(s, SIOCGIFNETMASK, &ifr) == 0)
        printf("mask=%s\n", a4(&ifr.ifr_netmask));

    set_lo(&ifr);
    if (ioctl(s, SIOCGIFMTU, &ifr) == 0)
        /* Loopback's MTU is a kernel constant, but a versioned one: 65536
         * since 3.12, 16436 before. Assert it is one of the two so a recorded
         * oracle from a modern host still referees an old-kernel replay. */
        printf("mtu_ok=%d\n", ifr.ifr_mtu == 65536 || ifr.ifr_mtu == 16436);

    /* SIOCGIFHWADDR lives in ifhwaddr.c: it is the one query in this family a
     * host can deny (Android does), and there the oracle fails while we answer,
     * so it needs a gate the rest of these do not. */

    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_ifindex = 1;
    if (ioctl(s, SIOCGIFNAME, &ifr) == 0)
        printf("name=%s\n", ifr.ifr_name);

    /* SIOCGIFCONF: locate "lo" in the returned array, print its address. */
    char buf[2048];
    struct ifconf ifc;
    memset(&ifc, 0, sizeof ifc);
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = buf;
    if (ioctl(s, SIOCGIFCONF, &ifc) == 0) {
        struct ifreq *r = (struct ifreq *) buf;
        int n = ifc.ifc_len / (int) sizeof(struct ifreq);
        for (int i = 0; i < n; i++)
            if (strcmp(r[i].ifr_name, "lo") == 0) {
                printf("conf-lo=%s\n", a4(&r[i].ifr_addr));
                break;
            }
    }

    close(s);
    return 0;
}
