/* Faked network namespace + rtnetlink ack emulation (src/sys_netlink.c),
 * self-checking: qemu cannot be the oracle here, since the whole point is that
 * the emulator answers differently from the bare kernel.
 *
 * Mimics bubblewrap's loopback_setup(): unshare(CLONE_NEWNET), then configure
 * "lo" over a real NETLINK_ROUTE socket. The kernel refuses (no CAP_NET_ADMIN
 * in the host's namespace) with NLMSG_ERROR(-EPERM); the emulator must turn
 * that into a plain ack carrying the request's own sequence number.
 *
 * Prints one line per check so a failure names itself. Skips silently (with
 * the expected output) where the host hands out no netlink socket at all —
 * then the AF_UNIX fallback is in charge and synthesises its own acks, which
 * the netlink_fallback test covers. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* unshare(2), CLONE_NEWNET */
#endif
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static int nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl snl;
    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&snl, sizeof snl) < 0) { close(fd); return -1; }
    return fd;
}

/* Send a minimal RTM_NEWADDR (a reconfiguring request) and report the reply:
 * "ack" (error == 0), "eperm", another errno name, or a non-error message. */
static const char *newaddr_roundtrip(int fd, unsigned seq) {
    static char out[64];
    struct { struct nlmsghdr n; struct ifaddrmsg i; } r;
    struct sockaddr_nl snl;
    char buf[4096];

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    memset(&r, 0, sizeof r);
    r.n.nlmsg_len = NLMSG_LENGTH(sizeof r.i);
    r.n.nlmsg_type = RTM_NEWADDR;
    r.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    r.n.nlmsg_seq = seq;
    r.i.ifa_family = AF_INET;
    r.i.ifa_prefixlen = 8;
    r.i.ifa_index = 1;                       /* loopback is always index 1 */

    if (sendto(fd, &r, r.n.nlmsg_len, 0, (struct sockaddr *)&snl, sizeof snl) < 0)
        return "sendfail";
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    if (n < 0) return "recvfail";
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    if ((size_t)n < NLMSG_HDRLEN || h->nlmsg_type != NLMSG_ERROR) return "nonerror";
    if (h->nlmsg_seq != seq) return "badseq";
    struct nlmsgerr *e = NLMSG_DATA(h);
    if (e->error == 0) return "ack";
    snprintf(out, sizeof out, "err%d", -e->error);
    return out;
}

int main(void) {
    int fd = nl_open();
    if (fd < 0) {   /* no real netlink here: the AF_UNIX fallback answers */
        printf("no_netns=skip\nunshare=1\nafter_netns=skip\nquery=skip\n");
        return 0;
    }

    /* Before any unshare: a refusal must reach the caller untouched. The host
     * may legitimately allow this (running as root), so accept either, but
     * never an ack that the emulator invented -- that is the bug this guards. */
    const char *before = newaddr_roundtrip(fd, 1001);
    printf("no_netns=%s\n", strcmp(before, "ack") == 0 ? "acked" : "passed-through");
    close(fd);

    printf("unshare=%d\n", unshare(CLONE_NEWNET) == 0);

    /* After the faked unshare, the same refusal must come back as an ack. */
    fd = nl_open();
    if (fd < 0) { printf("after_netns=skip\nquery=skip\n"); return 0; }
    const char *after = newaddr_roundtrip(fd, 1002);
    printf("after_netns=%s\n", strcmp(after, "ack") == 0 ? "ack" : after);

    /* A query (RTM_GET*) is not a reconfiguration: it must still deliver real
     * data from the host's namespace, not a synthesised ack. */
    struct { struct nlmsghdr n; struct ifaddrmsg i; } q;
    struct sockaddr_nl snl;
    char buf[8192];
    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    memset(&q, 0, sizeof q);
    q.n.nlmsg_len = NLMSG_LENGTH(sizeof q.i);
    q.n.nlmsg_type = RTM_GETADDR;
    q.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    q.n.nlmsg_seq = 1003;
    q.i.ifa_family = AF_INET;
    if (sendto(fd, &q, q.n.nlmsg_len, 0, (struct sockaddr *)&snl, sizeof snl) < 0) {
        printf("query=sendfail\n");
        return 0;
    }
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    printf("query=%s\n",
           n > 0 && h->nlmsg_type == RTM_NEWADDR ? "data" :
           n > 0 && h->nlmsg_type == NLMSG_DONE  ? "data" : "broken");
    return 0;
}
