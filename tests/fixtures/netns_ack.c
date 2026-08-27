/* Faked network namespace + rtnetlink ack emulation (src/sys_netlink.c),
 * self-checking: qemu cannot be the oracle here, since the whole point is that
 * the emulator answers differently from the bare kernel.
 *
 * Mimics bubblewrap's loopback_setup(): unshare(CLONE_NEWNET), then configure
 * "lo" over a real NETLINK_ROUTE socket. The kernel refuses (no CAP_NET_ADMIN
 * in the host's namespace) with NLMSG_ERROR(-EPERM); the emulator must turn
 * that into a plain ack carrying the request's own sequence number.
 *
 * The socket-shaped checks (empty=, self=, src=) are the ones a guest could
 * use to tell the two tiers apart, so they must answer the same whether a real
 * netlink socket or the AF_UNIX substitute is underneath: an empty receive
 * queue reports EAGAIN rather than a zero-length message (which rtnetlink never
 * delivers, and which strands every caller that reads a dump until NLMSG_DONE),
 * a reply names the kernel as its sender, and the socket names itself.
 *
 * Prints one line per check so a failure names itself. Skips silently (with
 * the expected output) where the host hands out no netlink socket at all —
 * then the AF_UNIX fallback is in charge and synthesises its own acks, which
 * the af_unix tier of this same test covers. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* unshare(2), CLONE_NEWNET */
#endif
#include <errno.h>
#include <poll.h>
#include <sys/mman.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
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

/* An empty receive queue must report EAGAIN, never a zero-length message: a
 * caller reading a dump can make no progress on one, so it either spins on the
 * socket or (musl) abandons the dump as broken. */
static const char *empty_read(int fd) {
    static char out[64];
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);

    if (n == 0) return "zerolen";
    if (n > 0) return "data";                /* nothing was ever requested */
    if (errno == EAGAIN || errno == EWOULDBLOCK) return "eagain";
    snprintf(out, sizeof out, "err%d", errno);
    return out;
}

/* A netlink socket names itself with the port id the kernel gave it, in a
 * sockaddr_nl of the full length (iproute2 rejects anything shorter with
 * "Wrong address length"). Port id 0 is the kernel's own and never a socket's. */
static const char *sockname(int fd) {
    static char out[64];
    struct sockaddr_nl snl;
    socklen_t sl = sizeof snl;

    memset(&snl, 0, sizeof snl);
    if (getsockname(fd, (struct sockaddr *)&snl, &sl) < 0) return "fail";
    if (sl != sizeof snl) { snprintf(out, sizeof out, "len%u", sl); return out; }
    if (snl.nl_family != AF_NETLINK) return "family";
    return snl.nl_pid != 0 ? "own" : "kernel";
}

/* Is @fd readable right now, according to each of the three mechanisms a guest
 * can ask with? They must agree with each other and with whether a reply is
 * actually waiting -- a synthesised one lives in the emulator, where none of
 * them can see it, so the substitute socket has to carry the readiness itself.
 * Returns a 3-bit set so a disagreement names the odd one out. */
static int readable(int fd, int ep) {
    struct pollfd p = { fd, POLLIN, 0 };
    fd_set rs;
    struct timeval tv = { 0, 0 };
    struct epoll_event ev;
    int bits = 0;

    if (poll(&p, 1, 0) == 1 && (p.revents & POLLIN)) bits |= 1;
    FD_ZERO(&rs);
    FD_SET(fd, &rs);
    if (select(fd + 1, &rs, NULL, NULL, &tv) == 1 && FD_ISSET(fd, &rs)) bits |= 2;
    if (epoll_wait(ep, &ev, 1, 0) == 1) bits |= 4;
    return bits;
}

/* Ask for a dump, then wait to be told the reply arrived before reading it --
 * the shape that hangs when readiness isn't reported. Reports what each stage
 * saw: idle (nothing asked) -> pending -> consumed, then the wait-then-read. */
static const char *readiness_cycle(int fd) {
    static char out[96];
    struct { struct nlmsghdr n; struct rtgenmsg g; } req;
    struct sockaddr_nl snl;
    char buf[8192];
    int idle, pending, consumed, ep;

    ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) return "noepoll";
    struct epoll_event add = { .events = EPOLLIN, .data.fd = fd };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &add) < 0) { close(ep); return "noctl"; }

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    memset(&req, 0, sizeof req);
    req.n.nlmsg_len = sizeof req;
    req.n.nlmsg_type = RTM_GETADDR;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_seq = 1005;
    req.g.rtgen_family = AF_INET;

    idle = readable(fd, ep);            /* nothing asked for yet */
    if (sendto(fd, &req, sizeof req, 0, (struct sockaddr *)&snl, sizeof snl) < 0) {
        close(ep);
        return "sendfail";
    }
    pending = readable(fd, ep);         /* a reply is waiting */
    /* Drain it all: a real kernel may split a dump across datagrams, and both
     * tiers must end up with nothing left to report. */
    while (recv(fd, buf, sizeof buf, MSG_DONTWAIT) > 0)
        ;
    consumed = readable(fd, ep);        /* nothing left */

    if (idle != 0 || pending != 7 || consumed != 0) {
        snprintf(out, sizeof out, "idle%d/pending%d/consumed%d",
                 idle, pending, consumed);
        close(ep);
        return out;
    }

    /* Now the shape itself: wait for the reply, then take it. A tier that
     * can't report readiness times out here instead of answering. */
    if (sendto(fd, &req, sizeof req, 0, (struct sockaddr *)&snl, sizeof snl) < 0) {
        close(ep);
        return "sendfail2";
    }
    struct pollfd p = { fd, POLLIN, 0 };
    int r = poll(&p, 1, 5000);
    close(ep);
    if (r != 1 || !(p.revents & POLLIN)) return "timeout";
    return recv(fd, buf, sizeof buf, 0) > 0 ? "ok" : "empty";
}

/* Walk a dump the way fastfetch's default-route lookup does: stop reading a
 * datagram the moment the wanted entry turns up, then keep reading until
 * NLMSG_DONE ends the loop. The terminator has to arrive in a datagram the
 * caller has not already walked past, which is why the kernel closes a dump
 * with one of its own -- hand the whole reply back at once and the read that
 * follows finds nothing and blocks. Bounded by a poll timeout so a regression
 * reports itself instead of wedging the suite. */
static const char *dump_walk(int fd) {
    struct { struct nlmsghdr n; struct rtgenmsg g; } req;
    struct sockaddr_nl snl;
    char buf[8192];
    int round, found = 0;

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    memset(&req, 0, sizeof req);
    req.n.nlmsg_len = sizeof req;
    req.n.nlmsg_type = RTM_GETADDR;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_seq = 1006;
    req.g.rtgen_family = AF_INET;
    if (sendto(fd, &req, sizeof req, 0, (struct sockaddr *)&snl, sizeof snl) < 0)
        return "sendfail";

    for (round = 0; round < 16; round++) {
        struct pollfd p = { fd, POLLIN, 0 };
        ssize_t n;

        if (poll(&p, 1, 5000) != 1) return "hang";
        n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) return "recvfail";
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE)
                return found ? "ok" : "nodata";
            if (h->nlmsg_type == NLMSG_ERROR)
                return "error";
            found = 1;
            break;            /* stop mid-datagram, as fastfetch does */
        }
    }
    return "noend";
}

/* Send a minimal RTM_NEWADDR (a reconfiguring request) and report the reply:
 * "ack" (error == 0), "eperm", another errno name, or a non-error message.
 * @src_pid takes the port id the reply claims to come from. */
static const char *newaddr_roundtrip(int fd, unsigned seq, unsigned *src_pid) {
    static char out[64];
    struct { struct nlmsghdr n; struct ifaddrmsg i; } r;
    struct sockaddr_nl snl;
    socklen_t sl = sizeof snl;
    char buf[4096];

    *src_pid = (unsigned)-1;
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
    memset(&snl, 0, sizeof snl);
    ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&snl, &sl);
    if (n < 0) return "recvfail";
    if (sl >= sizeof snl && snl.nl_family == AF_NETLINK) *src_pid = snl.nl_pid;
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    if ((size_t)n < NLMSG_HDRLEN || h->nlmsg_type != NLMSG_ERROR) return "nonerror";
    if (h->nlmsg_seq != seq) return "badseq";
    struct nlmsgerr *e = NLMSG_DATA(h);
    if (e->error == 0) return "ack";
    snprintf(out, sizeof out, "err%d", -e->error);
    return out;
}

/* One request out via sendmmsg and one reply back via recvmmsg. */
static const char *mmsg_cycle(int fd) {
    struct { struct nlmsghdr nh; struct rtgenmsg g; } req;
    memset(&req, 0, sizeof req);
    req.nh.nlmsg_len = sizeof req;
    req.nh.nlmsg_type = RTM_GETLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 99;
    req.g.rtgen_family = AF_UNSPEC;

    struct iovec siov = { &req, sizeof req };
    struct mmsghdr smm;
    memset(&smm, 0, sizeof smm);
    smm.msg_hdr.msg_iov = &siov;
    smm.msg_hdr.msg_iovlen = 1;
    if (sendmmsg(fd, &smm, 1, 0) != 1) return "sendfail";
    if (smm.msg_len != sizeof req) return "shortsend";

    static char buf[8192];
    struct iovec riov = { buf, sizeof buf };
    struct mmsghdr rmm;
    memset(&rmm, 0, sizeof rmm);
    rmm.msg_hdr.msg_iov = &riov;
    rmm.msg_hdr.msg_iovlen = 1;
    if (recvmmsg(fd, &rmm, 1, 0, NULL) != 1) return "recvfail";
    if (rmm.msg_len < sizeof(struct nlmsghdr)) return "short";
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    /* A reply, not our own request handed back. */
    if (h->nlmsg_type == RTM_GETLINK) return "echoed";
    return (h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == NLMSG_DONE)
               ? "data" : "broken";
}

/* A receive whose destination the guest cannot write is EFAULT, and the
 * datagram is gone -- what netlink_recvmsg does with an skb it could not copy
 * out (it is freed, not requeued). Reported as a short read or an empty
 * success instead, the caller reads a truncated message, or walks a dump that
 * never reaches its terminator. Both tiers must answer the same. */
static const char *fault_recv(int fd) {
    static char out[64];
    struct { struct nlmsghdr n; struct rtgenmsg g; } req;
    struct sockaddr_nl snl;
    void *bad;

    bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (bad == MAP_FAILED) return "nomap";

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    memset(&req, 0, sizeof req);
    req.n.nlmsg_len = sizeof req;
    req.n.nlmsg_type = RTM_GETADDR;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_seq = 1007;
    req.g.rtgen_family = AF_INET;
    if (sendto(fd, &req, sizeof req, 0, (struct sockaddr *)&snl, sizeof snl) < 0)
        return "sendfail";

    struct iovec iov = { bad, 64 };
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    ssize_t n = recvmsg(fd, &mh, 0);
    if (n >= 0) {
        snprintf(out, sizeof out, "delivered%d", (int)n);
        return out;
    }
    if (errno == EFAULT) return "efault";
    snprintf(out, sizeof out, "err%d", errno);
    return out;
}

/* Guest pointers a *send* cannot read. A kernel reads the msghdr, then the
 * iovec array, then the message itself out of the caller's memory before it
 * queues anything (copy_msghdr_from_user / import_iovec / netlink_sendmsg), so
 * every one of these is EFAULT with nothing sent. Read as "no segments"
 * instead, a bad pointer became a successful send of nothing -- and on the
 * substituted socket it left a synthesised reply behind for a receive that
 * should never have had one, which the final drain here is what catches. Both
 * tiers must answer the same. */
static const char *fault_send(int fd) {
    struct sockaddr_nl snl;
    struct iovec badbase;
    struct msghdr mh;
    char buf[256];
    void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (bad == MAP_FAILED) return "nomap";
    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    badbase.iov_base = bad;                  /* a readable array naming an
                                                unreadable buffer */
    badbase.iov_len = 64;

    if (write(fd, bad, 64) != -1 || errno != EFAULT) return "write";
    if (sendto(fd, bad, 64, 0, (struct sockaddr *)&snl, sizeof snl) != -1 ||
        errno != EFAULT) return "sendto";
    if (writev(fd, (struct iovec *)bad, 1) != -1 || errno != EFAULT)
        return "writev-array";
    if (writev(fd, &badbase, 1) != -1 || errno != EFAULT) return "writev-base";
    if (sendmsg(fd, (struct msghdr *)bad, 0) != -1 || errno != EFAULT)
        return "sendmsg-hdr";
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = (struct iovec *)bad;
    mh.msg_iovlen = 1;
    if (sendmsg(fd, &mh, 0) != -1 || errno != EFAULT) return "sendmsg-array";
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &badbase;
    mh.msg_iovlen = 1;
    if (sendmsg(fd, &mh, 0) != -1 || errno != EFAULT) return "sendmsg-base";

    /* Nothing went out, so nothing may be waiting to come back. */
    if (recv(fd, buf, sizeof buf, MSG_DONTWAIT) >= 0) return "queued";
    if (errno != EAGAIN && errno != EWOULDBLOCK) return "queued-err";
    return "ok";
}

/* Ask for a dump and drain whatever it produced, so the next check starts from
 * an empty queue on either tier (a real kernel may split a dump across
 * datagrams). Returns 0 on failure. */
static int ask_dump(int fd, unsigned seq) {
    struct { struct nlmsghdr n; struct rtgenmsg g; } req;
    struct sockaddr_nl snl;

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETLINK;
    memset(&req, 0, sizeof req);
    req.n.nlmsg_len = sizeof req;
    req.n.nlmsg_type = RTM_GETADDR;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_seq = seq;
    req.g.rtgen_family = AF_INET;
    return sendto(fd, &req, sizeof req, 0,
                  (struct sockaddr *)&snl, sizeof snl) == (ssize_t)sizeof req;
}

static void drain(int fd) {
    char buf[8192];
    while (recv(fd, buf, sizeof buf, MSG_DONTWAIT) > 0)
        ;
}

/* The source address a receive writes back. The datagram is delivered first and
 * the copyout fault is then the call's own result (__sys_recvfrom overwrites
 * its byte count with move_addr_to_user's error, ____sys_recvmsg the same for
 * the header) -- and the datagram is gone regardless. Reported as a success,
 * the caller reads a message it was told came from an address that was never
 * written. Both tiers must answer the same. */
static const char *fault_addr(int fd) {
    struct msghdr mh;
    struct iovec iov;
    socklen_t sl;
    char buf[8192];
    void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (bad == MAP_FAILED) return "nomap";

    if (!ask_dump(fd, 1008)) return "sendfail";
    sl = sizeof(struct sockaddr_nl);
    if (recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)bad, &sl) != -1 ||
        errno != EFAULT) return "recvfrom";
    drain(fd);

    /* A msghdr the guest cannot even read: EFAULT before anything is taken off
     * the socket, so the reply is still there afterwards. */
    if (!ask_dump(fd, 1009)) return "sendfail2";
    if (recvmsg(fd, (struct msghdr *)bad, 0) != -1 || errno != EFAULT)
        return "recvmsg-hdr";
    if (recv(fd, buf, sizeof buf, MSG_DONTWAIT) <= 0) return "consumed";
    drain(fd);

    if (!ask_dump(fd, 1010)) return "sendfail3";
    memset(&mh, 0, sizeof mh);
    iov.iov_base = buf;
    iov.iov_len = sizeof buf;
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_name = bad;
    mh.msg_namelen = sizeof(struct sockaddr_nl);
    if (recvmsg(fd, &mh, 0) != -1 || errno != EFAULT) return "recvmsg-name";
    drain(fd);
    return "ok";
}

int main(void) {
    unsigned src_pid;
    int fd = nl_open();
    if (fd < 0) {   /* no real netlink here: the AF_UNIX fallback answers */
        printf("empty=skip\nself=skip\nno_netns=skip\nunshare=1\n"
               "after_netns=skip\nsrc=skip\nquery=skip\nwrdump=skip\nready=skip\n"
               "frame=skip\nmmsg=skip\nfault=skip\nsendfault=skip\n"
               "addrfault=skip\n");
        return 0;
    }

    /* Nothing has been asked of this socket yet, so a non-blocking read must
     * find the queue empty rather than be handed a message of length zero. */
    printf("empty=%s\n", empty_read(fd));
    printf("self=%s\n", sockname(fd));

    /* Before any unshare: a refusal must reach the caller untouched. The host
     * may legitimately allow this (running as root), so accept either, but
     * never an ack that the emulator invented -- that is the bug this guards. */
    const char *before = newaddr_roundtrip(fd, 1001, &src_pid);
    printf("no_netns=%s\n", strcmp(before, "ack") == 0 ? "acked" : "passed-through");
    close(fd);

    printf("unshare=%d\n", unshare(CLONE_NEWNET) == 0);

    /* After the faked unshare, the same refusal must come back as an ack. */
    fd = nl_open();
    if (fd < 0) {
        printf("after_netns=skip\nsrc=skip\nquery=skip\nwrdump=skip\nready=skip\n"
               "frame=skip\nmmsg=skip\nfault=skip\nsendfault=skip\n"
               "addrfault=skip\n");
        return 0;
    }
    const char *after = newaddr_roundtrip(fd, 1002, &src_pid);
    printf("after_netns=%s\n", strcmp(after, "ack") == 0 ? "ack" : after);
    /* The reply comes from the kernel, which owns port id 0. Callers rely on
     * it: glibc's __netlink_request() discards a buffer whose source claims a
     * port id of its own, then reads on for a reply already delivered. */
    printf("src=%s\n", src_pid == 0 ? "kernel" :
                       src_pid == (unsigned)-1 ? "noaddr" : "self");

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
    close(fd);

    /* The same dump driven by write(2)/read(2) rather than the socket calls: a
     * netlink socket needs no destination address, so plain writes carry a
     * request just as well -- which is how busybox's `ip` sends its. The
     * AF_UNIX substitute has no such default destination and would answer
     * ENOTCONN, so these must be routed to the emulation like send/recv are. */
    fd = nl_open();
    if (fd < 0) {
        printf("wrdump=skip\nready=skip\nframe=skip\nmmsg=skip\nfault=skip\n"
               "sendfault=skip\naddrfault=skip\n");
        return 0;
    }
    struct { struct nlmsghdr n; struct rtgenmsg g; } d;
    memset(&d, 0, sizeof d);
    d.n.nlmsg_len = sizeof d;
    d.n.nlmsg_type = RTM_GETLINK;
    d.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;   /* busybox's */
    d.n.nlmsg_seq = 1004;
    d.g.rtgen_family = AF_UNSPEC;
    if (write(fd, &d, sizeof d) != (ssize_t)sizeof d) {
        printf("wrdump=writefail\n");
        return 0;
    }
    n = read(fd, buf, sizeof buf);
    printf("wrdump=%s\n",
           n > 0 && h->nlmsg_type == RTM_NEWLINK ? "data" :
           n > 0 && h->nlmsg_type == NLMSG_DONE  ? "data" : "broken");
    close(fd);

    /* Readiness: poll/select/epoll must track whether a reply is waiting, and
     * a caller must be able to wait for one before reading it. */
    fd = nl_open();
    if (fd < 0) {
        printf("ready=skip\nframe=skip\nmmsg=skip\nfault=skip\nsendfault=skip\n"
               "addrfault=skip\n");
        return 0;
    }
    printf("ready=%s\n", readiness_cycle(fd));
    close(fd);

    /* Dump framing: the terminator must arrive in a datagram of its own, or a
     * caller that stops walking early never reaches it. */
    fd = nl_open();
    if (fd < 0) {
        printf("frame=skip\nmmsg=skip\nfault=skip\nsendfault=skip\n"
               "addrfault=skip\n");
        return 0;
    }
    printf("frame=%s\n", dump_walk(fd));
    close(fd);

    /* sendmmsg/recvmmsg are sendmsg/recvmsg per element, so a substituted
     * socket has to answer them too. Going straight to the host wrote the
     * request into the AF_UNIX stand-in as opaque bytes and read them back --
     * the guest saw its own request echoed instead of a reply. */
    fd = nl_open();
    if (fd < 0) {
        printf("mmsg=skip\nfault=skip\nsendfault=skip\naddrfault=skip\n");
        return 0;
    }
    printf("mmsg=%s\n", mmsg_cycle(fd));
    close(fd);

    /* A destination the guest cannot write: EFAULT, not a silent short read. */
    fd = nl_open();
    if (fd < 0) { printf("fault=skip\nsendfault=skip\naddrfault=skip\n"); return 0; }
    printf("fault=%s\n", fault_recv(fd));
    close(fd);

    /* ...and the pointers a send reads, and the address a receive writes back:
     * a bad one must fail the call rather than become a successful empty
     * operation. */
    fd = nl_open();
    if (fd < 0) { printf("sendfault=skip\naddrfault=skip\n"); return 0; }
    printf("sendfault=%s\n", fault_send(fd));
    close(fd);

    fd = nl_open();
    if (fd < 0) { printf("addrfault=skip\n"); return 0; }
    printf("addrfault=%s\n", fault_addr(fd));
    close(fd);
    return 0;
}
