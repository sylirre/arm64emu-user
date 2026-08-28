/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* AF_NETLINK / NETLINK_ROUTE emulation. Ported from Termux PRoot's tracer-side
 * netlink shim (src/syscall/enter.c): the rtnetlink reply builders carry over
 * unchanged; the interception glue that PRoot did with peek_reg/poke_reg and a
 * two-phase enter/exit stop collapses here to ordinary handlers that read/write
 * guest memory with copy_from_guest/copy_to_guest and return the guest x0.
 *
 * Some environments deny the process a real netlink socket (Android's SELinux
 * policy on untrusted_app domains, inherited seccomp filters, hardened
 * containers); there socket() substitutes an AF_UNIX/SOCK_DGRAM socket and the
 * handlers below synthesise responses: NLMSG_ERROR(err=0) for non-dump requests
 * (bubblewrap's loopback_setup RTM_NEWADDR/RTM_NEWLINK) and real host interfaces
 * (via getifaddrs) or an empty NLMSG_DONE for dumps (glibc/apt getifaddrs
 * RTM_GETADDR, iproute2 RTM_GETLINK/RTM_GETROUTE). The substitution only fires
 * when the host actually refuses AF_NETLINK, so ordinary users (c-ares, dnf,
 * getaddrinfo) keep a real netlink socket when one is available.
 *
 * The substitute socket is never written to -- a send only records the reply it
 * should draw -- so its own receive queue stands in for "the kernel has nothing
 * more to say": a receive with no synthesised reply pending is left to the real
 * syscall, which waits or reports EAGAIN there. Answering it here instead would
 * mean a zero-length datagram, which rtnetlink never delivers. */
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#include "guest_abi.h"
#include "sys.h"
#include "sys_netlink.h"

/* ABI-stable rtnetlink constants for the synthesised replies. Defined locally
 * so we needn't pull in <linux/if.h> / <linux/if_arp.h>, which clash with the
 * already-included <net/if.h>. */
#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK 772
#endif
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

/* Per-fd reply buffer capacity (matches PRoot's MAX_FAKE_NETLINK_REPLY). The
 * builders cap each appended message and always leave room for NLMSG_DONE. */
#define NL_REPLY_MAX 8192

/* Guards the m->nl_fds table and the per-fd reply buffers (guest threads share
 * one struct Machine; netlink use is rare and short, so a single lock is fine). */
static pthread_mutex_t nl_lock = PTHREAD_MUTEX_INITIALIZER;

/* Fork safety, as in mem.c: prepare takes the lock so the child inherits it
 * free and the fd table settled; the child re-initializes it, because after
 * fork the surviving thread's tid no longer matches the recorded owner. */
/* Raw pthread calls on purpose: main()'s atfork handlers call these from
 * inside fork(), where the held-lock mask must not move (machine.h,
 * "fork safety"). */
void netlink_locks_take(void)   { pthread_mutex_lock(&nl_lock); }
void netlink_locks_drop(void)   { pthread_mutex_unlock(&nl_lock); }
void netlink_locks_reinit(void) { pthread_mutex_init(&nl_lock, NULL); }

/* --- fake-fd table (call with nl_lock held) --- */

static int nl_slot(struct Machine *m, int fd)
{
    if (fd < 0)
        return -1;
    for (int i = 0; i < m->nl_fds_count; i++)
        if (m->nl_fds[i].fd == fd)
            return i;
    return -1;
}

bool nl_is_fd(struct Machine *m, int fd)
{
    /* Unlocked fast path, as in sigfd_tracked() / procfs_pre_read(): every
     * read(2) and write(2) asks this, and the table is empty in every process
     * that never got a substituted socket -- which is all of them wherever the
     * host grants AF_NETLINK. The race is benign: a count that just went
     * non-zero was raised by the same thread's own socket(2). */
    if (!m->nl_fds_count || fd < 0)
        return false;
    EMU_LOCK(&nl_lock, EMU_LK_NL);
    bool r = nl_slot(m, fd) >= 0;
    EMU_UNLOCK(&nl_lock, EMU_LK_NL);
    return r;
}

/* --- datagram framing -------------------------------------------------------
 * A dump does not reach a netlink socket as one blob: the kernel fills a socket
 * buffer, sends it, and closes the sequence with an NLMSG_DONE of its own.
 * Callers count on that framing -- fastfetch's default-route lookup stops
 * walking a datagram the moment it has the route it wanted, then reads again
 * only to reach the terminator that ends its loop. Handing the whole reply back
 * at once leaves such a caller reading from a substitute socket that has
 * nothing more to give, so keep the terminator in a datagram of its own. */

/* Length of the next datagram out of the @len bytes of reply at @reply. */
static size_t nl_datagram_len(const uint8_t *reply, size_t len)
{
    size_t off = 0;

    while (off + NLMSG_HDRLEN <= len) {
        struct nlmsghdr hdr;
        size_t mlen;

        memcpy(&hdr, reply + off, sizeof hdr);
        mlen = hdr.nlmsg_len;
        /* Bound the length by subtraction, before aligning it. `off + mlen`
         * wraps for an nlmsg_len near the size_t maximum -- which is every
         * 32-bit host, since nlmsg_len is itself 32 bits -- and NLMSG_ALIGN of
         * such a length rounds up to 0, leaving `off` where it was. The walk
         * then never advances and never ends. */
        if (mlen < NLMSG_HDRLEN || mlen > len - off)
            break;
        if (hdr.nlmsg_type == NLMSG_DONE)
            break;
        off += NLMSG_ALIGN(mlen);
    }

    /* No terminator in sight (a plain ack, or a truncated dump): the whole
     * remainder is one datagram. Reaching it at @off == 0 means the terminator
     * is all that is left, and it goes out on its own. */
    return (off == 0 || off > len) ? len : off;
}

/* Point @reply at the datagram slot @i is about to deliver and return its
 * length, or 0 when that socket has nothing pending. Caller holds nl_lock. */
static size_t nl_pending_datagram(struct Machine *m, int i, const uint8_t **reply)
{
    if (i < 0 || m->nl_fds[i].reply_len == 0)
        return 0;
    *reply = m->nl_fds[i].reply + m->nl_fds[i].reply_off;
    return nl_datagram_len(*reply, m->nl_fds[i].reply_len - m->nl_fds[i].reply_off);
}

/* Drop the datagram just delivered; a datagram socket discards whatever didn't
 * fit in the caller's buffer, so it is consumed whole. Caller holds nl_lock. */
static void nl_consume_datagram(struct Machine *m, int i, size_t datagram)
{
    m->nl_fds[i].reply_off += datagram;
    if (m->nl_fds[i].reply_off >= m->nl_fds[i].reply_len) {
        m->nl_fds[i].reply_len = 0;
        m->nl_fds[i].reply_off = 0;
    }
}

/* --- readiness: make the stand-in socket look like what it is standing in for -
 * A synthesised reply lives in the emulator, so poll(2), select(2) and epoll --
 * which ask the kernel about the fd, not us -- would never report the socket
 * readable and a caller that waits before reading waits forever. Give them
 * something true to see: an AF_UNIX datagram socket may be connected to itself,
 * so the reply posted on it lands in its own receive queue, and the kernel then
 * answers every readiness mechanism (present and future) for us.
 *
 * What is posted is the reply itself, split into the same datagrams the guest
 * will be handed, rather than a readiness token: it stays harmless -- correct,
 * even -- if a receive ever reaches the socket instead of the emulation,
 * through a dup of the fd say, which nothing tracks. */

/* Connect @fd to itself so a send on it is a send to itself: autobind for a
 * name (an abstract one, invisible in the filesystem), then connect to it. The
 * guest never sees either -- its own bind/connect are answered without touching
 * the socket, and getsockname/getpeername are synthesised. */
static bool nl_selfconnect(int fd)
{
    struct sockaddr_un un;
    socklen_t sl = sizeof un;

    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    /* addrlen == sizeof(sa_family_t) is the autobind request. */
    if (bind(fd, (struct sockaddr *) &un, sizeof(sa_family_t)) < 0)
        return false;
    if (getsockname(fd, (struct sockaddr *) &un, &sl) < 0)
        return false;
    return connect(fd, (struct sockaddr *) &un, sl) == 0;
}

/* Make the socket's queue hold exactly the datagrams still to be delivered, so
 * every readiness mechanism agrees with the emulation datagram by datagram.
 * Re-derived from scratch each time rather than tracked incrementally: it costs
 * a handful of syscalls on a rare path and cannot drift -- not even if a read
 * slipped past the emulation and took a datagram of its own. Best-effort, since
 * a socket that never self-connected simply reports no readiness; delivery does
 * not go through the queue either way. Caller holds nl_lock. */
static void nl_sync_ready(struct Machine *m, int i)
{
    uint8_t drop[64];
    size_t off;

    if (!m->nl_fds[i].ready)
        return;
    if (m->nl_fds[i].armed) {
        while (recv(m->nl_fds[i].fd, drop, sizeof drop, MSG_DONTWAIT) >= 0)
            ;
        m->nl_fds[i].armed = 0;
    }
    off = m->nl_fds[i].reply_off;
    while (off < m->nl_fds[i].reply_len) {
        const uint8_t *at = m->nl_fds[i].reply + off;
        size_t dg = nl_datagram_len(at, m->nl_fds[i].reply_len - off);

        if (send(m->nl_fds[i].fd, at, dg, MSG_DONTWAIT | MSG_NOSIGNAL) != (ssize_t) dg)
            break;
        m->nl_fds[i].armed = 1;
        off += dg;
    }
}

void nl_mark_fd(struct Machine *m, int fd)
{
    bool ready = fd >= 0 && nl_selfconnect(fd);

    EMU_LOCK(&nl_lock, EMU_LK_NL);
    if (fd >= 0 && nl_slot(m, fd) < 0 && m->nl_fds_count < NL_MAX_FDS) {
        m->nl_fds[m->nl_fds_count].fd = fd;
        m->nl_fds[m->nl_fds_count].reply = NULL;
        m->nl_fds[m->nl_fds_count].reply_len = 0;
        m->nl_fds[m->nl_fds_count].reply_off = 0;
        m->nl_fds[m->nl_fds_count].ready = ready;
        m->nl_fds[m->nl_fds_count].armed = 0;
        m->nl_fds_count++;
    }
    EMU_UNLOCK(&nl_lock, EMU_LK_NL);
}

/* A fork child keeps its parent's substituted sockets -- they are its fds too --
 * but not the replies pending on them: a reply belongs to whoever sent the
 * request, and the copy the child inherited would otherwise be delivered twice,
 * once out of each process. The buffers stay allocated for the child's own
 * requests to reuse, and `armed` stays set so the next sync drains whatever the
 * parent posted in the queue they now share. Called on the child side of fork,
 * where only the forking thread exists, so no lock is taken. */
void nl_fork_child(struct Machine *m)
{
    for (int i = 0; i < m->nl_fds_count; i++) {
        m->nl_fds[i].reply_len = 0;
        m->nl_fds[i].reply_off = 0;
    }
}

void nl_unmark_fd(struct Machine *m, int fd)
{
    /* Unlocked fast path (see nl_is_fd): close(2) calls this for every fd. */
    if (!m->nl_fds_count && !m->nlr_fds_count && !m->nl_ack_pending)
        return;
    EMU_LOCK(&nl_lock, EMU_LK_NL);
    int i = nl_slot(m, fd);
    if (i >= 0) {
        free(m->nl_fds[i].reply);
        m->nl_fds[i] = m->nl_fds[--m->nl_fds_count];
    }
    /* Same for the real-NETLINK_ROUTE table: an fd number outliving its socket
     * there would make us inspect an unrelated file's traffic. */
    for (int j = 0; j < m->nlr_fds_count; j++) {
        if (m->nlr_fds[j] == fd) {
            m->nlr_fds[j] = m->nlr_fds[--m->nlr_fds_count];
            break;
        }
    }
    if (m->nl_ack_pending && m->nl_ack_fd == fd)
        m->nl_ack_pending = 0;
    EMU_UNLOCK(&nl_lock, EMU_LK_NL);
}

/* --- faked net namespace: ack what the host refuses (proot 87af48f5) ------
 * A guest whose CLONE_NEWNET we faked believes it configures a namespace of
 * its own, but its real NETLINK_ROUTE socket lives in the host's namespace
 * where it has no CAP_NET_ADMIN. rtnetlink answers every reconfiguring
 * request with NLMSG_ERROR(-EPERM) (or -EACCES), which kills bubblewrap's
 * loopback_setup(). Let the request reach the kernel untouched and rewrite
 * only that refusal in the reply the guest reads: the ack is the kernel's
 * own, so its sequence number and port id are the ones the caller expects. */

/* rtnetlink message types come in groups of four -- NEW, DEL, GET, SET -- and
 * everything but the GET reconfigures the network. */
static bool nlr_type_reconfigures(uint16_t type)
{
    if (type < RTM_BASE || type > RTM_MAX)
        return false;
    return ((type - RTM_BASE) & 3) != 2 /* RTM_GET* */;
}

/* True for a real NETLINK_ROUTE fd held by a guest that thinks it owns a
 * network namespace. Caller holds nl_lock. */
static bool nlr_is_netns_fd(struct Machine *m, int fd)
{
    if (!m->fake_netns || fd < 0)
        return false;
    for (int i = 0; i < m->nlr_fds_count; i++)
        if (m->nlr_fds[i] == fd)
            return true;
    return false;
}

void nlr_mark_fd(struct Machine *m, int fd)
{
    EMU_LOCK(&nl_lock, EMU_LK_NL);
    if (fd >= 0 && m->nlr_fds_count < NLR_MAX_FDS) {
        bool present = false;
        for (int i = 0; i < m->nlr_fds_count; i++)
            if (m->nlr_fds[i] == fd) { present = true; break; }
        if (!present)
            m->nlr_fds[m->nlr_fds_count++] = fd;
    }
    EMU_UNLOCK(&nl_lock, EMU_LK_NL);
}

void nlr_note_request(struct Machine *m, int fd, const void *msg, size_t len)
{
    struct nlmsghdr hdr;

    /* Unlocked fast path (see nl_is_fd): every sendto/sendmsg passes here, and
     * only a guest with both a faked network namespace and a real
     * NETLINK_ROUTE socket can have anything to note. */
    if (!m->fake_netns || !m->nlr_fds_count)
        return;
    if (!msg || len < sizeof(hdr))
        return;
    memcpy(&hdr, msg, sizeof(hdr));
    if (!nlr_type_reconfigures(hdr.nlmsg_type))
        return;

    EMU_LOCK(&nl_lock, EMU_LK_NL);
    if (nlr_is_netns_fd(m, fd)) {
        m->nl_ack_pending = 1;
        m->nl_ack_fd = fd;
        m->nl_ack_seq = hdr.nlmsg_seq;
    }
    EMU_UNLOCK(&nl_lock, EMU_LK_NL);
}

int nlr_fix_reply(struct Machine *m, int fd, void *buf, size_t len, int peek)
{
    int fixed = 0;

    /* Unlocked fast path (see nl_is_fd): every recvfrom/recvmsg that got bytes
     * passes here, and nothing is ever pending unless a faked namespace's
     * reconfiguring request is awaiting its refusal. */
    if (!m->nl_ack_pending)
        return 0;
    EMU_LOCK(&nl_lock, EMU_LK_NL);
    if (!m->nl_ack_pending || m->nl_ack_fd != fd) {
        EMU_UNLOCK(&nl_lock, EMU_LK_NL);
        return 0;
    }
    /* Walk the datagram's messages for the NLMSG_ERROR carrying our sequence
     * number. Only the expected permission refusal is rewritten -- a real
     * error (EINVAL on a malformed request, say) must still reach the guest. */
    for (size_t off = 0; off + NLMSG_HDRLEN + sizeof(int) <= len; ) {
        struct nlmsghdr hdr;
        memcpy(&hdr, (char *)buf + off, sizeof(hdr));
        /* As in nl_datagram_len: reject a length that runs past the bytes
         * actually received *before* aligning it, or a crafted nlmsg_len near
         * UINT32_MAX aligns to 0 and spins this loop forever holding nl_lock.
         * A guest can put one here -- netlink carries userspace-to-userspace
         * unicast, so it can address a datagram to its own socket. */
        size_t mlen = hdr.nlmsg_len;
        if (mlen < NLMSG_HDRLEN || mlen > len - off)
            break;
        if (hdr.nlmsg_type == NLMSG_ERROR && hdr.nlmsg_seq == m->nl_ack_seq) {
            int error;
            memcpy(&error, (char *)buf + off + NLMSG_HDRLEN, sizeof(error));
            if (error != -EPERM && error != -EACCES)
                break;                     /* a real error: report it as is */
            error = 0;
            memcpy((char *)buf + off + NLMSG_HDRLEN, &error, sizeof(error));
            fixed = 1;
            break;
        }
        off += NLMSG_ALIGN(mlen);
    }
    /* MSG_PEEK leaves the reply in the socket: keep the note for the read that
     * consumes it. */
    if (!peek)
        m->nl_ack_pending = 0;
    EMU_UNLOCK(&nl_lock, EMU_LK_NL);
    return fixed;
}

/* --- host netlink probe (cached process-wide) --- */

bool nl_host_blocks(void)
{
    enum { PROBE_UNKNOWN, PROBE_ALLOWED, PROBE_BLOCKED };
    /* Answered once per process and then remembered. Guest threads call this
     * concurrently (every socket(2) does), so the cache moves through relaxed
     * atomics: two threads racing here both run the probe and reach the same
     * verdict -- which costs a socket pair, not correctness -- but a plain int
     * written by one and read by another is a C11 data race all the same. */
    static int cached = PROBE_UNKNOWN;
    struct {
        struct nlmsghdr  nlh;
        struct ifaddrmsg ifa;
    } request;
    struct sockaddr_nl snl;
    int verdict;
    int fd;

    verdict = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (verdict != PROBE_UNKNOWN)
        return verdict == PROBE_BLOCKED;

    /* Testability: force the fallback on hosts where netlink actually works
     * (mirrors the A64_*_FORCE_* android-sim switches). */
    if (getenv("A64_NETLINK_FORCE_BLOCK"))
        goto blocked;

    /* Mirror bubblewrap's loopback_setup(): socket() then bind() with
     * nl_groups == 0. Some hosts permit socket creation but reject bind()
     * under a separate SELinux/seccomp check, so probing socket() alone would
     * wrongly classify them as "AF_NETLINK works". */
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        goto blocked;
    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *) &snl, sizeof(snl)) < 0) {
        close(fd);
        goto blocked;
    }

    /* socket() and bind() succeeding doesn't mean the guest can use the
     * socket: LSM policies filter netlink *per message type*. Android's
     * SELinux grants untrusted_app "nlmsg_read" on a netlink_route_socket but
     * not "nlmsg_write", so every rtnetlink message that reconfigures the
     * network is rejected right in sendmsg(2) with EACCES -- bubblewrap's
     * loopback_setup() then dies with "loopback: Failed RTM_NEWADDR:
     * Permission denied" although it just created and bound the socket
     * successfully. Probe a write too, otherwise such hosts are wrongly
     * classified as "AF_NETLINK works" and the guest is left to fail later.
     *
     * The probe message can't reconfigure anything: rtnetlink has no handler
     * for RTM_NEWADDR in the AF_UNSPEC family (-EOPNOTSUPP) and refuses
     * senders without CAP_NET_ADMIN even earlier (-EPERM). Both of those are
     * reported asynchronously, as a netlink reply we never read, so only a
     * send(2) that fails outright means the message was denied passage to the
     * kernel -- hosts where rtnetlink merely refuses the request keep their
     * real netlink socket. */
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(request.ifa));
    request.nlh.nlmsg_type  = RTM_NEWADDR;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.nlh.nlmsg_seq   = 1;
    request.ifa.ifa_family  = AF_UNSPEC;

    if (sendto(fd, &request, sizeof(request), MSG_DONTWAIT,
               (struct sockaddr *) &snl, sizeof(snl)) < 0
        && (errno == EACCES || errno == EPERM)) {
        close(fd);
        goto blocked;
    }

    close(fd);
    __atomic_store_n(&cached, PROBE_ALLOWED, __ATOMIC_RELAXED);
    return false;

blocked:
    __atomic_store_n(&cached, PROBE_BLOCKED, __ATOMIC_RELAXED);
    return true;
}

/* ==================================================================== */
/* rtnetlink reply builders (ported verbatim from PRoot; pure functions   */
/* operating on a flat buffer, no guest-memory access).                   */
/* ==================================================================== */

/* Append one rtattr (@type, @data/@dlen) at @off; drop it (return @off) if it
 * would overflow @max. */
static size_t nl_add_attr(uint8_t *buf, size_t off, size_t max,
                          uint16_t type, const void *data, uint16_t dlen)
{
    struct rtattr *rta;
    size_t space = RTA_SPACE(dlen);

    if (off + space > max)
        return off;

    rta = (struct rtattr *) (buf + off);
    rta->rta_len  = RTA_LENGTH(dlen);
    rta->rta_type = type;
    if (dlen > 0)
        memcpy((char *) rta + RTA_LENGTH(0), data, dlen);
    if (space > RTA_LENGTH(dlen))
        memset(buf + off + RTA_LENGTH(dlen), 0, space - RTA_LENGTH(dlen));
    return off + space;
}

/* Append an RTM_NEWLINK message describing one interface. */
static size_t nl_build_link(uint8_t *buf, size_t off, size_t max,
                            uint32_t seq, uint32_t pid, uint16_t nlflags,
                            int ifindex, uint16_t iftype, uint32_t ifflags,
                            uint32_t mtu, const char *name,
                            const uint8_t *hwaddr, uint8_t hwlen)
{
    size_t start = off;
    struct nlmsghdr *nlh;
    struct ifinfomsg ifi;
    uint32_t txqlen    = 1000;
    uint8_t  operstate = (ifflags & IFF_UP) ? 6 : 2;  /* IF_OPER_UP : _DOWN */
    uint8_t  brd[8];
    size_t len;

    if (start + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(ifi)) > max)
        return start;

    memset(&ifi, 0, sizeof(ifi));
    ifi.ifi_family = AF_UNSPEC;
    ifi.ifi_type   = iftype;
    ifi.ifi_index  = ifindex;
    ifi.ifi_flags  = ifflags | ((ifflags & IFF_RUNNING) ? IFF_LOWER_UP : 0);
    ifi.ifi_change = 0;

    off = start + NLMSG_HDRLEN;
    memcpy(buf + off, &ifi, sizeof(ifi));
    off += NLMSG_ALIGN(sizeof(ifi));

    off = nl_add_attr(buf, off, max, IFLA_IFNAME, name, strlen(name) + 1);
    off = nl_add_attr(buf, off, max, IFLA_MTU, &mtu, sizeof(mtu));
    off = nl_add_attr(buf, off, max, IFLA_TXQLEN, &txqlen, sizeof(txqlen));
    off = nl_add_attr(buf, off, max, IFLA_OPERSTATE, &operstate, sizeof(operstate));
    if (hwlen > 0) {
        memset(brd, (iftype == ARPHRD_LOOPBACK) ? 0x00 : 0xff, sizeof(brd));
        off = nl_add_attr(buf, off, max, IFLA_ADDRESS, hwaddr, hwlen);
        off = nl_add_attr(buf, off, max, IFLA_BROADCAST, brd, hwlen);
    }

    len = off - start;
    nlh = (struct nlmsghdr *) (buf + start);
    nlh->nlmsg_len   = len;
    nlh->nlmsg_type  = RTM_NEWLINK;
    nlh->nlmsg_flags = nlflags;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = pid;
    return start + NLMSG_ALIGN(len);
}

/* Append an RTM_NEWADDR message for one address. */
static size_t nl_build_addr(uint8_t *buf, size_t off, size_t max,
                            uint32_t seq, uint32_t pid, uint16_t nlflags,
                            int family, int ifindex,
                            const uint8_t *addr, uint8_t addrlen,
                            uint8_t prefixlen, uint8_t scope, const char *label)
{
    size_t start = off;
    struct nlmsghdr *nlh;
    struct ifaddrmsg ifa;
    size_t len;

    if (start + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(ifa)) > max)
        return start;

    memset(&ifa, 0, sizeof(ifa));
    ifa.ifa_family    = family;
    ifa.ifa_prefixlen = prefixlen;
    ifa.ifa_flags     = IFA_F_PERMANENT;
    ifa.ifa_scope     = scope;
    ifa.ifa_index     = ifindex;

    off = start + NLMSG_HDRLEN;
    memcpy(buf + off, &ifa, sizeof(ifa));
    off += NLMSG_ALIGN(sizeof(ifa));

    off = nl_add_attr(buf, off, max, IFA_ADDRESS, addr, addrlen);
    off = nl_add_attr(buf, off, max, IFA_LOCAL, addr, addrlen);
    if (family == AF_INET && label != NULL)
        off = nl_add_attr(buf, off, max, IFA_LABEL, label, strlen(label) + 1);

    len = off - start;
    nlh = (struct nlmsghdr *) (buf + start);
    nlh->nlmsg_len   = len;
    nlh->nlmsg_type  = RTM_NEWADDR;
    nlh->nlmsg_flags = nlflags;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = pid;
    return start + NLMSG_ALIGN(len);
}

/* Append an NLMSG_DONE terminator (end-of-dump marker). */
static size_t nl_build_done(uint8_t *buf, size_t off, size_t max,
                            uint32_t seq, uint32_t pid)
{
    struct nlmsghdr *nlh;
    int32_t error = 0;
    size_t len = NLMSG_HDRLEN + sizeof(error);

    if (off + NLMSG_ALIGN(len) > max)
        return off;

    nlh = (struct nlmsghdr *) (buf + off);
    memcpy(buf + off + NLMSG_HDRLEN, &error, sizeof(error));
    nlh->nlmsg_len   = len;
    nlh->nlmsg_type  = NLMSG_DONE;
    nlh->nlmsg_flags = NLM_F_MULTI;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = pid;
    return off + NLMSG_ALIGN(len);
}

/* Append an NLMSG_ERROR reply carrying @error (0 == success ack). */
static size_t nl_build_error(uint8_t *buf, size_t off, size_t max,
                             uint32_t seq, uint32_t pid, int error)
{
    struct nlmsghdr *nlh;
    struct nlmsgerr err;
    size_t len = NLMSG_HDRLEN + sizeof(err);

    if (off + NLMSG_ALIGN(len) > max)
        return off;

    memset(&err, 0, sizeof(err));
    err.error = error;

    nlh = (struct nlmsghdr *) (buf + off);
    memcpy(buf + off + NLMSG_HDRLEN, &err, sizeof(err));
    nlh->nlmsg_len   = len;
    nlh->nlmsg_type  = NLMSG_ERROR;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = pid;
    return off + NLMSG_ALIGN(len);
}

/* Decide whether a single (non-dump) RTM_GETLINK in @req refers to loopback:
 * either it names "lo" via IFLA_IFNAME, or asks by ifi_index 0/1. */
static bool nl_request_is_loopback(const uint8_t *req, size_t req_len)
{
    const struct ifinfomsg *ifi;
    size_t off = NLMSG_HDRLEN;
    char name[IFNAMSIZ] = { 0 };
    bool have_name = false;
    int ifindex;

    if (req_len < off + sizeof(*ifi))
        return true;            /* no selector -> treat as loopback */

    ifi = (const struct ifinfomsg *) (req + off);
    ifindex = ifi->ifi_index;

    off += NLMSG_ALIGN(sizeof(*ifi));
    while (off + sizeof(struct rtattr) <= req_len) {
        const struct rtattr *rta = (const struct rtattr *) (req + off);
        size_t rlen = rta->rta_len;

        if (rlen < sizeof(*rta) || off + rlen > req_len)
            break;
        if (rta->rta_type == IFLA_IFNAME) {
            size_t dlen = rlen - RTA_LENGTH(0);
            size_t cpy  = dlen < sizeof(name) ? dlen : sizeof(name) - 1;
            memcpy(name, (const char *) rta + RTA_LENGTH(0), cpy);
            name[cpy] = '\0';
            have_name = true;
        }
        off += RTA_ALIGN(rlen);
    }

    if (have_name)
        return strcmp(name, "lo") == 0;
    return ifindex == 0 || ifindex == 1;
}

/* Prefix length (CIDR) from a contiguous network mask of @len bytes. */
static uint8_t nl_prefixlen(const uint8_t *mask, size_t len)
{
    uint8_t bits = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        uint8_t b = mask[i];
        if (b == 0xff) {
            bits += 8;
            continue;
        }
        while (b & 0x80) {
            bits++;
            b <<= 1;
        }
        break;
    }
    return bits;
}

/* rtnetlink address scope for @addr (host / link / universe). */
static uint8_t nl_addr_scope(int family, const uint8_t *addr)
{
    if (family == AF_INET) {
        if (addr[0] == 127)
            return RT_SCOPE_HOST;                  /* 127/8 */
        if (addr[0] == 169 && addr[1] == 254)
            return RT_SCOPE_LINK;                  /* 169.254/16 */
        return RT_SCOPE_UNIVERSE;
    } else {
        static const uint8_t loop[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
        if (memcmp(addr, loop, 16) == 0)
            return RT_SCOPE_HOST;                  /* ::1 */
        if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80)
            return RT_SCOPE_LINK;                  /* fe80::/10 */
        return RT_SCOPE_UNIVERSE;
    }
}

/* Hardcoded loopback link / addresses, used as a fallback when the host
 * interfaces can't be enumerated. */
static size_t nl_build_loopback_link(uint8_t *buf, size_t off, size_t max,
                                     uint32_t seq, uint32_t pid, uint16_t nlflags)
{
    static const uint8_t zero[6] = { 0 };
    return nl_build_link(buf, off, max, seq, pid, nlflags, 1, ARPHRD_LOOPBACK,
                         IFF_UP | IFF_LOOPBACK | IFF_RUNNING, 65536, "lo", zero, 6);
}

static size_t nl_build_loopback_addr(uint8_t *buf, size_t off, size_t max,
                                     uint32_t seq, uint32_t pid, int family,
                                     uint16_t nlflags)
{
    static const uint8_t v4[4]  = { 127, 0, 0, 1 };
    static const uint8_t v6[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
    if (family == AF_INET6)
        return nl_build_addr(buf, off, max, seq, pid, nlflags, AF_INET6, 1,
                             v6, 16, 128, RT_SCOPE_HOST, NULL);
    return nl_build_addr(buf, off, max, seq, pid, nlflags, AF_INET, 1,
                         v4, 4, 8, RT_SCOPE_HOST, "lo");
}

/* Extract the interface a single (non-dump) RTM_GETLINK asks for: returns its
 * ifi_index and fills @name (empty if no IFLA_IFNAME was given). */
static int nl_request_link_target(const uint8_t *req, size_t req_len,
                                  char name[IFNAMSIZ])
{
    const struct ifinfomsg *ifi;
    size_t off = NLMSG_HDRLEN;
    int ifindex;

    name[0] = '\0';
    if (req_len < off + sizeof(*ifi))
        return 0;
    ifi = (const struct ifinfomsg *) (req + off);
    ifindex = ifi->ifi_index;

    off += NLMSG_ALIGN(sizeof(*ifi));
    while (off + sizeof(struct rtattr) <= req_len) {
        const struct rtattr *rta = (const struct rtattr *) (req + off);
        size_t rlen = rta->rta_len;

        if (rlen < sizeof(*rta) || off + rlen > req_len)
            break;
        if (rta->rta_type == IFLA_IFNAME) {
            size_t dlen = rlen - RTA_LENGTH(0);
            size_t cpy  = dlen < IFNAMSIZ ? dlen : IFNAMSIZ - 1;
            memcpy(name, (const char *) rta + RTA_LENGTH(0), cpy);
            name[cpy] = '\0';
        }
        off += RTA_ALIGN(rlen);
    }
    return ifindex;
}

/* Build RTM_NEWLINK messages for the host's interfaces (the set getifaddrs(3)
 * exposes, which keeps working on Android even when raw AF_NETLINK is denied).
 * A dump emits every interface; a single get only the one matching
 * @want_name / @want_index. Returns the new offset; @built gets the count. */
static size_t build_host_links(uint8_t *out, size_t max, uint32_t seq,
                               uint32_t pid, const char *want_name,
                               int want_index, bool dump, int *built)
{
    struct ifaddrs *ifaddr, *ifa;
    char seen[64][IFNAMSIZ];
    int seen_count = 0;
    size_t off = 0;
    int sock;

    *built = 0;
    if (getifaddrs(&ifaddr) != 0)
        return 0;
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        uint32_t ifflags;
        uint16_t iftype;
        uint32_t mtu;
        uint8_t  hwaddr[8] = { 0 };
        uint8_t  hwlen = 0;
        int ifindex;
        int i;
        bool dup = false;

        if (ifa->ifa_name == NULL)
            continue;
        for (i = 0; i < seen_count; i++)
            if (strncmp(seen[i], ifa->ifa_name, IFNAMSIZ) == 0) {
                dup = true;
                break;
            }
        if (dup)
            continue;
        if (seen_count < 64) {
            strncpy(seen[seen_count], ifa->ifa_name, IFNAMSIZ - 1);
            seen[seen_count][IFNAMSIZ - 1] = '\0';
            seen_count++;
        }

        ifflags = ifa->ifa_flags;
        iftype  = (ifflags & IFF_LOOPBACK) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
        mtu     = (ifflags & IFF_LOOPBACK) ? 65536 : 1500;
        ifindex = (int) if_nametoindex(ifa->ifa_name);

        /* AF_PACKET entries carry the authoritative index/type/hwaddr. */
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *) ifa->ifa_addr;
            if (sll->sll_ifindex != 0)
                ifindex = sll->sll_ifindex;
            iftype = sll->sll_hatype;
            if (sll->sll_halen > 0 && sll->sll_halen <= sizeof(hwaddr)) {
                memcpy(hwaddr, sll->sll_addr, sll->sll_halen);
                hwlen = sll->sll_halen;
            }
        }

        /* Best-effort MTU, and hwaddr/type when no AF_PACKET entry. */
        if (sock >= 0) {
            struct ifreq ifr;

            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            if (ioctl(sock, SIOCGIFMTU, &ifr) == 0)
                mtu = ifr.ifr_mtu;
            if (hwlen == 0) {
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    iftype = ifr.ifr_hwaddr.sa_family;
                    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
                    hwlen = 6;
                }
            }
        }

        if (!dump) {
            if (want_name != NULL && want_name[0] != '\0') {
                if (strcmp(want_name, ifa->ifa_name) != 0)
                    continue;
            } else if (want_index > 0 && ifindex != want_index) {
                continue;
            }
        }

        if (off + 256 > max)
            break;
        off = nl_build_link(out, off, max, seq, pid,
                            dump ? NLM_F_MULTI : 0, ifindex, iftype,
                            ifflags, mtu, ifa->ifa_name, hwaddr, hwlen);
        (*built)++;
        if (!dump)
            break;
    }

    if (sock >= 0)
        close(sock);
    freeifaddrs(ifaddr);
    return off;
}

/* Build RTM_NEWADDR messages for the host's addresses (optionally filtered to
 * @want_family). Returns the new offset; @built gets the count. */
static size_t build_host_addrs(uint8_t *out, size_t max, uint32_t seq,
                               uint32_t pid, int want_family, bool dump,
                               int *built)
{
    struct ifaddrs *ifaddr, *ifa;
    size_t off = 0;

    *built = 0;
    if (getifaddrs(&ifaddr) != 0)
        return 0;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        const uint8_t *addr;
        const uint8_t *mask = NULL;
        uint8_t addrlen, masklen = 0;
        uint8_t prefixlen, scope;
        int family, ifindex;

        if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL)
            continue;
        family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;
        if (want_family != AF_UNSPEC && family != want_family)
            continue;

        if (family == AF_INET) {
            addr = (const uint8_t *) &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
            addrlen = 4;
            if (ifa->ifa_netmask != NULL) {
                mask = (const uint8_t *) &((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr;
                masklen = 4;
            }
        } else {
            addr = (const uint8_t *) &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
            addrlen = 16;
            if (ifa->ifa_netmask != NULL) {
                mask = (const uint8_t *) &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;
                masklen = 16;
            }
        }

        prefixlen = (mask != NULL) ? nl_prefixlen(mask, masklen)
                                   : (family == AF_INET ? 32 : 128);
        scope = nl_addr_scope(family, addr);
        ifindex = (int) if_nametoindex(ifa->ifa_name);

        if (off + 256 > max)
            break;
        off = nl_build_addr(out, off, max, seq, pid,
                            dump ? NLM_F_MULTI : 0, family, ifindex,
                            addr, addrlen, prefixlen, scope, ifa->ifa_name);
        (*built)++;
    }

    freeifaddrs(ifaddr);
    return off;
}

/* Relay a routing-table dump (RTM_GETROUTE) from the host kernel. The Android
 * builds that deny *binding* an AF_NETLINK socket still let an unbound socket
 * issue a dump; we run that dump ourselves and copy the RTM_NEWROUTE messages
 * back, rewriting nlmsg_seq/nlmsg_pid so the tracee's iproute2 accepts them.
 * Returns 0 (caller falls back to an empty NLMSG_DONE) if the host won't play. */
static size_t relay_route_dump(const uint8_t *req, size_t req_len,
                               uint8_t *out, size_t max,
                               uint32_t seq, uint32_t pid)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
    } dreq;
    struct sockaddr_nl sa;
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    uint8_t family = (req_len > NLMSG_HDRLEN) ? req[NLMSG_HDRLEN] : 0;
    size_t off = 0;
    bool done = false;
    bool saw_done = false;
    int fd;
    int rounds;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return 0;
    (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&dreq, 0, sizeof(dreq));
    dreq.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    dreq.nlh.nlmsg_type  = RTM_GETROUTE;
    dreq.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    dreq.nlh.nlmsg_seq   = seq;
    dreq.rtm.rtm_family  = family;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, &dreq, dreq.nlh.nlmsg_len, 0,
               (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        close(fd);
        return 0;
    }

    for (rounds = 0; !done && rounds < 64; rounds++) {
        uint8_t buf[8192] __attribute__((aligned(8)));
        struct nlmsghdr *h;
        ssize_t n;
        size_t len;

        n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        len = (size_t) n;
        for (h = (struct nlmsghdr *) buf; NLMSG_OK(h, len);
             h = NLMSG_NEXT(h, len)) {
            size_t mlen = h->nlmsg_len;
            size_t aligned = NLMSG_ALIGN(mlen);

            /* Keep 64 bytes spare so the NLMSG_DONE terminator always fits. */
            if (off + aligned + 64 > max) {
                done = true;
                break;
            }
            h->nlmsg_seq = seq;
            h->nlmsg_pid = pid;
            memcpy(out + off, h, mlen);
            if (aligned > mlen)
                memset(out + off + mlen, 0, aligned - mlen);
            off += aligned;
            if (h->nlmsg_type == NLMSG_DONE) {
                saw_done = true;
                done = true;
                break;
            }
        }
    }

    close(fd);

    if (off == 0)
        return 0;
    /* Always hand back a terminator so iproute2 doesn't report "EOF on netlink". */
    if (!saw_done)
        off = nl_build_done(out, off, max, seq, pid);
    return off;
}

/* ==================================================================== */
/* Glue: reply build/deliver against guest memory.                        */
/* ==================================================================== */

/* Parse the netlink request at [buf_va, buf_len) and build the reply the kernel
 * would have produced into @out (capacity @max). Returns the reply length,
 * which is never zero: see the `reply:` tail. */
static size_t build_reply_into(CPU *c, uint8_t *out, size_t max,
                               u64 buf_va, u64 buf_len)
{
    uint8_t req[256] __attribute__((aligned(8)));
    size_t  req_len;
    struct nlmsghdr hdr;
    uint32_t pid = (uint32_t) getpid();
    uint32_t seq = 0;
    uint16_t type, flags;
    bool dump;
    size_t off = 0;

    if (buf_va == 0 || buf_len < sizeof(hdr))
        goto reply;
    req_len = buf_len < sizeof(req) ? buf_len : sizeof(req);
    if (copy_from_guest(c, req, buf_va, req_len) < 0)
        goto reply;

    memcpy(&hdr, req, sizeof(hdr));
    type  = hdr.nlmsg_type;
    flags = hdr.nlmsg_flags;
    seq   = hdr.nlmsg_seq;
    dump  = (flags & NLM_F_DUMP) == NLM_F_DUMP;

    switch (type) {
    case RTM_GETLINK: {
        char want_name[IFNAMSIZ];
        int want_index = nl_request_link_target(req, req_len, want_name);
        int n = 0;

        off = build_host_links(out, max, seq, pid,
                               dump ? NULL : want_name,
                               dump ? 0 : want_index, dump, &n);
        if (n == 0) {
            /* Host enumeration unavailable: present loopback only. */
            off = 0;
            if (dump)
                off = nl_build_loopback_link(out, off, max, seq, pid, NLM_F_MULTI);
            else if (nl_request_is_loopback(req, req_len))
                off = nl_build_loopback_link(out, off, max, seq, pid, 0);
            else
                off = nl_build_error(out, off, max, seq, pid, -ENODEV);
        }
        if (dump)
            off = nl_build_done(out, off, max, seq, pid);
        break;
    }

    case RTM_GETADDR: {
        uint8_t family = (req_len > NLMSG_HDRLEN) ? req[NLMSG_HDRLEN] : 0;
        int want_family = (family == AF_INET || family == AF_INET6)
                          ? family : AF_UNSPEC;
        int n = 0;

        off = build_host_addrs(out, max, seq, pid, want_family, dump, &n);
        if (n == 0) {
            /* Host enumeration unavailable: present loopback only. */
            off = 0;
            if (family == 0 || family == AF_INET)
                off = nl_build_loopback_addr(out, off, max, seq, pid,
                                             AF_INET, dump ? NLM_F_MULTI : 0);
            if (family == 0 || family == AF_INET6)
                off = nl_build_loopback_addr(out, off, max, seq, pid,
                                             AF_INET6, dump ? NLM_F_MULTI : 0);
        }
        if (dump)
            off = nl_build_done(out, off, max, seq, pid);
        break;
    }

    case RTM_GETROUTE:
        if (dump) {
            off = relay_route_dump(req, req_len, out, max, seq, pid);
            if (off == 0)
                off = nl_build_done(out, off, max, seq, pid);
        } else {
            off = nl_build_error(out, off, max, seq, pid, 0);
        }
        break;

    default:
        if (dump)
            off = nl_build_done(out, off, max, seq, pid);
        else
            off = nl_build_error(out, off, max, seq, pid, 0);
        break;
    }

reply:
    /* Never leave a request unanswered. The cases that would otherwise build
     * nothing are a message too short to parse and a single get whose selector
     * matches no host interface (an RTM_GETADDR for an exotic family, say);
     * an empty reply turns the read that follows into a wait on the substitute
     * socket, which nobody will ever wake (see nl_maybe_recvfrom). */
    if (off == 0)
        off = nl_build_error(out, off, max, seq, pid, -EINVAL);

    return off;
}

/* Write a synthetic sockaddr_nl into a getsockname()/getpeername()/recvfrom()
 * (@addr_va, @size_va) buffer pair. The kernel would otherwise hand back the
 * AF_UNIX sockaddr of our substitute socket (length 2), which iproute2 rejects
 * with "Wrong address length 2". Returns 0 or -errno. */
static int nl_write_sockname(CPU *c, u64 addr_va, u64 size_va, uint32_t nl_pid,
                             uint32_t nl_groups, int addr_optional)
{
    struct sockaddr_nl snl;

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid    = nl_pid;
    snl.nl_groups = nl_groups;

    /* The pointer pair is answered by the same helper every other socket goes
     * through (sock_addr_out, sys_net.c) -- the two tiers must be
     * indistinguishable, and a guest must not be able to tell a substituted
     * netlink socket from a real one by handing it half a pair. */
    return sock_addr_out(c, addr_va, size_va, &snl, sizeof snl, addr_optional);
}

/* Scatter @reply into the guest recvmsg iovec array (@iov_va, @iov_count),
 * walking segments until the reply is exhausted. Returns the bytes scattered,
 * or -EFAULT if the guest's array -- or one of the buffers it names -- could
 * not be reached.
 *
 * That has to be an error and not a short count: a caller whose buffer faults
 * is told EFAULT by the kernel, and one told "0 bytes, no error" instead reads
 * a truncated message, or walks a dump that can never reach its terminator.
 * The datagram is consumed either way (nl_take_reply), which is what
 * netlink_recvmsg does with an skb whose copy to user space failed -- it is
 * freed, not put back. */
static ssize_t nl_scatter(CPU *c, u64 iov_va, u64 iov_count,
                          const uint8_t *reply, size_t reply_len)
{
    size_t done = 0;
    if (iov_count > 1024)
        iov_count = 1024;
    for (u64 i = 0; i < iov_count && done < reply_len; i++) {
        GIovec gi;
        if (copy_from_guest(c, &gi, iov_va + i * sizeof(GIovec), sizeof gi) < 0)
            return -EFAULT;
        size_t chunk = reply_len - done;
        if (chunk > gi.iov_len)
            chunk = gi.iov_len;
        if (chunk > 0 &&
            (gi.iov_base == 0 ||
             copy_to_guest(c, gi.iov_base, reply + done, chunk) < 0))
            return -EFAULT;
        done += chunk;
    }
    return (ssize_t)done;
}

/* ==================================================================== */
/* Public syscall handlers, called on a fake netlink fd by sys_net.c (the  */
/* socket calls) and sys_file.c (read/write and their vector forms).       */
/* ==================================================================== */

/* Can the guest back the request at [base, blen)? A kernel copies the whole
 * message out of the caller's memory before it queues anything
 * (netlink_sendmsg -> memcpy_from_msg), so a request it cannot read is EFAULT
 * with nothing sent -- and therefore nothing to read back either, which is the
 * same "no reply pending" state a socket that was never written to is in.
 *
 * Only the head of the message is ever parsed here (build_reply_into reads 256
 * bytes at most), so the remainder is probed rather than copied. A message
 * larger than the socket's send buffer never reaches that point on a kernel:
 * netlink_sendmsg refuses it with EMSGSIZE before reading a byte of it, and the
 * substitute socket carries the same limit -- it comes from the same sysctl
 * (net.core.wmem_default) and a guest setsockopt(SO_SNDBUF) on this fd reaches
 * it. Without that bound a guest could name a length no buffer could hold and
 * be told all of it was sent. */
static int nl_request_check(CPU *c, int fd, u64 base, u64 blen)
{
    int sndbuf = 0;
    socklen_t sl = sizeof sndbuf;
    size_t len;

    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sl) == 0 &&
        sndbuf > 32 && blen > (u64)(sndbuf - 32))
        return -EMSGSIZE;
    if (blen == 0)
        return 0;                      /* an empty message is a valid one */
    len = rw_count(blen);
    if ((u64) len != blen || base == 0 ||
        rw_room(c, base, len, ACC_READ) < len)
        return -EFAULT;
    return 0;
}

/* Record the reply the request at [base, blen) draws, and report the whole
 * request as sent. Called for every message we accepted, even one we couldn't
 * parse: build_reply_into always leaves something behind, so no *successful*
 * send on this socket can strand a later read. */
static u64 nl_take_request(CPU *c, int fd, u64 base, u64 blen)
{
    int e = nl_request_check(c, fd, base, blen);
    if (e < 0) return (u64)(s64) e;

    EMU_LOCK(&nl_lock, EMU_LK_NL);
    int i = nl_slot(c->m, fd);
    if (i < 0) { EMU_UNLOCK(&nl_lock, EMU_LK_NL); return (u64)(s64)-EBADF; }
    if (!c->m->nl_fds[i].reply)
        c->m->nl_fds[i].reply = malloc(NL_REPLY_MAX);
    if (!c->m->nl_fds[i].reply) {
        /* Refuse the send rather than swallow it: a request with no reply
         * behind it leaves the read that follows waiting forever. */
        EMU_UNLOCK(&nl_lock, EMU_LK_NL);
        return (u64)(s64)-ENOBUFS;
    }
    c->m->nl_fds[i].reply_off = 0;
    c->m->nl_fds[i].reply_len =
        build_reply_into(c, c->m->nl_fds[i].reply, NL_REPLY_MAX, base, blen);
    /* The reply is ready now, so the socket must read as readable now: a caller
     * that waits for POLLIN before receiving is the common shape. */
    nl_sync_ready(c->m, i);
    EMU_UNLOCK(&nl_lock, EMU_LK_NL);
    return (u64)blen;
}

/* First segment of a guest iovec array, which is where the netlink callers we
 * care about put their (single) message: multi-iovec netlink requests don't
 * occur for bwrap / glibc / iproute2.
 *
 * An empty vector is an empty message (zeroed, and sent as one). An array the
 * guest cannot back is -EFAULT, which is what import_iovec makes of it -- a
 * pointer that cannot be read is not a message of no bytes. One longer than
 * UIO_MAXIOV is refused with @toobig, which differs by caller: iovec_from_user
 * answers EINVAL for writev, while copy_msghdr_from_user answers EMSGSIZE for
 * sendmsg (mirrors iov_from_guest / msg_import, sys_file.c and sys_net.c). */
static int nl_first_iovec(CPU *c, u64 iov_va, u64 iov_cnt, int toobig,
                          u64 *base, u64 *len)
{
    GIovec gi;

    *base = *len = 0;
    if (iov_cnt > 1024)
        return toobig;
    if (iov_cnt == 0)
        return 0;
    if (iov_va == 0 || copy_from_guest(c, &gi, iov_va, sizeof gi) < 0)
        return -EFAULT;
    *base = gi.iov_base;
    *len  = gi.iov_len;
    return 0;
}

u64 nl_sendto(CPU *c, int fd, u64 buf, u64 len)
{
    return nl_take_request(c, fd, buf, len);
}

u64 nl_sendmsg(CPU *c, int fd, u64 msghdr_va)
{
    /* struct msghdr (guest LP64): msg_iov @+16, msg_iovlen @+24. The header is
     * read in full before anything is sent and a field that cannot be read
     * fails the call (copy_msghdr_from_user), so a bad pointer here is EFAULT
     * -- reading it as "no segments" instead reported it as a successful send
     * of nothing, and left a reply behind for a receive that should never have
     * had one. */
    u64 iov_va = 0, iov_count = 0, base, blen;
    int e;

    if (msghdr_va == 0)
        return (u64)(s64)-EFAULT;
    if (copy_from_guest(c, &iov_va, msghdr_va + 16, 8) < 0 ||
        copy_from_guest(c, &iov_count, msghdr_va + 24, 8) < 0)
        return (u64)(s64)-EFAULT;
    e = nl_first_iovec(c, iov_va, iov_count, -EMSGSIZE, &base, &blen);
    if (e < 0) return (u64)(s64) e;
    return nl_take_request(c, fd, base, blen);
}

u64 nl_writev(CPU *c, int fd, u64 iov_va, u64 iov_cnt)
{
    u64 base, blen;
    int e = nl_first_iovec(c, iov_va, iov_cnt, -EINVAL, &base, &blen);

    if (e < 0) return (u64)(s64) e;
    return nl_take_request(c, fd, base, blen);
}

/* Hand the next pending datagram on @fd to a flat buffer (@buf, @len) or, when
 * @iov_va is non-zero, to a guest iovec array. On 1, *datagram is its
 * untruncated length and *taken the bytes actually delivered.
 *
 * Returns 0 when the socket has nothing left, and then the caller must let the
 * real syscall run: rtnetlink hands out one datagram per reply and nothing at
 * all once the queue is empty -- it never delivers a zero-length message, and a
 * caller reading a dump until NLMSG_DONE cannot make progress on one (glibc's
 * __netlink_request() walks no message, finds no terminator and reads again;
 * musl's __netlink_enumerate() escapes only because it treats the zero as a
 * hard error and abandons the dump). The substitute socket then holds only what
 * nl_sync_ready posted, which is nothing, so the kernel blocks a caller that
 * asked to wait and reports EAGAIN to one that didn't -- which is what a
 * netlink socket with nothing left to say does. Every send leaves a reply
 * behind (build_reply_into), so a read waits only when nothing was ever
 * asked. */
static int nl_take_reply(CPU *c, int fd, u64 buf, u64 len,
                         u64 iov_va, u64 iov_cnt, int flags,
                         size_t *datagram, ssize_t *taken)
{
    const uint8_t *reply = NULL;

    EMU_LOCK(&nl_lock, EMU_LK_NL);
    int i = nl_slot(c->m, fd);
    *datagram = nl_pending_datagram(c->m, i, &reply);
    if (*datagram == 0) {
        EMU_UNLOCK(&nl_lock, EMU_LK_NL);
        return 0;
    }
    *taken = 0;
    if (iov_va != 0) {
        if (iov_cnt > 0)
            *taken = nl_scatter(c, iov_va, iov_cnt, reply, *datagram);
    } else {
        size_t copied = len < *datagram ? len : *datagram;
        /* As nl_scatter: a destination that cannot be written is EFAULT, not a
         * silent zero -- and a NULL buffer with room asked for is one. */
        if (copied > 0 && (buf == 0 || copy_to_guest(c, buf, reply, copied) < 0))
            *taken = -EFAULT;
        else
            *taken = (ssize_t)copied;
    }
    /* MSG_PEEK leaves the datagram pending for the following real read -- and
     * the socket armed, since it is still readable. Consuming it re-syncs the
     * queue, which then says exactly what is left. */
    if (!(flags & MSG_PEEK)) {
        nl_consume_datagram(c->m, i, *datagram);
        nl_sync_ready(c->m, i);
    }
    EMU_UNLOCK(&nl_lock, EMU_LK_NL);
    return 1;
}

int nl_maybe_recvfrom(CPU *c, int fd, u64 buf, u64 len, int flags,
                      u64 addr_va, u64 size_va, u64 *ret)
{
    size_t datagram;
    ssize_t copied;

    if (!nl_take_reply(c, fd, buf, len, 0, 0, flags, &datagram, &copied))
        return 0;                      /* let the real recvfrom(2) run */
    if (copied < 0) { *ret = (u64)copied; return 1; }

    /* MSG_TRUNC asks for the untruncated length (libnetlink size probe). */
    size_t result = (flags & MSG_TRUNC) ? datagram : (size_t)copied;
    /* Name the kernel (nl_pid == 0), not this socket, as the sender: that is
     * how a netlink caller tells a reply apart from a message another socket
     * sent it, and glibc's __netlink_request() drops -- and then reads past --
     * every buffer whose source claims a port id of its own. */
    /* A writeback that faults is the answer the call returns, byte count or
     * not: __sys_recvfrom overwrites its result with move_addr_to_user's error,
     * and the datagram is gone either way. */
    int e = nl_write_sockname(c, addr_va, size_va, 0, 0, 1);
    if (e < 0) { *ret = (u64)(s64) e; return 1; }
    *ret = (u64)result;
    return 1;
}

int nl_maybe_readv(CPU *c, int fd, u64 iov_va, u64 iov_cnt, u64 *ret)
{
    size_t datagram;
    ssize_t scattered;

    /* As iovec_from_user, and ahead of the receive: too many segments is
     * EINVAL whether or not a reply is waiting. */
    if (iov_cnt > 1024) { *ret = (u64)(s64)-EINVAL; return 1; }
    if (iov_va == 0)                   /* nothing to scatter into */
        return 0;
    if (!nl_take_reply(c, fd, 0, 0, iov_va, iov_cnt, 0, &datagram, &scattered))
        return 0;                      /* let the real readv(2) run */
    *ret = (u64)scattered;             /* -EFAULT rides back as the errno */
    return 1;
}

int nl_maybe_recvmsg(CPU *c, int fd, u64 msghdr_va, int flags, u64 *ret)
{
    u64 msg_name = 0, iov_va = 0, iov_count = 0;
    u32 in_namelen = 0;
    size_t datagram;
    ssize_t scattered;

    if (msghdr_va == 0)                /* no header: let the real one EFAULT */
        return 0;
    /* The whole header is read before anything is received, and a field that
     * cannot be read fails the call there (copy_msghdr_from_user runs ahead of
     * the receive, so nothing is consumed). Treating an unreadable field as
     * absent reported a bad pointer as a successful receive. */
    if (copy_from_guest(c, &msg_name, msghdr_va, 8) < 0 ||
        copy_from_guest(c, &in_namelen, msghdr_va + 8, 4) < 0 ||
        copy_from_guest(c, &iov_va, msghdr_va + 16, 8) < 0 ||
        copy_from_guest(c, &iov_count, msghdr_va + 24, 8) < 0) {
        *ret = (u64)(s64)-EFAULT;
        return 1;
    }
    if (iov_count > 1024) { *ret = (u64)(s64)-EMSGSIZE; return 1; }

    if (!nl_take_reply(c, fd, 0, 0, iov_va, iov_count, flags,
                       &datagram, &scattered))
        return 0;                      /* let the real recvmsg(2) run */
    /* Nothing of the header is written back on a fault: the kernel returns
     * the error before ___sys_recvmsg touches msg_namelen or msg_flags. */
    if (scattered < 0) { *ret = (u64)scattered; return 1; }

    size_t result = (flags & MSG_TRUNC) ? datagram : (size_t)scattered;

    /* Hand back a kernel sockaddr_nl (nl_pid == 0) as the source, and set
     * msg_namelen accordingly; glibc's getifaddrs() inspects it. This is
     * recvmsg_writeback (sys_net.c) again, reached only when the caller named a
     * msg_name: truncate to the room offered, always report the real length --
     * even when no room was offered at all -- and let a writeback that faults be
     * what the call returns. The datagram is gone by then, which is what a
     * kernel does with an skb it could not copy out. */
    if (msg_name != 0) {
        struct sockaddr_nl snl;
        u32 real = (u32) sizeof(snl);
        u32 copy = in_namelen < sizeof(snl) ? in_namelen : (u32) sizeof(snl);
        memset(&snl, 0, sizeof(snl));
        snl.nl_family = AF_NETLINK;
        if (copy > 0 && copy_to_guest(c, msg_name, &snl, copy) < 0) {
            *ret = (u64)(s64)-EFAULT;
            return 1;
        }
        if (copy_to_guest(c, msghdr_va + 8, &real, 4) < 0) {
            *ret = (u64)(s64)-EFAULT;
            return 1;
        }
    }
    /* msg_flags @+48 (guest LP64): MSG_TRUNC iff the datagram didn't fit. */
    u32 mf = ((size_t)scattered < datagram) ? MSG_TRUNC : 0;
    if (copy_to_guest(c, msghdr_va + 48, &mf, 4) < 0) {
        *ret = (u64)(s64)-EFAULT;
        return 1;
    }
    /* msg_controllen @+40: the bytes of control data delivered, which is none
     * -- no NETLINK_PKTINFO here. The kernel writes it unconditionally, so a
     * caller cannot be left reading its own request value back as an answer. */
    u64 cl = 0;
    if (copy_to_guest(c, msghdr_va + 40, &cl, 8) < 0) {
        *ret = (u64)(s64)-EFAULT;
        return 1;
    }

    *ret = (u64)result;
    return 1;
}

u64 nl_getsockname(CPU *c, u64 addr_va, u64 size_va)
{
    return (u64)(s64) nl_write_sockname(c, addr_va, size_va,
                                        (uint32_t) getpid(), 0, 0);
}

/* getpeername(2) on a netlink socket names its DESTINATION, not itself:
 * netlink_getname(peer=1) reports nlk->dst_portid/dst_group, which stay zero
 * -- the kernel -- until a connect(2) names another port, and naming a
 * non-zero one on NETLINK_ROUTE needs CAP_NET_ADMIN, so an unprivileged
 * process sees 0 there whatever it asked for. (There is no ENOTCONN either:
 * netlink has no connected state to be missing.)
 *
 * Zero is right here by construction and not merely by default. This
 * emulation answers the kernel's own replies and nothing else: nl_sendto
 * ignores the destination address it is handed, connect(2) on a fake fd
 * records nothing, and no other port id is reachable through the substitute.
 * Routing this to nl_getsockname, as it used to, reported the socket's own
 * port as its peer's -- a guest that read it back saw itself where the kernel
 * names the kernel, and the substituted tier could be told from a real
 * netlink socket by asking. */
u64 nl_getpeername(CPU *c, u64 addr_va, u64 size_va)
{
    return (u64)(s64) nl_write_sockname(c, addr_va, size_va, 0, 0, 0);
}

/* Guest ABI struct ifreq size (LP64): ifr_name[16] + a 24-byte union = 40. We
 * never memcpy a host struct ifreq (32 bytes on an ILP32 host build), so this
 * fixed stride keeps SIOCGIFCONF correct on 64-bit and 32-bit hosts alike. */
#define GUEST_IFREQ_SZ 40

/* Host facts for one interface, gathered from getifaddrs plus best-effort host
 * ioctls (mirrors build_host_links above). Addresses are kept in network byte
 * order so they drop straight into a guest sockaddr_in. */
struct ifq {
    int          found;
    int          ifindex;
    unsigned int flags;      /* IFF_* */
    int          mtu, txqlen;
    uint16_t     hwtype;     /* ARPHRD_* */
    uint8_t      hwaddr[8];
    uint8_t      hwlen;
    int          hwerr;      /* why the host would not say, when hwlen == 0 */
    uint32_t     addr, netmask, broadaddr, dstaddr;
    int          have_addr;
};

/* Zero @ifr and copy the (validated, NUL-terminated) interface name into
 * ifr_name. Uses strnlen+memcpy rather than strncpy so GCC doesn't warn about
 * a length-bounded source possibly truncating (-Wstringop-truncation). */
static void ifr_set_name(struct ifreq *ifr, const char *name)
{
    size_t n = strnlen(name, IFNAMSIZ - 1);
    memset(ifr, 0, sizeof *ifr);
    memcpy(ifr->ifr_name, name, n);
    ifr->ifr_name[n] = '\0';
}

/* Fill @q for interface @name. Synthesises loopback defaults when the host has
 * no such interface but the guest asked for "lo". Returns 1 on success. */
static int gather_ifq(const char *name, struct ifq *q)
{
    struct ifaddrs *ifaddr, *ifa;
    int sock;

    memset(q, 0, sizeof *q);

    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_name == NULL || strcmp(ifa->ifa_name, name) != 0)
                continue;
            q->found = 1;
            q->flags = ifa->ifa_flags;

            if (ifa->ifa_addr == NULL)
                continue;
            if (ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *sll = (struct sockaddr_ll *) ifa->ifa_addr;
                if (sll->sll_ifindex != 0)
                    q->ifindex = sll->sll_ifindex;
                q->hwtype = sll->sll_hatype;
                if (sll->sll_halen > 0 && sll->sll_halen <= sizeof q->hwaddr) {
                    memcpy(q->hwaddr, sll->sll_addr, sll->sll_halen);
                    q->hwlen = sll->sll_halen;
                }
            } else if (ifa->ifa_addr->sa_family == AF_INET && !q->have_addr) {
                struct sockaddr_in *si = (struct sockaddr_in *) ifa->ifa_addr;
                q->addr = si->sin_addr.s_addr;
                q->have_addr = 1;
                if (ifa->ifa_netmask != NULL) {
                    si = (struct sockaddr_in *) ifa->ifa_netmask;
                    q->netmask = si->sin_addr.s_addr;
                }
                /* ifa_broadaddr / ifa_dstaddr alias the same union member. */
                if ((ifa->ifa_flags & IFF_BROADCAST) &&
                    ifa->ifa_broadaddr != NULL) {
                    si = (struct sockaddr_in *) ifa->ifa_broadaddr;
                    q->broadaddr = si->sin_addr.s_addr;
                } else if ((ifa->ifa_flags & IFF_POINTOPOINT) &&
                           ifa->ifa_dstaddr != NULL) {
                    si = (struct sockaddr_in *) ifa->ifa_dstaddr;
                    q->dstaddr = si->sin_addr.s_addr;
                }
            }
        }
        freeifaddrs(ifaddr);
    }

    if (q->found && q->ifindex == 0)
        q->ifindex = (int) if_nametoindex(name);

    /* Best-effort MTU / tx queue length / hwaddr from the host kernel. */
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (q->found && sock >= 0) {
        struct ifreq ifr;

        ifr_set_name(&ifr, name);
        if (ioctl(sock, SIOCGIFMTU, &ifr) == 0)
            q->mtu = ifr.ifr_mtu;

        ifr_set_name(&ifr, name);
        if (ioctl(sock, SIOCGIFTXQLEN, &ifr) == 0)
            q->txqlen = ifr.ifr_qlen;

        if (q->hwlen == 0) {
            ifr_set_name(&ifr, name);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                q->hwtype = ifr.ifr_hwaddr.sa_family;
                memcpy(q->hwaddr, ifr.ifr_hwaddr.sa_data, 6);
                q->hwlen = 6;
            } else {
                q->hwerr = errno;   /* Android denies this one to an app */
            }
        }
    }

    /* Loopback's hardware address is not a host fact to be discovered: every
     * kernel answers ARPHRD_LOOPBACK with an all-zero address. Filling it in
     * here matters because Android denies both this ioctl and /sys/class/net to
     * an unprivileged app, so an interface we can otherwise see completely
     * would have no type at all -- and the caller used to report that as a
     * successful lookup with sa_family 0, a value no kernel returns. (The
     * whole-interface synthesis below covers only the case where lo is not
     * found; on Android it is found, just not fully described.) */
    if (q->found && q->hwlen == 0 && (q->flags & IFF_LOOPBACK)) {
        q->hwtype = ARPHRD_LOOPBACK;
        q->hwlen = 6;                /* six zero bytes, as the kernel reports */
        q->hwerr = 0;
    }
    if (sock >= 0)
        close(sock);

    if (!q->found && strcmp(name, "lo") == 0) {
        q->found     = 1;
        q->ifindex   = 1;                            /* index 1 on every kernel */
        q->flags     = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
        q->mtu       = 65536;
        q->hwtype    = ARPHRD_LOOPBACK;
        q->addr      = htonl(INADDR_LOOPBACK);       /* 127.0.0.1 */
        q->netmask   = htonl(0xff000000u);           /* 255.0.0.0  */
        q->have_addr = 1;
    }

    return q->found;
}

int nl_maybe_ifreq_ioctl(CPU *c, u32 cmd, u64 arg, u64 *ret)
{
    char name[IFNAMSIZ];
    struct ifq q;
    uint8_t out[GUEST_IFREQ_SZ - IFNAMSIZ];   /* the ifr union, at offset 16 */
    size_t outlen = 0;

    /* SIOCGIFNAME is the reverse mapping: ifr_ifindex in, ifr_name out. */
    if (cmd == 0x8910 /*SIOCGIFNAME*/) {
        int idx;
        char nm[IFNAMSIZ];
        if (arg == 0)
            return 0;
        if (copy_from_guest(c, &idx, arg + IFNAMSIZ, sizeof idx) < 0)
            return 0;
        memset(nm, 0, sizeof nm);
        if (idx > 0 && if_indextoname((unsigned) idx, nm) == NULL) {
            if (idx != 1) { *ret = (u64)(s64) -ENODEV; return 1; }
            strcpy(nm, "lo");                        /* loopback is index 1 */
        }
        if (copy_to_guest(c, arg, nm, sizeof nm) < 0)
            return 0;
        *ret = 0;
        return 1;
    }

    switch (cmd) {
    case 0x8913: /*SIOCGIFFLAGS*/   case 0x8915: /*SIOCGIFADDR*/
    case 0x8917: /*SIOCGIFDSTADDR*/ case 0x8919: /*SIOCGIFBRDADDR*/
    case 0x891b: /*SIOCGIFNETMASK*/ case 0x891d: /*SIOCGIFMETRIC*/
    case 0x8921: /*SIOCGIFMTU*/     case 0x8927: /*SIOCGIFHWADDR*/
    case 0x8933: /*SIOCGIFINDEX*/   case 0x8942: /*SIOCGIFTXQLEN*/
    case 0x8970: /*SIOCGIFMAP*/
        break;
    default:
        return 0;                                    /* not ours; fall through */
    }

    if (arg == 0)
        return 0;
    if (copy_from_guest(c, name, arg, sizeof name) < 0)
        return 0;
    name[IFNAMSIZ - 1] = '\0';

    if (!gather_ifq(name, &q)) {
        *ret = (u64)(s64) -ENODEV;                   /* real kernel's errno */
        return 1;
    }

    memset(out, 0, sizeof out);
    switch (cmd) {
    case 0x8933: { int v = q.ifindex; memcpy(out, &v, sizeof v); outlen = sizeof v; break; }
    case 0x8921: { int v = q.mtu;     memcpy(out, &v, sizeof v); outlen = sizeof v; break; }
    case 0x8942: { int v = q.txqlen;  memcpy(out, &v, sizeof v); outlen = sizeof v; break; }
    case 0x891d: { int v = 0;         memcpy(out, &v, sizeof v); outlen = sizeof v; break; }  /* metric */
    case 0x8913: { short v = (short)(q.flags & 0xffff); memcpy(out, &v, sizeof v); outlen = sizeof v; break; }
    case 0x8915:   /* SIOCGIFADDR    */
    case 0x8917:   /* SIOCGIFDSTADDR */
    case 0x8919:   /* SIOCGIFBRDADDR */
    case 0x891b: { /* SIOCGIFNETMASK */
        struct sockaddr_in si;
        uint32_t a = (cmd == 0x8915) ? q.addr :
                     (cmd == 0x8917) ? q.dstaddr :
                     (cmd == 0x8919) ? q.broadaddr : q.netmask;
        memset(&si, 0, sizeof si);
        si.sin_family = AF_INET;
        si.sin_addr.s_addr = a;
        memcpy(out, &si, sizeof si); outlen = sizeof si; break;
    }
    case 0x8927: { /* SIOCGIFHWADDR: sockaddr(sa_family=hwtype, sa_data=hwaddr) */
        /* Loopback is filled in by gather_ifq whatever the host says, so a zero
         * length here means a real interface whose address the host refused to
         * reveal. Report that refusal. Returning success with sa_family 0 --
         * which is what this did -- invents an answer no kernel gives, and a
         * guest cannot tell it from a real one. */
        if (q.hwlen == 0) {
            *ret = (u64)(s64) -(q.hwerr ? q.hwerr : EINVAL);
            return 1;
        }
        struct sockaddr sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_family = q.hwtype;
        memcpy(sa.sa_data, q.hwaddr, q.hwlen);
        memcpy(out, &sa, sizeof sa); outlen = sizeof sa; break;
    }
    case 0x8970:   /* SIOCGIFMAP: struct ifmap, zero-filled (out already zeroed) */
        outlen = GUEST_IFREQ_SZ - IFNAMSIZ; break;
    }

    if (copy_to_guest(c, arg + IFNAMSIZ, out, outlen) < 0)
        return 0;
    *ret = 0;
    return 1;
}

int nl_maybe_siocgifconf(CPU *c, u64 arg, u64 *ret)
{
    uint32_t ifc_len;
    uint64_t bufp;
    struct { char name[IFNAMSIZ]; uint32_t addr; } ent[64];
    int n = 0;
    struct ifaddrs *ifaddr, *ifa;
    uint32_t total, cap, produced, i;

    if (arg == 0)
        return 0;
    /* guest struct ifconf: int ifc_len @0, pad @4, ifc_buf/ifc_req ptr @8. */
    if (copy_from_guest(c, &ifc_len, arg, sizeof ifc_len) < 0)
        return 0;
    if (copy_from_guest(c, &bufp, arg + 8, sizeof bufp) < 0)
        return 0;

    /* SIOCGIFCONF is IPv4-only: one ifreq per AF_INET address (aliases too). */
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL && n < 64; ifa = ifa->ifa_next) {
            struct sockaddr_in *si;
            if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL)
                continue;
            if (ifa->ifa_addr->sa_family != AF_INET)
                continue;
            memset(ent[n].name, 0, IFNAMSIZ);
            strncpy(ent[n].name, ifa->ifa_name, IFNAMSIZ - 1);
            si = (struct sockaddr_in *) ifa->ifa_addr;
            ent[n].addr = si->sin_addr.s_addr;
            n++;
        }
        freeifaddrs(ifaddr);
    }
    if (n == 0) {                                    /* loopback fallback */
        memset(ent[0].name, 0, IFNAMSIZ);
        strcpy(ent[0].name, "lo");
        ent[0].addr = htonl(INADDR_LOOPBACK);
        n = 1;
    }

    total = (uint32_t) n * GUEST_IFREQ_SZ;

    /* NULL buffer => report the size needed to hold every entry (netdevice(7)). */
    if (bufp == 0) {
        if (copy_to_guest(c, arg, &total, sizeof total) < 0)
            return 0;
        *ret = 0;
        return 1;
    }

    cap = ifc_len / GUEST_IFREQ_SZ;                  /* whole entries that fit */
    produced = 0;
    for (i = 0; i < (uint32_t) n && i < cap; i++) {
        uint8_t e[GUEST_IFREQ_SZ];
        struct sockaddr_in si;
        memset(e, 0, sizeof e);
        memcpy(e, ent[i].name, IFNAMSIZ);
        memset(&si, 0, sizeof si);
        si.sin_family = AF_INET;
        si.sin_addr.s_addr = ent[i].addr;
        memcpy(e + IFNAMSIZ, &si, sizeof si);        /* ifr_addr @ offset 16 */
        if (copy_to_guest(c, bufp + (uint64_t) i * GUEST_IFREQ_SZ,
                          e, GUEST_IFREQ_SZ) < 0)
            return 0;
        produced += GUEST_IFREQ_SZ;
    }
    if (copy_to_guest(c, arg, &produced, sizeof produced) < 0)
        return 0;
    *ret = 0;
    return 1;
}
