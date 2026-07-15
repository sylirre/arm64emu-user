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
 * getaddrinfo) keep a real netlink socket when one is available. */
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#include "guest_abi.h"
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
    pthread_mutex_lock(&nl_lock);
    bool r = nl_slot(m, fd) >= 0;
    pthread_mutex_unlock(&nl_lock);
    return r;
}

void nl_mark_fd(struct Machine *m, int fd)
{
    pthread_mutex_lock(&nl_lock);
    if (fd >= 0 && nl_slot(m, fd) < 0 && m->nl_fds_count < NL_MAX_FDS) {
        m->nl_fds[m->nl_fds_count].fd = fd;
        m->nl_fds[m->nl_fds_count].reply = NULL;
        m->nl_fds[m->nl_fds_count].reply_len = 0;
        m->nl_fds_count++;
    }
    pthread_mutex_unlock(&nl_lock);
}

void nl_unmark_fd(struct Machine *m, int fd)
{
    pthread_mutex_lock(&nl_lock);
    int i = nl_slot(m, fd);
    if (i >= 0) {
        free(m->nl_fds[i].reply);
        m->nl_fds[i] = m->nl_fds[--m->nl_fds_count];
    }
    pthread_mutex_unlock(&nl_lock);
}

/* --- host netlink probe (cached process-wide) --- */

bool nl_host_blocks(void)
{
    enum { PROBE_UNKNOWN, PROBE_ALLOWED, PROBE_BLOCKED };
    static int cached = PROBE_UNKNOWN;
    struct sockaddr_nl snl;
    int fd;

    if (cached != PROBE_UNKNOWN)
        return cached == PROBE_BLOCKED;

    /* Testability: force the fallback on hosts where netlink actually works
     * (mirrors the A64_*_FORCE_* android-sim switches). */
    if (getenv("A64_NETLINK_FORCE_BLOCK")) {
        cached = PROBE_BLOCKED;
        return true;
    }

    /* Mirror bubblewrap's loopback_setup(): socket() then bind() with
     * nl_groups == 0. Some hosts permit socket creation but reject bind()
     * under a separate SELinux/seccomp check, so probing socket() alone would
     * wrongly classify them as "AF_NETLINK works". */
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        cached = PROBE_BLOCKED;
        return true;
    }
    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *) &snl, sizeof(snl)) < 0) {
        close(fd);
        cached = PROBE_BLOCKED;
        return true;
    }
    close(fd);
    cached = PROBE_ALLOWED;
    return false;
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
 * would have produced into @out (capacity @max). Returns the reply length. */
static size_t build_reply_into(CPU *c, uint8_t *out, size_t max,
                               u64 buf_va, u64 buf_len)
{
    uint8_t req[256] __attribute__((aligned(8)));
    size_t  req_len;
    struct nlmsghdr hdr;
    uint32_t pid = (uint32_t) getpid();
    uint32_t seq;
    uint16_t type, flags;
    bool dump;
    size_t off = 0;

    if (buf_va == 0 || buf_len < sizeof(hdr))
        return 0;
    req_len = buf_len < sizeof(req) ? buf_len : sizeof(req);
    if (copy_from_guest(c, req, buf_va, req_len) < 0)
        return 0;

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

    return off;
}

/* Write a synthetic sockaddr_nl into a getsockname()/getpeername()/recvfrom()
 * (@addr_va, @size_va) buffer pair. The kernel would otherwise hand back the
 * AF_UNIX sockaddr of our substitute socket (length 2), which iproute2 rejects
 * with "Wrong address length 2". Returns 0 or -errno. */
static int nl_write_sockname(CPU *c, u64 addr_va, u64 size_va, uint32_t nl_pid)
{
    struct sockaddr_nl snl;
    u32 in_size, out_size;

    if (size_va == 0)
        return -EINVAL;
    if (copy_from_guest(c, &in_size, size_va, 4) < 0)
        return -EFAULT;

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid    = nl_pid;

    if (addr_va != 0 && in_size > 0) {
        u32 copy = in_size < sizeof(snl) ? in_size : (u32) sizeof(snl);
        if (copy_to_guest(c, addr_va, &snl, copy) < 0)
            return -EFAULT;
    }
    /* Linux semantics: *size always reflects the real address length. */
    out_size = sizeof(snl);
    if (copy_to_guest(c, size_va, &out_size, 4) < 0)
        return -EFAULT;
    return 0;
}

/* Scatter @reply into the guest recvmsg iovec array (@iov_va, @iov_count),
 * walking segments until the reply is exhausted. Returns the bytes scattered. */
static size_t nl_scatter(CPU *c, u64 iov_va, u64 iov_count,
                         const uint8_t *reply, size_t reply_len)
{
    size_t done = 0;
    if (iov_count > 1024)
        iov_count = 1024;
    for (u64 i = 0; i < iov_count && done < reply_len; i++) {
        GIovec gi;
        if (copy_from_guest(c, &gi, iov_va + i * sizeof(GIovec), sizeof gi) < 0)
            break;
        size_t chunk = reply_len - done;
        if (chunk > gi.iov_len)
            chunk = gi.iov_len;
        if (gi.iov_base != 0 && chunk > 0) {
            if (copy_to_guest(c, gi.iov_base, reply + done, chunk) < 0)
                break;
        }
        done += chunk;
    }
    return done;
}

/* ==================================================================== */
/* Public syscall handlers (called from sys_net.c on a fake netlink fd).   */
/* ==================================================================== */

u64 nl_sendto(CPU *c, int fd, u64 buf, u64 len)
{
    pthread_mutex_lock(&nl_lock);
    int i = nl_slot(c->m, fd);
    if (i < 0) { pthread_mutex_unlock(&nl_lock); return (u64)(s64)-EBADF; }
    if (!c->m->nl_fds[i].reply)
        c->m->nl_fds[i].reply = malloc(NL_REPLY_MAX);
    if (c->m->nl_fds[i].reply)
        c->m->nl_fds[i].reply_len =
            build_reply_into(c, c->m->nl_fds[i].reply, NL_REPLY_MAX, buf, len);
    else
        c->m->nl_fds[i].reply_len = 0;
    pthread_mutex_unlock(&nl_lock);
    return (u64)len;   /* pretend the whole request was sent */
}

u64 nl_sendmsg(CPU *c, int fd, u64 msghdr_va)
{
    /* struct msghdr (guest LP64): msg_iov @+16, msg_iovlen @+24. Use the first
     * iovec as the request (multi-iovec netlink requests don't occur for the
     * bwrap/glibc/iproute2 callers we care about). */
    u64 iov_va = 0, iov_count = 0, total = 0;
    if (msghdr_va != 0) {
        if (copy_from_guest(c, &iov_va, msghdr_va + 16, 8) < 0 ||
            copy_from_guest(c, &iov_count, msghdr_va + 24, 8) < 0)
            iov_va = iov_count = 0;
    }
    pthread_mutex_lock(&nl_lock);
    int i = nl_slot(c->m, fd);
    if (i < 0) { pthread_mutex_unlock(&nl_lock); return (u64)(s64)-EBADF; }
    c->m->nl_fds[i].reply_len = 0;
    if (iov_va != 0 && iov_count > 0) {
        GIovec gi;
        if (copy_from_guest(c, &gi, iov_va, sizeof gi) == 0) {
            if (!c->m->nl_fds[i].reply)
                c->m->nl_fds[i].reply = malloc(NL_REPLY_MAX);
            if (c->m->nl_fds[i].reply)
                c->m->nl_fds[i].reply_len = build_reply_into(
                    c, c->m->nl_fds[i].reply, NL_REPLY_MAX,
                    gi.iov_base, gi.iov_len);
            total = gi.iov_len;
        }
    }
    pthread_mutex_unlock(&nl_lock);
    return (u64)total;
}

u64 nl_recvfrom(CPU *c, int fd, u64 buf, u64 len, int flags,
                u64 addr_va, u64 size_va)
{
    pthread_mutex_lock(&nl_lock);
    int i = nl_slot(c->m, fd);
    if (i < 0) { pthread_mutex_unlock(&nl_lock); return (u64)(s64)-EBADF; }
    size_t reply_len = c->m->nl_fds[i].reply_len;
    size_t copied = 0;
    if (reply_len > 0 && buf != 0) {
        copied = len < reply_len ? len : reply_len;
        if (copied > 0 && copy_to_guest(c, buf, c->m->nl_fds[i].reply, copied) < 0)
            copied = 0;
    }
    /* MSG_PEEK leaves the reply pending for the following real read;
     * MSG_TRUNC asks for the untruncated length (libnetlink size probe). */
    if (!(flags & MSG_PEEK))
        c->m->nl_fds[i].reply_len = 0;
    pthread_mutex_unlock(&nl_lock);

    size_t result = (flags & MSG_TRUNC) ? reply_len : copied;
    if (addr_va != 0 && size_va != 0)
        (void) nl_write_sockname(c, addr_va, size_va, (uint32_t) getpid());
    return (u64)result;
}

u64 nl_recvmsg(CPU *c, int fd, u64 msghdr_va, int flags)
{
    u64 msg_name = 0, iov_va = 0, iov_count = 0;
    if (msghdr_va != 0) {
        if (copy_from_guest(c, &msg_name, msghdr_va, 8) < 0)       msg_name = 0;
        if (copy_from_guest(c, &iov_va, msghdr_va + 16, 8) < 0)    iov_va = 0;
        if (copy_from_guest(c, &iov_count, msghdr_va + 24, 8) < 0) iov_count = 0;
    }

    pthread_mutex_lock(&nl_lock);
    int i = nl_slot(c->m, fd);
    if (i < 0) { pthread_mutex_unlock(&nl_lock); return (u64)(s64)-EBADF; }
    size_t reply_len = c->m->nl_fds[i].reply_len;
    size_t scattered = 0;
    if (iov_va != 0 && iov_count > 0)
        scattered = nl_scatter(c, iov_va, iov_count, c->m->nl_fds[i].reply, reply_len);
    if (!(flags & MSG_PEEK))
        c->m->nl_fds[i].reply_len = 0;
    pthread_mutex_unlock(&nl_lock);

    size_t result = (flags & MSG_TRUNC) ? reply_len : scattered;

    /* Hand back a kernel sockaddr_nl (nl_pid == 0) as the source, and set
     * msg_namelen accordingly; glibc's getifaddrs() inspects it. */
    if (msg_name != 0 && msghdr_va != 0) {
        u32 in_namelen;
        if (copy_from_guest(c, &in_namelen, msghdr_va + 8, 4) == 0 && in_namelen > 0) {
            struct sockaddr_nl snl;
            u32 copy = in_namelen < sizeof(snl) ? in_namelen : (u32) sizeof(snl);
            memset(&snl, 0, sizeof(snl));
            snl.nl_family = AF_NETLINK;
            (void) copy_to_guest(c, msg_name, &snl, copy);
            u32 real = sizeof(snl);
            (void) copy_to_guest(c, msghdr_va + 8, &real, 4);
        }
    }
    /* msg_flags @+48 (guest LP64): MSG_TRUNC iff the reply didn't fit. */
    if (msghdr_va != 0) {
        u32 mf = (scattered < reply_len) ? MSG_TRUNC : 0;
        (void) copy_to_guest(c, msghdr_va + 48, &mf, 4);
    }
    return (u64)result;
}

u64 nl_getsockname(CPU *c, u64 addr_va, u64 size_va)
{
    return (u64)(s64) nl_write_sockname(c, addr_va, size_va, (uint32_t) getpid());
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
            }
        }
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
        struct sockaddr sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_family = q.hwtype;
        memcpy(sa.sa_data, q.hwaddr, q.hwlen ? q.hwlen : 6);
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
