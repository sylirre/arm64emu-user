/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* AF_NETLINK / NETLINK_ROUTE emulation (proot-style): when the host denies a
 * real netlink socket, socket() substitutes an AF_UNIX/SOCK_DGRAM socket and
 * the netlink-shaped syscalls on it are answered with synthesised rtnetlink
 * replies. Only NETLINK_ROUTE is emulated; other protocols pass through. */
#ifndef A64_SYS_NETLINK_H
#define A64_SYS_NETLINK_H

#include "machine.h"

/* True iff the host kernel refuses a real AF_NETLINK/NETLINK_ROUTE socket
 * (probed once via socket()+bind(), then cached process-wide). */
bool nl_host_blocks(void);

/* Fake-netlink fd table. */
bool nl_is_fd(struct Machine *m, int fd);
void nl_mark_fd(struct Machine *m, int fd);
void nl_unmark_fd(struct Machine *m, int fd);   /* frees any pending reply */
/* Fork child: keeps the sockets, drops the replies pending on them (they belong
 * to whoever sent the request). Child side of fork, single-threaded, unlocked. */
void nl_fork_child(struct Machine *m);

/* Real-NETLINK_ROUTE fd table + faked-net-namespace ack emulation. A guest
 * whose CLONE_NEWNET was faked (m->fake_netns) still talks to the host's
 * network namespace over a real netlink socket, where it has no CAP_NET_ADMIN,
 * so rtnetlink refuses every reconfiguring request with NLMSG_ERROR(-EPERM).
 * The request reaches the kernel untouched; only that refusal is rewritten
 * into the kernel's own ack (right seq and port id, error zeroed).
 *   nlr_mark_fd  -- socket() handed out a real NETLINK_ROUTE fd.
 *   nlr_note_request -- a sendto/sendmsg on such an fd may need the rewrite.
 *   nlr_fix_reply -- rewrite the noted refusal in a just-received buffer.
 * nl_unmark_fd drops an fd from both tables (close). */
void nlr_mark_fd(struct Machine *m, int fd);
void nlr_note_request(struct Machine *m, int fd, const void *msg, size_t len);
/* `buf` holds `len` received bytes from `fd`; rewrites in place. `peek` (a
 * MSG_PEEK receive) keeps the note pending for the read that consumes the
 * reply. Returns 1 if a refusal was turned into an ack. */
int  nlr_fix_reply(struct Machine *m, int fd, void *buf, size_t len, int peek);

/* Sends on a fake fd: the request is parsed and the reply it draws recorded for
 * the receive that follows. Each returns the guest x0 value (a non-negative
 * result, or a negative errno). A netlink socket takes a message by write(2)
 * just as well as by send(2) -- busybox's `ip` uses write, and an unaddressed
 * write to the AF_UNIX substitute would fail with ENOTCONN -- so nl_sendto
 * doubles as the write(2) handler and nl_writev as the writev(2) one. */
u64 nl_sendto(CPU *c, int fd, u64 buf, u64 len);
u64 nl_sendmsg(CPU *c, int fd, u64 msghdr_va);
u64 nl_writev(CPU *c, int fd, u64 iov_va, u64 iov_cnt);
u64 nl_getsockname(CPU *c, u64 addr_va, u64 size_va);
u64 nl_getpeername(CPU *c, u64 addr_va, u64 size_va);

/* Receives on a fake fd (nl_maybe_recvfrom also serves read(2), passed flags 0
 * and no address). Each returns 1 and stores the guest x0 in *ret when a
 * synthesised reply was pending; 0 when none was, which means the real syscall
 * must run on the substitute AF_UNIX socket. Its receive queue is always empty,
 * so it blocks or reports EAGAIN exactly as a netlink socket with nothing left
 * to say does -- unlike a zero-length message, which rtnetlink never delivers
 * and which strands every caller that reads a dump until NLMSG_DONE. */
int nl_maybe_recvfrom(CPU *c, int fd, u64 buf, u64 len, int flags,
                      u64 addr_va, u64 size_va, u64 *ret);
int nl_maybe_recvmsg(CPU *c, int fd, u64 msghdr_va, int flags, u64 *ret);
int nl_maybe_readv(CPU *c, int fd, u64 iov_va, u64 iov_cnt, u64 *ret);

/* Read-only interface-query ioctls answered from the host's own interface
 * table (getifaddrs + best-effort host ioctls) with a synthesised loopback
 * fallback. Each returns 1 and stores the guest x0 in *ret when handled; 0 to
 * let the real ioctl run.
 *   nl_maybe_ifreq_ioctl: SIOCGIF{INDEX,NAME,FLAGS,ADDR,NETMASK,BRDADDR,
 *                         DSTADDR,MTU,METRIC,HWADDR,TXQLEN,MAP} on a struct ifreq.
 *   nl_maybe_siocgifconf: SIOCGIFCONF enumeration into a struct ifconf. */
int nl_maybe_ifreq_ioctl(CPU *c, u32 cmd, u64 arg, u64 *ret);
int nl_maybe_siocgifconf(CPU *c, u64 arg, u64 *ret);

#endif /* A64_SYS_NETLINK_H */
