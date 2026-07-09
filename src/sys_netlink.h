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

/* Netlink-shaped syscalls issued on a fake fd. Each returns the guest x0
 * value (a non-negative result, or a negative errno). */
u64 nl_sendto(CPU *c, int fd, u64 buf, u64 len);
u64 nl_sendmsg(CPU *c, int fd, u64 msghdr_va);
u64 nl_recvfrom(CPU *c, int fd, u64 buf, u64 len, int flags, u64 addr_va, u64 size_va);
u64 nl_recvmsg(CPU *c, int fd, u64 msghdr_va, int flags);
u64 nl_getsockname(CPU *c, u64 addr_va, u64 size_va);

/* SIOCGIFINDEX answered from the host's own interface table. Returns 1 and
 * stores the guest x0 in *ret when handled; 0 to let the real ioctl run. */
int nl_maybe_siocgifindex(CPU *c, u64 arg, u64 *ret);

#endif /* A64_SYS_NETLINK_H */
