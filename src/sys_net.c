/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Socket syscalls. sockaddr layouts (sockaddr_in/in6/un) are identical across
 * arm64/arm/x86; msghdr and cmsghdr differ only in pointer/size_t width and are
 * converted explicitly, so the code is correct on ILP32 hosts too. AF_UNIX
 * pathname sockets carry a filesystem path in sun_path, so bind/connect/sendto/
 * sendmsg rewrite it through the rootfs resolver (unix_path_in) and the address
 * the kernel reports back is stripped to its guest view (unix_path_out). A
 * translated path is reached relative to its PINNED parent-directory fd via
 * /proc/self/fd (unix_path_in), which both contains it against a concurrent
 * rename and leaves only the basename to fit the 108 bytes. Abstract
 * sockets, which have no filesystem node, are instead isolated per rootfs by a
 * name tag (abs_tag_in/out) unless --share-abstract-sockets is given. */
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>    /* struct timeval (SO_RCVTIMEO/SO_SNDTIMEO) */
#include <time.h>       /* clock_gettime (recvmmsg's deadline)               */
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/filter.h>    /* sock_fprog/sock_filter (SO_ATTACH_FILTER) */
#include <linux/netlink.h>   /* AF_NETLINK, NETLINK_ROUTE, NETLINK_AUDIT */

#ifndef SO_ATTACH_REUSEPORT_CBPF   /* pre-4.5 host kernel headers */
#define SO_ATTACH_REUSEPORT_CBPF 51
#endif

#include "sys.h"
#include "sys_netlink.h"

SYSDEF(socket) {
    (void)a3; (void)a4; (void)a5;
    int domain = (int)a0, type = (int)a1, protocol = (int)a2;
    /* On hosts that deny AF_NETLINK (Android), substitute an AF_UNIX/SOCK_DGRAM
     * socket for a NETLINK_ROUTE request and synthesise its traffic; other
     * netlink protocols fall through to the real kernel behavior. */
    if (domain == AF_NETLINK && protocol == NETLINK_ROUTE && nl_host_blocks()) {
        int fd = socket(AF_UNIX, SOCK_DGRAM | (type & (SOCK_CLOEXEC | SOCK_NONBLOCK)), 0);
        if (fd < 0) return host_err();
        if (!fd_within_limit(c, fd)) return (u64)(s64)-EMFILE;
        int r = nl_mark_fd(c->m, fd);
        if (r < 0) { close(fd); return (u64)(s64)r; }   /* untracked = a bare AF_UNIX socket */
        return (u64)fd;
    }
    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        /* fake_id0-style shim: a would-be-root guest that the host denies a
         * NETLINK_AUDIT socket gets EPROTONOSUPPORT ("audit not built in")
         * rather than a hard permission error. */
        if (fake_root(c->m) &&
            domain == AF_NETLINK && protocol == NETLINK_AUDIT &&
            (errno == EPERM || errno == EACCES))
            return (u64)(s64)-EPROTONOSUPPORT;
        return host_err();
    }
    if (!fd_within_limit(c, fd)) return (u64)(s64)-EMFILE;
    /* A real NETLINK_ROUTE socket still needs the ack emulation when the guest
     * believes it configures a network namespace of its own (sys_netlink.c). */
    if (domain == AF_NETLINK && protocol == NETLINK_ROUTE) {
        int r = nlr_mark_fd(c->m, fd);
        if (r < 0) { close(fd); return (u64)(s64)r; }
    }
    return (u64)fd;
}

SYSDEF(socketpair) {
    int sv[2];
    if (socketpair((int)a0, (int)a1, (int)a2, sv) < 0) return host_err();
    if (!fd_pair_within_limit(c, sv[0], sv[1])) return (u64)(s64)-EMFILE;
    s32 g[2] = { sv[0], sv[1] };
    if (copy_to_guest(c, a3, g, sizeof g) < 0) {
        /* The guest never learns the two numbers, so nothing it does can ever
         * close them: a caller looping on a bad pointer would run this process
         * out of descriptors two at a time, and every fd here is the guest's
         * own (guest fd == host fd). The kernel closes them on this path too;
         * pipe2 above already did. */
        close(sv[0]);
        close(sv[1]);
        return (u64)(s64)-EFAULT;
    }
    return 0;
}

/* Import a guest sockaddr (raw bytes; layout is arch-independent). */
static int addr_in(CPU *c, u64 va, u32 len, struct sockaddr_storage *ss, socklen_t *out) {
    /* move_addr_to_kernel refuses a length it cannot use rather than trimming
     * it: an addrlen is an int, and both a negative one and one past
     * sizeof(sockaddr_storage) are EINVAL, whatever the address itself says.
     * Clamping instead -- what this did -- turned a bad length into a
     * plausible address: bind/connect/sendto then went ahead with 128 bytes of
     * whatever the guest's pointer happened to reach. An AF_UNIX address
     * cannot show it (the protocol refuses anything past sun_path either way),
     * an AF_INET one can: a kernel answers EINVAL where this answered 0. */
    if ((s32)len < 0 || len > sizeof *ss) return -EINVAL;
    /* The bytes past the guest's length are never the address, but the host
     * call takes the whole struct and the family check below reads the first
     * two of them: defined either way, rather than whatever the stack held. */
    memset(ss, 0, sizeof *ss);
    if (len && copy_from_guest(c, ss, va, len) < 0) return -EFAULT;
    *out = len;
    return 0;
}

/* Abstract AF_UNIX sockets (leading NUL in sun_path) live in one global,
 * netns-scoped namespace the unprivileged emulator can't partition — so by
 * default we isolate them per rootfs by splicing m->abs_tag in right after the
 * leading NUL. The name after the NUL is opaque bytes of length (*sl-poff-1);
 * shift it right by the tag and copy the tag in. Same rootfs -> same tag, so
 * guest processes still rendezvous, while the host and other rootfs (untagged
 * or differently tagged) don't. No-op with --share-abstract-sockets.
 *
 * A name the tag cannot fit alongside is REFUSED (-ENAMETOOLONG), not passed
 * through untagged: untagged is the host's own global namespace, so leaving it
 * there gave any guest a deliberate way out of the isolation — pick a name
 * longer than sun_path minus the tag and bind or connect anywhere in it. The
 * cost is that the isolated namespace's names are that much shorter than the
 * kernel's 107 bytes, which is the same shape of limit the rootfs prefix
 * imposes on pathname sockets below (and which reports the same errno). An
 * address longer than sun_path itself is left alone: it is invalid whatever we
 * do with it, and the kernel's own EINVAL is the better answer. */
static int abs_tag_in(CPU *c, struct sockaddr_un *un, socklen_t *sl, size_t poff) {
    size_t T = c->m->abs_tag_len, total = (size_t)*sl - poff;
    if (c->m->share_abstract || T == 0) return 0;
    if (total > sizeof un->sun_path) return 0;          /* the kernel's EINVAL */
    if (total + T > sizeof un->sun_path) return -ENAMETOOLONG;
    memmove(un->sun_path + 1 + T, un->sun_path + 1, total - 1);
    memcpy(un->sun_path + 1, c->m->abs_tag, T);
    *sl = (socklen_t)(*sl + T);
    return 0;
}

/* Reverse of abs_tag_in: strip our rootfs tag from an abstract address the
 * kernel reports back, so the guest sees its original name. Leaves foreign
 * (untagged or other-rootfs) abstract names as-is. */
static void abs_tag_out(CPU *c, struct sockaddr_un *un, socklen_t *sl, size_t poff) {
    size_t T = c->m->abs_tag_len, total = (size_t)*sl - poff;
    if (c->m->share_abstract || T == 0 || total < 1 + T) return;
    if (memcmp(un->sun_path + 1, c->m->abs_tag, T) != 0) return;   /* not ours */
    memmove(un->sun_path + 1, un->sun_path + 1 + T, total - 1 - T);
    *sl = (socklen_t)(*sl - T);
}

/* AF_UNIX pathname sockets carry a filesystem path in sun_path; route it
 * through the rootfs resolver so bind/connect/sendto reach the guest's socket,
 * not the host's. Abstract sockets are per-rootfs isolated (abs_tag_in);
 * unnamed/autobind (len<=off) and every non-AF_UNIX family pass through
 * untouched. `follow` selects final-component symlink handling: connect/sendto
 * follow, bind does not. Rewrites the address and its length in place; returns
 * 0 or -errno.
 *
 * The rootfs prefix can push the host path past the 108-byte sun_path limit.
 * When it does and `dirfd_out` is non-NULL, only the socket basename need fit:
 * open the parent directory and rewrite sun_path to "/proc/self/fd/<fd>/<base>"
 * (the kernel follows that magic symlink to the real directory). The caller
 * runs the syscall and then closes *dirfd_out. `dirfd_out` is set to -1 unless a
 * fd was opened; passing NULL keeps the plain -ENAMETOOLONG behavior. */
static int unix_path_in(CPU *c, struct sockaddr_storage *ss, socklen_t *sl,
                        int follow, int *dirfd_out) {
    if (dirfd_out) *dirfd_out = -1;
    /* An address too short to hold a family has none to look at (the host
     * refuses it by protocol); the field used to be read regardless, and a
     * guest length of 0 or 1 left it uninitialized. */
    if ((size_t)*sl < sizeof ss->ss_family) return 0;
    if (ss->ss_family != AF_UNIX) return 0;
    struct sockaddr_un *un = (struct sockaddr_un *)ss;
    const size_t poff = offsetof(struct sockaddr_un, sun_path);
    if ((size_t)*sl <= poff) return 0;         /* unnamed / autobind */
    if (un->sun_path[0] == '\0')               /* abstract namespace */
        return abs_tag_in(c, un, sl, poff);
    size_t maxp = (size_t)*sl - poff;
    if (maxp > sizeof un->sun_path) maxp = sizeof un->sun_path;
    char gpath[PATH_MAX];
    size_t i = 0;
    for (; i < maxp && un->sun_path[i]; i++) {
        if (i + 1 >= sizeof gpath) return -ENAMETOOLONG;
        gpath[i] = un->sun_path[i];
    }
    gpath[i] = 0;
    PathPin pin;
    char canon[PATH_MAX];
    int r = path_resolve(c->m, G_AT_FDCWD, gpath,
                         follow ? 0 : PATH_NOFOLLOW_LAST, pin.host, canon);
    if (r < 0) return r;
    if ((r = path_pin(c->m, canon, pin.host, &pin)) < 0) return r;
    if (!pin.pinned) {                         /* nothing to pin (the /proc zone) */
        size_t hl = strlen(pin.host);
        if (hl + 1 > sizeof un->sun_path) { path_unpin(&pin); return -ENAMETOOLONG; }
        memcpy(un->sun_path, pin.host, hl + 1);
        *sl = (socklen_t)(poff + hl + 1);
        return 0;
    }
    /* Pinned: name the socket through its parent's descriptor, so no rename can
     * redirect the bind or connect (the kernel follows that magic symlink to
     * the directory the walk found). This is also what makes a path too long
     * for the 108-byte sun_path work at all -- only the basename has to fit --
     * which is why it was already the shape of the overlong fallback. The
     * caller closes *dirfd_out once the syscall has run. */
    if (!dirfd_out) { path_unpin(&pin); return -ENAMETOOLONG; }
    char proc[sizeof un->sun_path];
    int n = snprintf(proc, sizeof proc, "/proc/self/fd/%d/%s", pin.dfd, pin.base);
    if (n < 0 || (size_t)n >= sizeof proc) { path_unpin(&pin); return -ENAMETOOLONG; }
    memcpy(un->sun_path, proc, (size_t)n + 1);
    *sl = (socklen_t)(poff + (size_t)n + 1);
    *dirfd_out = pin.dfd;                      /* handed to the caller to close --
                                                * with fdheld_close: it is a held
                                                * descriptor (machine.h) */
    return 0;
}

/* Reverse of unix_path_in: rewrite a host sun_path the kernel reports back
 * (getsockname/getpeername/accept/recvfrom/recvmsg) to its guest view, so the
 * guest never sees a host path (pathname) or our rootfs tag (abstract). No-op
 * for non-AF_UNIX and unnamed addresses. Rewrites address and length in place. */
static void unix_path_out(CPU *c, struct sockaddr_storage *ss, socklen_t *sl) {
    /* As on the way in: a length the kernel left at 0 (an unnamed datagram
     * peer) wrote no family, so there is none to read. */
    if ((size_t)*sl < sizeof ss->ss_family) return;
    if (ss->ss_family != AF_UNIX) return;
    struct sockaddr_un *un = (struct sockaddr_un *)ss;
    const size_t poff = offsetof(struct sockaddr_un, sun_path);
    if ((size_t)*sl <= poff) return;           /* unnamed */
    if (un->sun_path[0] == '\0') {             /* abstract: strip our tag */
        abs_tag_out(c, un, sl, poff);
        return;
    }
    size_t maxp = (size_t)*sl - poff;
    if (maxp > sizeof un->sun_path) maxp = sizeof un->sun_path;
    char path[PATH_MAX];
    size_t i = 0;
    for (; i < maxp && i + 1 < sizeof path && un->sun_path[i]; i++)
        path[i] = un->sun_path[i];
    path[i] = 0;
    path_strip_rootfs(c->m, path);
    size_t pl = strlen(path);
    if (pl + 1 > sizeof un->sun_path) return;   /* leave as-is if it won't fit */
    memcpy(un->sun_path, path, pl + 1);
    *sl = (socklen_t)(poff + pl + 1);
}

SYSDEF(bind) {
    /* Fake netlink socket: silent success. The stand-in is already bound to a
     * name of the emulator's own choosing (sys_netlink.c gives it one so it can
     * carry readiness), and the guest's sockaddr_nl means nothing to AF_UNIX. */
    if (nl_is_fd(c->m, (int)a0)) return 0;
    struct sockaddr_storage ss;
    socklen_t sl;
    int dfd, r = addr_in(c, a1, (u32)a2, &ss, &sl);
    if (r < 0) return (u64)(s64)r;
    if ((r = unix_path_in(c, &ss, &sl, 0, &dfd)) < 0) return (u64)(s64)r;
    u64 ret = bind((int)a0, (struct sockaddr *)&ss, sl) < 0 ? host_err() : 0;
    fdheld_close(dfd);   /* the pin's parent (unix_path_in) */
    return ret;
}

SYSDEF(connect) {
    /* As in bind: connecting a netlink socket to the kernel (nl_pid 0) is an
     * ordinary success, and letting a sockaddr_nl reach the AF_UNIX stand-in
     * would both fail and re-point the self-connection its readiness rides on. */
    if (nl_is_fd(c->m, (int)a0)) return 0;
    struct sockaddr_storage ss;
    socklen_t sl;
    int dfd, r = addr_in(c, a1, (u32)a2, &ss, &sl);
    if (r < 0) return (u64)(s64)r;
    if ((r = unix_path_in(c, &ss, &sl, 1, &dfd)) < 0) return (u64)(s64)r;
    u64 ret = connect((int)a0, (struct sockaddr *)&ss, sl) < 0 ? host_err() : 0;
    fdheld_close(dfd);   /* the pin's parent (unix_path_in) */
    return ret;
}

SYSDEF(listen) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return listen((int)a0, (int)a1) < 0 ? host_err() : 0;
}

/* Write a sockaddr back through a guest (addr, addrlen) pointer pair, with
 * move_addr_to_user's semantics -- shared with the netlink emulation
 * (sys_netlink.c), which answers the same pair for its own sockets and must be
 * indistinguishable from this one. Returns 0 or -errno.
 *
 * The kernel's order, and every consequence of it: read the caller's length
 * first, so an unreadable addrlen is EFAULT whatever else is wrong; clamp it to
 * the real address length; a negative length is EINVAL (and the caller's value
 * is left alone); copy only when the clamped length is nonzero, so an
 * unwritable -- NULL, usually -- address is EFAULT only when there was
 * something to put there; and finally report the UNtruncated length, which is
 * what POSIX asks for.
 *
 * `addr_optional` marks the calls whose address argument may be left out
 * outright: accept/accept4 test upeer_sockaddr and recvfrom tests uaddr before
 * touching the pair at all, so a NULL there is an ordinary success and the
 * addrlen pointer is never read. getsockname/getpeername have no such test --
 * a NULL address is refused unless the caller also asked for zero bytes.
 *
 * None of this special-cases a NULL pointer as such: the copy helpers reach
 * guest address 0 exactly as get_user/copy_to_user reach host address 0, and
 * fail for the same reason (nothing is mapped there). Answering a half-supplied
 * pair with a bare success -- what this used to do whenever either pointer was
 * missing -- told a guest its address had been written when it had not. */
int sock_addr_out(CPU *c, u64 addr_va, u64 len_va, const void *sa,
                  socklen_t salen, int addr_optional) {
    if (addr_optional && !addr_va) return 0;
    s32 glen;
    if (copy_from_guest(c, &glen, len_va, 4) < 0) return -EFAULT;
    if (glen > (s32)salen) glen = (s32)salen;
    if (glen < 0) return -EINVAL;
    if (glen && copy_to_guest(c, addr_va, sa, (size_t)glen) < 0) return -EFAULT;
    u32 real = salen;
    if (copy_to_guest(c, len_va, &real, 4) < 0) return -EFAULT;
    return 0;
}

/* Write back a sockaddr result (accept/getsockname/getpeername/recvfrom),
 * translating an AF_UNIX path to the guest's view on the way out. */
static u64 addr_out(CPU *c, u64 addr_va, u64 len_va, struct sockaddr_storage *ss,
                    socklen_t sl, int addr_optional) {
    if (addr_optional && !addr_va) return 0;
    unix_path_out(c, ss, &sl);   /* host sun_path -> guest view */
    return (u64)(s64)sock_addr_out(c, addr_va, len_va, ss, sl, addr_optional);
}

SYSDEF(accept) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd = accept((int)a0, (struct sockaddr *)&ss, &sl);
    if (fd < 0) return host_err();
    if (!fd_within_limit(c, fd)) return (u64)(s64)-EMFILE;
    u64 e = addr_out(c, a1, a2, &ss, sl, 1);
    if ((s64)e < 0) { close(fd); return e; }
    return (u64)fd;
}

SYSDEF(accept4) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd = accept4((int)a0, (struct sockaddr *)&ss, &sl, (int)a3);
    if (fd < 0) return host_err();
    if (!fd_within_limit(c, fd)) return (u64)(s64)-EMFILE;
    u64 e = addr_out(c, a1, a2, &ss, sl, 1);
    if ((s64)e < 0) { close(fd); return e; }
    return (u64)fd;
}

SYSDEF(getsockname) {
    if (nl_is_fd(c->m, (int)a0)) return nl_getsockname(c, a1, a2);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getsockname((int)a0, (struct sockaddr *)&ss, &sl) < 0) return host_err();
    return addr_out(c, a1, a2, &ss, sl, 0);
}

SYSDEF(getpeername) {
    if (nl_is_fd(c->m, (int)a0)) return nl_getpeername(c, a1, a2);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getpeername((int)a0, (struct sockaddr *)&ss, &sl) < 0) return host_err();
    return addr_out(c, a1, a2, &ss, sl, 0);
}

/* A send the transfer could not cover in full (sys.h: only a vector over a
 * thousand separate mappings, or a straddling buffer past XFER_STAGE_MAX on a
 * file that is no socket, gets there): a stream takes the short send it may
 * always make, but a datagram cannot go in part -- EMSGSIZE, the answer a
 * protocol gives for a message it will not carry. */
static int xfer_send_whole(int fd, const GuestXfer *x, size_t want) {
    if (x->total >= want) return 0;
    int type = 0;
    socklen_t tl = sizeof type;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 && type == SOCK_STREAM)
        return 0;
    return -EMSGSIZE;
}

SYSDEF(sendto) {
    if (nl_is_fd(c->m, (int)a0)) return nl_sendto(c, (int)a0, a1, a2);
    size_t len = rw_count(a2);
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    struct sockaddr *dp = NULL;
    int dfd = -1;
    if (a4 && a5) {
        /* addr_in's own answer, not a blanket EFAULT: an addrlen the kernel
         * refuses to use (negative, or past sizeof(sockaddr_storage)) is
         * EINVAL there, and reporting EFAULT for it sends a caller looking at
         * its pointer instead of its length. bind/connect already pass it on. */
        int ar = addr_in(c, a4, (u32)a5, &ss, &sl);
        if (ar < 0) return (u64)(s64)ar;
        int tr = unix_path_in(c, &ss, &sl, 1, &dfd);
        if (tr < 0) return (u64)(s64)tr;
        dp = (struct sockaddr *)&ss;
    }
    /* As far as the guest's memory goes, and the rest handed to the host as a
     * fault in the same place (sys.h): the protocol copies the data last,
     * after the address above and everything else it checks, and it is what
     * decides what a fault means -- nothing sent of a datagram, the packets
     * of a stream it copied whole. The whole buffer used to be demanded up
     * front, which made every such send EFAULT, and ahead of the protocol's
     * own answers. */
    size_t room = len ? rw_room(c, a1, len, ACC_READ) : 0;
    GIovec g = { a1, room };
    XferCut cut = { len - room, 0 };
    /* A reconfiguring rtnetlink request from a guest with a faked network
     * namespace: note it, so the kernel's refusal becomes an ack on receive. */
    nlr_note_gvec(c, (int)a0, &g, 1);
    /* MSG_ZEROCOPY has the socket go on referencing the pages after the call
     * returns, so those have to be the guest's own (msg_import has the rest). */
    int zc = (int)a3 & MSG_ZEROCOPY;
    GuestXfer x;
    int r = xfer_begin(c, (int)a0, &g, 1, 0, zc ? XFER_LEND : 0, &cut, NULL, &x);
    /* (A guarded staging is a file that is no socket -- sys.h: a socket
     * takes its fault lent -- and the host answers ENOTSOCK without looking.) */
    if (r == 0 && zc && x.stage && !x.guarded) { xfer_end(c, &x, 0); r = -ENOBUFS; }
    if (r == 0 && (r = xfer_send_whole((int)a0, &x, room)) < 0) xfer_end(c, &x, 0);
    if (r < 0) { fdheld_close(dfd); return (u64)(s64)r; }
    ssize_t n;
    if (x.n == 1) {
        n = sendto((int)a0, x.iov[0].iov_base, x.iov[0].iov_len, (int)a3, dp, sl);
    } else {
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_name = dp;
        mh.msg_namelen = sl;
        mh.msg_iov = x.iov;
        mh.msg_iovlen = (size_t)x.n;
        n = sendmsg((int)a0, &mh, (int)a3);
    }
    u64 e = xfer_finish(c, &x, n);   /* before the close(2) below */
    fdheld_close(dfd);   /* the pin's parent (unix_path_in) */
    return e;
}

SYSDEF(recvfrom) {
    /* A fake netlink socket with a reply waiting is answered here; with none it
     * falls through, so the read waits on the (always empty) substitute socket
     * rather than being handed a zero-length datagram (sys_netlink.c). */
    u64 nlret;
    if (nl_is_fd(c->m, (int)a0) &&
        nl_maybe_recvfrom(c, (int)a0, a1, a2, (int)a3, a4, a5, &nlret))
        return nlret;
    /* Clamped only: shortening the buffer would truncate the datagram the host
     * hands over -- and it is gone once received -- while a guest that names
     * more room than it has is still entitled to a datagram that fits in what
     * it does have, so the room cannot be demanded up front either. What it
     * does not have is handed to the host as a fault in the same place, where
     * the host kernel's copy stops exactly where the guest's kernel would
     * (sys.h); this used to allocate everything the guest named before the
     * socket had anything to deliver. */
    size_t len = rw_count(a2);
    size_t room = len ? rw_room(c, a1, len, ACC_WRITE) : 0;
    GIovec g = { a1, room };
    XferCut cut = { len - room, 0 };
    GuestXfer x;
    int r = xfer_begin(c, (int)a0, &g, 1, 1, 0, &cut, NULL, &x);
    if (r < 0) return (u64)(s64)r;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    ssize_t n;
    if (x.n == 1) {
        n = recvfrom((int)a0, x.iov[0].iov_base, x.iov[0].iov_len, (int)a3,
                     (struct sockaddr *)&ss, &sl);
    } else {
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_name = &ss;
        mh.msg_namelen = sl;
        mh.msg_iov = x.iov;
        mh.msg_iovlen = (size_t)x.n;
        n = recvmsg((int)a0, &mh, (int)a3);
        sl = mh.msg_namelen;
    }
    u64 e = xfer_finish(c, &x, n);
    if ((s64)e < 0) return e;
    /* Turn the refusal of a request against a faked network namespace into the
     * kernel's own ack, before the guest sees the reply. MSG_TRUNC reports the
     * untruncated length, so clamp to what the buffer actually holds. */
    if (n > 0) nlr_fix_gvec(c, (int)a0, &g, 1, (size_t)n < room ? (size_t)n : room,
                            (int)a3 & MSG_PEEK);
    u64 ae = addr_out(c, a4, a5, &ss, sl, 1);
    if ((s64)ae < 0) return ae;
    return e;
}

SYSDEF(shutdown) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return shutdown((int)a0, (int)a1) < 0 ? host_err() : 0;
}

/* SO_ATTACH_FILTER / SO_ATTACH_REUSEPORT_CBPF: the optval is not a byte blob
 * but a struct sock_fprog whose second field is a POINTER to the classic-BPF
 * program. Passed through raw, the kernel dereferences the guest VA as an
 * emulator address -- attaching a filter built from unrelated emulator memory,
 * or failing with EFAULT -- and on ILP32 hosts the guest's 16-byte fprog is
 * not even the host's 8-byte one. Bounce the program (sock_filter is 8 bytes
 * of plain integers on every ABI) and rebuild the fprog host-side. A NULL
 * program is handed through unbounced so the kernel keeps its own error
 * order: a SO_LOCK_FILTERed socket answers EPERM before the NULL's EINVAL. */
static u64 sockopt_attach_fprog(CPU *c, int fd, int optname, const u8 *gopt,
                                size_t glen) {
    if (glen != 16) return (u64)(s64)-EINVAL;   /* kernel: optlen == sizeof(fprog) */
    u16 flen; u64 fva;
    memcpy(&flen, gopt, 2);
    memcpy(&fva, gopt + 8, 8);
    struct sock_fprog h = { .len = flen, .filter = NULL };
    struct sock_filter *prog = NULL;
    if (fva) {
        size_t fsize = (size_t)flen * sizeof *prog;
        prog = malloc(fsize ? fsize : 1);
        if (!prog) return (u64)(s64)-ENOMEM;
        if (copy_from_guest(c, prog, fva, fsize) < 0) {
            free(prog);
            return (u64)(s64)-EFAULT;
        }
        h.filter = prog;
    }
    int r = setsockopt(fd, SOL_SOCKET, optname, &h, sizeof h);
    u64 ret = r < 0 ? host_err() : 0;
    free(prog);
    return ret;
}

/* The option value once it is staged host-side: all of it for a generic
 * option (a longer one goes to sockopt_set_large instead), the head of it --
 * everything they read -- for the ones translated here. */
static u64 sockopt_set(CPU *c, u64 a0, u64 a1, u64 a2, const u8 *buf, size_t len) {
    /* Literal guest option values (asm-generic; the host macros match on x86
     * and arm, but the guest ABI is what is being decoded here). */
    if ((int)a1 == SOL_SOCKET &&
        ((int)a2 == 26 /*SO_ATTACH_FILTER*/ ||
         (int)a2 == 51 /*SO_ATTACH_REUSEPORT_CBPF*/))
        return sockopt_attach_fprog(c, (int)a0,
                                    (int)a2 == 26 ? SO_ATTACH_FILTER
                                                  : SO_ATTACH_REUSEPORT_CBPF,
                                    buf, len);
    /* SO_RCVTIMEO / SO_SNDTIMEO (guest 20/21) carry a struct timeval: 16
     * bytes in the guest's LP64 ABI, but an ILP32 host's old-style timeval
     * is 8 -- and a time64 32-bit libc (musl 1.2+) renumbers the option to
     * the 64-bit variant outright. Re-issue the option through the host
     * libc's own macro and struct so every host tier parses what the guest
     * sent. On LP64 hosts macro and layout already match the guest and the
     * branch folds away. The usec range check must run before the width
     * narrowing: the kernel answers EDOM, and truncation could turn an
     * out-of-range value into a valid one. */
    if ((SO_RCVTIMEO != 20 || sizeof(struct timeval) != 16) &&
        (int)a1 == SOL_SOCKET && ((int)a2 == 20 || (int)a2 == 21)) {
        if (len < 16) return (u64)(s64)-EINVAL;   /* kernel: optlen < sizeof(tv) */
        s64 gsec, gusec;
        memcpy(&gsec, buf, 8);
        memcpy(&gusec, buf + 8, 8);
        if (gusec < 0 || gusec >= 1000000) return (u64)(s64)-EDOM;
        struct timeval tv;
        s64 smax = (s64)((1ULL << (sizeof tv.tv_sec * 8 - 1)) - 1);
        tv.tv_sec = (time_t)(gsec > smax ? smax : gsec < -smax - 1 ? -smax - 1 : gsec);
        tv.tv_usec = (suseconds_t)gusec;
        return setsockopt((int)a0, SOL_SOCKET,
                          (int)a2 == 20 ? SO_RCVTIMEO : SO_SNDTIMEO,
                          &tv, sizeof tv) < 0 ? host_err() : 0;
    }
    return setsockopt((int)a0, (int)a1, (int)a2, buf, (socklen_t)len) < 0 ? host_err() : 0;
}

/* The options sockopt_set translates rather than hands through: each reads a
 * fixed struct of its own and no more, and judges the length before it does. */
static int sockopt_is_fprog(int level, int name) {
    return level == SOL_SOCKET && (name == 26 || name == 51);
}
static int sockopt_translated(int level, int name) {
    return sockopt_is_fprog(level, name) ||
           ((SO_RCVTIMEO != 20 || sizeof(struct timeval) != 16) &&
            level == SOL_SOCKET && (name == 20 || name == 21));
}

/* A generic option value past the stack staging: handed to the host in the
 * guest's own pages when they are one run of host memory (sys.h, GuestXfer),
 * and otherwise staged -- no more than XFER_STAGE_MAX of it, in front of a
 * guard (guardbuf_map, sys.h). Staging all of it, as this used to, let a guest
 * name INT_MAX bytes of untouched pages and have the emulator commit that
 * much copying them in, for an option a kernel reads four bytes of. Should the
 * kernel read past what was staged while the guest has more, the option is
 * one that really takes it all -- a netfilter table, which the kernel then
 * allocates as much for itself -- and it is staged whole and asked again: the
 * copy-in happens before anything is applied, so the first attempt changed
 * nothing. */
static u64 sockopt_set_large(CPU *c, int fd, int level, int name, u64 va,
                             size_t len) {
    size_t room = rw_room(c, va, len, ACC_READ);
    if (room == len) {
        GIovec g = { va, len };
        GuestXfer x;
        int r = xfer_begin(c, fd, &g, 1, 0, XFER_LEND, NULL, NULL, &x);
        if (r < 0) return (u64)(s64)r;
        if (x.n == 1 && !x.stage && x.total == len) {
            int rr = setsockopt(fd, level, name, x.iov[0].iov_base, (socklen_t)len);
            u64 e = rr < 0 ? host_err() : 0;
            xfer_end(c, &x, 0);
            return e;
        }
        xfer_end(c, &x, 0);
    }
    size_t head = room < XFER_STAGE_MAX ? room : XFER_STAGE_MAX;
    for (;;) {
        GuardBuf ob;
        u8 *p = guardbuf_map(&ob, head, len);
        if (!p) return (u64)(s64)-ENOMEM;
        if (head && copy_from_guest(c, p, va, head) < 0) {
            guardbuf_free(&ob);
            return (u64)(s64)-EFAULT;
        }
        int err = setsockopt(fd, level, name, p, (socklen_t)len) < 0 ? errno : 0;
        guardbuf_free(&ob);
        if (err == EFAULT && head < room) { head = room; continue; }
        return err ? (u64)(s64)-err : 0;
    }
}

SYSDEF(setsockopt) {
    /* optlen reaches the kernel as an int and a negative one is EINVAL before
     * anything else is looked at (do_sock_setsockopt). Reading the register as
     * a size_t and refusing everything over 4 KB, as this used to, arrived at
     * that answer by accident -- and refused with it every option value larger
     * than the emulator's staging buffer, a limit the kernel does not have and
     * a guest-visible one. Netfilter's table replace and a large
     * MCAST_MSFILTER are the option values that reach that size; the kernel
     * bounds them by its own optmem_max budget and answers ENOBUFS, which it
     * can only do once it is handed what the guest sent. */
    s32 optlen = (s32)a4;
    if (optlen < 0) return (u64)(s64)-EINVAL;
    size_t len = (size_t)optlen;
    u8 sbuf[4096];
    if (len > sizeof sbuf) {
        /* A translated option costs only its own struct, and a filter
         * program's length is judged before a byte is read (EINVAL for
         * anything but sizeof(sock_fprog), whatever is at the pointer). */
        if (sockopt_is_fprog((int)a1, (int)a2)) return (u64)(s64)-EINVAL;
        if (sockopt_translated((int)a1, (int)a2)) {
            if (copy_from_guest(c, sbuf, a3, 16) < 0) return (u64)(s64)-EFAULT;
            return sockopt_set(c, a0, a1, a2, sbuf, len);
        }
        return sockopt_set_large(c, (int)a0, (int)a1, (int)a2, a3, len);
    }
    /* A zero-length option value stages nothing, and nothing can be read back
     * out of the staging either -- the optlen handed to the host is what makes
     * that true, not the pointer. Leave it in a defined state all the same:
     * what setsockopt(2) is given is an address the host is entitled to read
     * `len` bytes through, and untouched stack is not that. (The 32-bit build
     * is where gcc notices, and it is right to.) */
    if (!len) sbuf[0] = 0;
    else if (copy_from_guest(c, sbuf, a3, len) < 0) return (u64)(s64)-EFAULT;
    return sockopt_set(c, a0, a1, a2, sbuf, len);   /* errno consumed already */
}

/* A generic option read back into a buffer past the stack staging -- the
 * mirror of sockopt_set_large: straight into the guest's pages when they are
 * one run of host memory, otherwise into no more than XFER_STAGE_MAX in front
 * of a guard (guardbuf_map, sys.h), and staged whole only for an option that
 * turns out to write more (a netfilter table's entries, which the kernel
 * holds that much of itself). `len` is what the kernel may write, already
 * bounded by the guest's buffer. Returns the length the kernel reported --
 * never past what it can have written, the check the stack path makes too --
 * or -errno. */
static s64 sockopt_get_large(CPU *c, int fd, int level, int name, u64 va,
                             size_t len) {
    GIovec g = { va, len };
    GuestXfer x;
    int r = xfer_begin(c, fd, &g, 1, 1, XFER_LEND, NULL, NULL, &x);
    if (r < 0) return r;
    if (x.n == 1 && !x.stage && x.total == len) {
        socklen_t sl = (socklen_t)len;
        s64 e = getsockopt(fd, level, name, x.iov[0].iov_base, &sl) < 0 ? -errno : 0;
        xfer_end(c, &x, 0);
        if (e < 0) return e;
        return (size_t)sl > len ? (s64)len : (s64)sl;
    }
    xfer_end(c, &x, 0);
    size_t head = len < XFER_STAGE_MAX ? len : XFER_STAGE_MAX;
    for (;;) {
        GuardBuf ob;
        u8 *p = guardbuf_map(&ob, head, len);
        if (!p) return -ENOMEM;
        socklen_t sl = (socklen_t)len;
        int err = getsockopt(fd, level, name, p, &sl) < 0 ? errno : 0;
        if (err == EFAULT && head < len) { guardbuf_free(&ob); head = len; continue; }
        if (!err && (size_t)sl > head) sl = (socklen_t)head;
        if (!err && sl && copy_to_guest(c, va, p, sl) < 0) err = EFAULT;
        guardbuf_free(&ob);
        return err ? -err : (s64)sl;
    }
}

SYSDEF(getsockopt) {
    /* The output pointers are the kernel's first business, ahead of the option
     * name: sk_getsockopt reads the caller's length before the switch, so an
     * unreadable optlen is EFAULT and a negative one is EINVAL whatever was
     * asked for. The value is then written only when that length -- clamped to
     * what the option is worth -- leaves something to write, which is why an
     * ask for zero bytes succeeds with no optval buffer at all. Taking a
     * missing optlen for "length 0" and bouncing a missing optval through a
     * local buffer, as this used to, made both of those a silent success: the
     * guest was told its option had been read out to memory that never
     * received it. */
    s32 glen;
    if (copy_from_guest(c, &glen, a4, 4) < 0) return (u64)(s64)-EFAULT;
    if (glen < 0) return (u64)(s64)-EINVAL;
    /* The reverse of setsockopt's SO_RCVTIMEO/SO_SNDTIMEO conversion: on a
     * host whose timeval is not the guest's 16-byte one the kernel would
     * write 8 bytes where the guest expects 16, read back as a garbage
     * tv_sec. Same macro-renumbering note as there. */
    if ((SO_RCVTIMEO != 20 || sizeof(struct timeval) != 16) &&
        (int)a1 == SOL_SOCKET && ((int)a2 == 20 || (int)a2 == 21)) {
        /* Zeroed before the call, and the length the host reports is what
         * decides how much of it is real. A kernel always writes the whole
         * struct here, so trusting it is invisible on a kernel -- but this is
         * the emulator's own stack, and handing the guest the part of it the
         * host did not write is the same disclosure the ioctl table's memset
         * and the SIMD-pair fix exist to prevent. It is not hypothetical: run
         * the ILP32 build under qemu-user, whose getsockopt reports optlen 4
         * for this option and writes nothing at all, and the guest read back a
         * tv_usec of 2^32 -- a leftover from this frame, not a timeout. */
        struct timeval tv;
        memset(&tv, 0, sizeof tv);
        socklen_t tl = sizeof tv;
        if (getsockopt((int)a0, SOL_SOCKET,
                       (int)a2 == 20 ? SO_RCVTIMEO : SO_SNDTIMEO, &tv, &tl) < 0)
            return host_err();
        u8 g[16];
        memset(g, 0, sizeof g);
        s64 v;
        if ((size_t)tl >= sizeof tv.tv_sec) { v = (s64)tv.tv_sec; memcpy(g, &v, 8); }
        if ((size_t)tl >= sizeof tv) { v = (s64)tv.tv_usec; memcpy(g + 8, &v, 8); }
        u32 outl = (u32)glen < 16 ? (u32)glen : 16;   /* kernel: len = min(len, lv) */
        if (outl && copy_to_guest(c, a3, g, outl) < 0) return (u64)(s64)-EFAULT;
        if (copy_to_guest(c, a4, &outl, 4) < 0) return (u64)(s64)-EFAULT;
        return 0;
    }
    /* SO_GET_FILTER (== SO_ATTACH_FILTER, 26) does not answer in the unit it is
     * asked in, so the caller's optlen is no bound at all on what the kernel
     * writes: sk_get_filter compares the byte length it was handed against the
     * attached program's INSTRUCTION count, then copies the whole program --
     * eight bytes per instruction -- and reports that instruction count back as
     * the length. A 600-instruction filter read back with an optlen of 600, or
     * of 4096, has 4800 bytes written into the buffer. The buffer here was the
     * emulator's own 4 KB stack array, so a guest that attached a filter of
     * more than 512 instructions and read it back smashed the emulator's stack
     * -- "*** stack smashing detected ***", from an ordinary unprivileged guest.
     *
     * Stage it where the kernel cannot outrun it. BPF_MAXINSNS is the ceiling
     * bpf_check_classic enforces at attach time, so 4096 * 8 bytes bounds any
     * program that can be attached -- including one a sibling guest thread
     * swaps in between this call's steps, which is why the size is a constant
     * and not a first "how long is it?" enquiry. The staging is zeroed, and the
     * copy back is the eight-bytes-per-instruction the kernel really wrote:
     * treating the reported length as a byte count copied stale bytes for a
     * short program and, for the optlen-0 enquiry -- which writes nothing and
     * only reports the count -- handed the guest that many bytes of the
     * emulator's own memory. qemu-user answers EINVAL for this option and is no
     * oracle for it; tests/fixtures/sockfilter_get.c checks it against the
     * kernel's documented behaviour instead. */
    if ((int)a1 == SOL_SOCKET && (int)a2 == 26 /*SO_GET_FILTER*/) {
        size_t cap = (size_t)BPF_MAXINSNS * sizeof(struct sock_filter);
        u8 *fb = calloc(1, cap);
        if (!fb) return (u64)(s64)-ENOMEM;
        socklen_t fl = (socklen_t)(u32)glen;
        if (getsockopt((int)a0, SOL_SOCKET, SO_ATTACH_FILTER, fb, &fl) < 0) {
            u64 e = host_err();
            free(fb);
            return e;
        }
        size_t wrote = glen ? (size_t)fl * sizeof(struct sock_filter) : 0;
        if (wrote > cap) wrote = cap;
        int bad = wrote && copy_to_guest(c, a3, fb, wrote) < 0;
        free(fb);
        if (bad) return (u64)(s64)-EFAULT;
        u32 ninsn = (u32)fl;
        if (copy_to_guest(c, a4, &ninsn, 4) < 0) return (u64)(s64)-EFAULT;
        return 0;
    }
    /* Answer the whole of what the guest asked for, not the first 4 KB of it.
     * The kernel writes as much of the option as its own length allows and
     * reports what it wrote, so a fixed ceiling here silently truncated any
     * option value larger than it and told the guest the short answer was the
     * whole one.
     *
     * Bounded by the guest's own buffer rather than by a constant: what will
     * not fit there could never have reached it -- the kernel's copy_to_user
     * stops at the same page and answers EFAULT, which the writeback below
     * still produces -- and allocating for it would let a guest name a length
     * it has no memory for and leave the emulator to find the room (rw_room,
     * sys.h). Past the stack buffer, the answer goes straight into the
     * guest's pages, or through a bounded staging (sockopt_get_large); the
     * stack buffer stays the floor, so nothing that fitted before changes.
     * SO_PEERCRED stays on the stack whatever was asked: it is 12 bytes, and
     * its fields are rewritten below before the guest may see them. */
    u8 sbuf[4096];
    u8 *buf = sbuf;
    size_t cap = (size_t)(u32)glen;
    int peercred = (int)a1 == SOL_SOCKET && (int)a2 == SO_PEERCRED;
    if (cap > sizeof sbuf) {
        size_t room = rw_room(c, a3, cap, ACC_WRITE);
        if (cap > room) cap = room;
        if (cap < sizeof sbuf || peercred) cap = sizeof sbuf;
        if (cap > sizeof sbuf) {
            s64 r = sockopt_get_large(c, (int)a0, (int)a1, (int)a2, a3, cap);
            if (r < 0) return (u64)r;
            u32 real = (u32)r;
            return copy_to_guest(c, a4, &real, 4) < 0 ? (u64)(s64)-EFAULT : 0;
        }
    }
    socklen_t sl = (socklen_t)cap;
    if (getsockopt((int)a0, (int)a1, (int)a2, buf, &sl) < 0) return host_err();
    /* Never take the reported length past the staging. Options answer in the
     * units they were asked in -- all but SO_GET_FILTER, which is handled
     * above precisely because it does not -- and this is the check that keeps
     * a future one from copying out of the emulator's memory. */
    if ((size_t)sl > cap) sl = (socklen_t)cap;
    /* SO_PEERCRED: struct ucred is {pid,uid,gid}, three u32s, the same layout
     * on every host, and the kernel copies out as much of it as was asked for
     * -- so each field is translated when it was answered at all. The pid is
     * the peer's as the guest may see it (proctab_pid_view, held: the socket
     * keeps its peer's pid alive), 0 for a host process at the other end --
     * a guest connected to a host daemon's socket through a bind used to read
     * the daemon's host pid here, a process it can see nowhere else. Under
     * -fake-id the uid/gid are the peer's *real* invoking ones; present the
     * fake identity instead (same remap as stat ownership), so peer-uid
     * checks — tmux's server ACL, polkit, ... — agree with getuid(). */
    if ((int)a1 == SOL_SOCKET && (int)a2 == SO_PEERCRED) {
        if (sl >= 4) {
            s32 pid;
            memcpy(&pid, buf, 4);
            pid = proctab_pid_view(pid, 1);
            memcpy(buf, &pid, 4);
        }
        if (c->m->fake_id && sl >= 8) {
            u32 uid;
            memcpy(&uid, buf + 4, 4);
            uid = remap_uid(c->m, uid);
            memcpy(buf + 4, &uid, 4);
        }
        if (c->m->fake_id && sl >= 12) {
            u32 gid;
            memcpy(&gid, buf + 8, 4);
            gid = remap_gid(c->m, gid);
            memcpy(buf + 8, &gid, 4);
        }
    }
    u32 real = sl;
    if (sl && copy_to_guest(c, a3, buf, sl) < 0) return (u64)(s64)-EFAULT;
    if (copy_to_guest(c, a4, &real, 4) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

/* guest msghdr (LP64): {name*, namelen u32, pad, iov*, iovlen u64, control*,
 * controllen u64, flags s32}. Bounce the iov data and control buffer. */
typedef struct {
    u64 msg_name;
    u32 msg_namelen; u32 _pad;
    u64 msg_iov;
    u64 msg_iovlen;
    u64 msg_control;
    u64 msg_controllen;
    s32 msg_flags; u32 _pad2;
} GMsghdr;

/* ---- ancillary data: guest cmsghdr <-> host cmsghdr ----
 *
 * The guest's is LP64 -- {u64 cmsg_len; s32 cmsg_level; s32 cmsg_type;}, data
 * at +16, each element padded up to a multiple of 8. A 64-bit host's is byte
 * for byte the same, but an ILP32 host's cmsg_len is 4 bytes wide, which makes
 * the header 12 and the padding 4. Handing that host a guest-shaped buffer
 * verbatim gives it a cmsg_len read out of the wrong half of the field and a
 * level/type read out of the payload, so nothing survived the trip: SCM_RIGHTS
 * fd passing over AF_UNIX simply did not work on the 32-bit build.
 *
 * Both directions run on every host rather than being compiled out where the
 * layouts agree, so the common build exercises the same code -- and so the
 * guest's buffer is validated rather than trusted. Descriptors inside
 * SCM_RIGHTS need no translation of their own: guest fds are host fds. */
#define GCMSG_HDRLEN   16u
#define GCMSG_ALIGN(n) (((n) + 7u) & ~(u64)7u)

/* Guest control buffer -> host. Returns the host controllen, or -1 if the
 * buffer is malformed or the result would not fit (the caller reports EINVAL,
 * as the kernel does for a control buffer it cannot parse or cannot hold).
 *
 * The walk is the kernel's, element for element: it starts only if a whole
 * header fits (CMSG_FIRSTHDR), steps only to a header that fits whole
 * (CMSG_NXTHDR), and every element it does reach must satisfy CMSG_OK --
 * cmsg_len no smaller than a header and no larger than what is left of the
 * buffer. An element that fails that is an error, not a place to stop: every
 * send path validates the control buffer before it looks at anything in it
 * (__scm_send, sock_cmsg_send, ip_cmsg_send all bail with EINVAL), so a
 * message whose ancillary data is malformed is never sent at all. Stopping
 * instead used to send the message with the offending element and everything
 * after it silently dropped, and report success. */
/* --fake-id and SCM_CREDENTIALS. The guest sends its own identity as it
 * knows it -- {getpid(), getuid(), getgid()} is what dbus authentication,
 * sd_notify and polkit put in the element -- and the kernel judges the uid and
 * gid against the sender's REAL credentials (scm_check_creds): a fake root
 * sending uid 0 was refused EPERM by a host whose task is uid 1000. So a uid
 * or gid that is one of the guest's own fake credentials goes out as the host
 * identity it stands for, and comes back in (cmsg_h2g, and SO_PEERCRED above)
 * as the fake one again, through the same remap every stat uses. An id that
 * is neither is left alone: a fake root has CAP_SETUID in its own eyes and
 * may send any id, and the host will refuse one that is not its own -- the
 * one refusal the mapping cannot lift. */
static void cred_g2h(const struct Machine *m, u8 *ucred /* {pid,uid,gid} */) {
    u32 uid, gid;
    memcpy(&uid, ucred + 4, 4);
    memcpy(&gid, ucred + 8, 4);
    Cred cr_;
    cred_get(m, &cr_);
    const Cred *cr = &cr_;
    if (uid == cr->ruid || uid == cr->euid || uid == cr->suid || uid == m->fake_uid)
        uid = m->host_uid;
    if (gid == cr->rgid || gid == cr->egid || gid == cr->sgid || gid == m->fake_gid)
        gid = m->host_gid;
    memcpy(ucred + 4, &uid, 4);
    memcpy(ucred + 8, &gid, 4);
}

static ssize_t cmsg_g2h(const struct Machine *m, const u8 *gb, size_t glen,
                        u8 *hb, size_t hcap) {
    size_t goff = 0, hoff = 0;
    while (goff + GCMSG_HDRLEN <= glen) {
        u64 clen;
        s32 level, type;
        memcpy(&clen, gb + goff, 8);
        memcpy(&level, gb + goff + 8, 4);
        memcpy(&type, gb + goff + 12, 4);
        /* Bound by subtraction: clen is a guest u64 and must not be trusted to
         * advance the walk (see the netlink walks for the same hazard). */
        if (clen < GCMSG_HDRLEN || clen > glen - goff) return -1;
        size_t dlen = (size_t)(clen - GCMSG_HDRLEN);
        size_t hel = CMSG_LEN(dlen), hstep = CMSG_ALIGN(hel);
        if (hstep > hcap - hoff) return -1;
        struct cmsghdr ch;
        memset(&ch, 0, sizeof ch);
        ch.cmsg_len = hel;
        ch.cmsg_level = level;
        ch.cmsg_type = type;
        memset(hb + hoff, 0, hstep);
        memcpy(hb + hoff, &ch, sizeof ch);
        memcpy(hb + hoff + CMSG_ALIGN(sizeof ch), gb + goff + GCMSG_HDRLEN, dlen);
        if (m->fake_id && level == SOL_SOCKET && type == SCM_CREDENTIALS && dlen >= 12)
            cred_g2h(m, hb + hoff + CMSG_ALIGN(sizeof ch));
        hoff += hstep;
        goff += (size_t)GCMSG_ALIGN(clen);
    }
    return (ssize_t)hoff;
}

/* Close every descriptor in the SCM_RIGHTS elements from `hoff` on: the ones
 * the walk below is not going to report. The host kernel installed them --
 * against ITS buffer, which on an ILP32 host holds more of them than the
 * guest's can -- and a descriptor the guest is never told the number of is
 * one it can never close, a hidden entry in its own table. */
static void cmsg_close_rights(const u8 *hb, size_t hoff, size_t hlen) {
    while (hoff + CMSG_ALIGN(sizeof(struct cmsghdr)) <= hlen) {
        struct cmsghdr ch;
        memcpy(&ch, hb + hoff, sizeof ch);
        size_t clen = ch.cmsg_len;
        if (clen < CMSG_LEN(0) || clen > hlen - hoff) break;
        if (ch.cmsg_level == SOL_SOCKET && ch.cmsg_type == SCM_RIGHTS) {
            size_t nfd = (clen - CMSG_LEN(0)) / sizeof(int);
            const u8 *fdp = hb + hoff + CMSG_ALIGN(sizeof(struct cmsghdr));
            for (size_t i = 0; i < nfd; i++) {
                int rfd;
                memcpy(&rfd, fdp + i * sizeof(int), sizeof rfd);
                close(rfd);
            }
        }
        hoff += CMSG_ALIGN(clen);
    }
}

/* Host control buffer -> guest, in the guest's layout and bounded by the
 * guest's buffer. Sets *ctrunc when anything had to be dropped or cut short.
 *
 * Whatever is dropped or cut short from an SCM_RIGHTS element is CLOSED. The
 * kernel installs only as many descriptors as the caller's buffer has room to
 * report (scm_detach_fds: fdmax from the remaining controllen, the rest of
 * the file list is released unopened), so every installed descriptor is a
 * reported one. Here the host has already installed them into a buffer of
 * its own layout, and on an ILP32 host that layout is four bytes tighter per
 * element than the guest's -- so the host fits descriptors the guest's
 * buffer cannot report. Those used to stay open: trimmed from the element by
 * the generic truncation below, or left in an element the walk never reached,
 * with the guest told MSG_CTRUNC and nothing else. The trim is now decided
 * where the element is walked, from the room the guest's buffer has left,
 * and an element the walk cannot place is closed along with everything after
 * it. */
static size_t cmsg_h2g(const struct Machine *m, const u8 *hb, size_t hlen,
                       u8 *gb, size_t gcap, int *ctrunc, int fdcap) {
    size_t hoff = 0, goff = 0;
    while (hoff + CMSG_ALIGN(sizeof(struct cmsghdr)) <= hlen) {
        struct cmsghdr ch;
        memcpy(&ch, hb + hoff, sizeof ch);
        size_t clen = ch.cmsg_len;
        if (clen < CMSG_LEN(0) || clen > hlen - hoff) break;
        /* The element as the HOST laid it out. The SCM_RIGHTS trim below can
         * shorten what is passed on, and the walk still has to step over the
         * whole of what arrived. */
        size_t hstep = CMSG_ALIGN(clen);
        size_t avail = gcap - goff;
        {
            s32 lvl = ch.cmsg_level, typ = ch.cmsg_type;
            if (lvl == SOL_SOCKET && typ == SCM_RIGHTS) {
                /* Every arriving descriptor is subject to the guest's own
                 * RLIMIT_NOFILE. The host installed them against ITS limit,
                 * which is the hard one (sys.h), so any that landed at or above
                 * the guest's ceiling are ones scm_detach_fds would never have
                 * installed: it stops at the first it cannot place, keeps the
                 * ones before it and raises MSG_CTRUNC. So does this -- and the
                 * ones it drops are closed here, since the guest never learns
                 * the numbers and could not close them itself.
                 *
                 * And every one is subject to the guest's buffer: scm_max_fds
                 * is how many the room left can carry after a header (a
                 * buffer that holds only the header carries none, and then
                 * no element is emitted at all), the descriptors past that
                 * are never installed -- so the ones the host installed past
                 * it are closed here, the same way. The kernel takes the
                 * lowest free numbers in order, as the host did, so the
                 * survivors are exactly the set it would have installed.
                 *
                 * The survivors are then classified: they may be another
                 * process's tier memfds, and the cache must stop assuming these
                 * numbers are plain files. */
                size_t nfd = (clen - CMSG_LEN(0)) / sizeof(int);
                const u8 *fdp = hb + hoff + CMSG_ALIGN(sizeof(struct cmsghdr));
                size_t keep = nfd;
                size_t fit = avail > GCMSG_HDRLEN ? (avail - GCMSG_HDRLEN) / sizeof(int) : 0;
                if (keep > fit) keep = fit;
                int rfd;
                for (size_t i = 0; i < keep; i++) {
                    memcpy(&rfd, fdp + i * sizeof(int), sizeof rfd);
                    if (rfd >= fdcap) { keep = i; break; }
                }
                for (size_t i = keep; i < nfd; i++) {
                    memcpy(&rfd, fdp + i * sizeof(int), sizeof rfd);
                    close(rfd);
                }
                for (size_t i = 0; i < keep; i++) {
                    memcpy(&rfd, fdp + i * sizeof(int), sizeof rfd);
                    mfd_track_recv(rfd);
                }
                if (keep < nfd) {
                    *ctrunc = 1;
                    /* Nothing placed: the kernel emits no element at all. */
                    if (!keep) { hoff += hstep; continue; }
                    clen = CMSG_LEN(keep * sizeof(int));
                }
            }
        }
        size_t dlen = clen - CMSG_LEN(0);
        u64 gel = GCMSG_HDRLEN + (u64)dlen;
        if (gel > avail) {
            /* Too big for what is left. The kernel's put_cmsg does not drop
             * the element -- it writes the header with the *truncated* length,
             * copies as much payload as fits, and raises MSG_CTRUNC. An ILP32
             * host reaches this where a real LP64 kernel would, because the
             * guest's element is four bytes bigger than the host's. (Never an
             * SCM_RIGHTS element: those were cut to fit above, descriptors
             * and all.) */
            *ctrunc = 1;
            if (avail < GCMSG_HDRLEN) {          /* not even a header fits */
                cmsg_close_rights(hb, hoff, hlen);
                return goff;
            }
            gel = avail;
            dlen = (size_t)gel - GCMSG_HDRLEN;
        }
        size_t gstep = (size_t)GCMSG_ALIGN(gel);
        if (gstep > avail) gstep = avail;      /* last element: no room to pad */
        s32 level = ch.cmsg_level, type = ch.cmsg_type;
        memset(gb + goff, 0, gstep);
        memcpy(gb + goff, &gel, 8);
        memcpy(gb + goff + 8, &level, 4);
        memcpy(gb + goff + 12, &type, 4);
        memcpy(gb + goff + GCMSG_HDRLEN,
               hb + hoff + CMSG_ALIGN(sizeof(struct cmsghdr)), dlen);
        /* The sender's credentials as the guest knows them: the pid as the
         * guest may see it (proctab_pid_view, held: the message keeps the
         * sender's pid alive), 0 for a host process -- and, under -fake-id,
         * the fake uid/gid (cred_g2h above). Field by field, since a truncated
         * element carries only the head of the struct. */
        if (level == SOL_SOCKET && type == SCM_CREDENTIALS) {
            u8 *cr = gb + goff + GCMSG_HDRLEN;
            if (dlen >= 4) {
                s32 pid;
                memcpy(&pid, cr, 4);
                pid = proctab_pid_view(pid, 1);
                memcpy(cr, &pid, 4);
            }
            if (m->fake_id && dlen >= 8) {
                u32 uid;
                memcpy(&uid, cr + 4, 4);
                uid = remap_uid(m, uid);
                memcpy(cr + 4, &uid, 4);
            }
            if (m->fake_id && dlen >= 12) {
                u32 gid;
                memcpy(&gid, cr + 8, 4);
                gid = remap_gid(m, gid);
                memcpy(cr + 8, &gid, 4);
            }
        }
        goff += gstep;
        hoff += hstep;
    }
    if (hoff < hlen) {
        *ctrunc = 1;   /* elements left over that never fit */
        cmsg_close_rights(hb, hoff, hlen);
    }
    return goff;
}

/* One sendmsg/recvmsg element on its way to the host: the guest's segments as
 * the transfer moves them, the transfer itself (sys.h, GuestXfer), the staged
 * control buffer and the destination's pinned parent directory. msg_import
 * fills it and msg_release takes down whatever it set up, on every path; a
 * receive hands its bytes back through xfer_end first (recvmsg_writeback). */
typedef struct MsgImport {
    GIovec gi[1024];
    int nseg;
    struct iovec iov[XFER_IOV];
    GuestXfer x;
    int xfer;                     /* x is live */
    u8 *ctrl;                     /* host-layout control buffer */
    size_t ctrl_cap;
    int dfd;                      /* unix_path_in's directory, or -1 */
} MsgImport;

static void msg_release(CPU *c, MsgImport *mi) {
    if (mi->xfer) xfer_end(c, &mi->x, 0);
    mi->xfer = 0;
    free(mi->ctrl);
    mi->ctrl = NULL;
    fdheld_close(mi->dfd);   /* the pin's parent (unix_path_in) */
    mi->dfd = -1;
}

/* The probe msg_import makes before staging a large send's control buffer:
 * sendmsg with the length and a buffer that is not there. ____sys_sendmsg
 * sizes the control buffer against the socket's optmem budget before it
 * copies a byte of it -- ENOBUFS, and the message is not looked at further --
 * and the copy then faults on the missing buffer, so nothing is ever sent.
 * EFAULT therefore means the kernel would take this much control data;
 * anything else is its answer to the call as it stands.
 *
 * All but EINVAL, which only a compat host gives: a 32-bit emulator on a
 * 64-bit kernel is served by cmsghdr_from_user_compat_to_kern, which walks the
 * elements before it sizes anything, and an absent buffer walks as none at
 * all. The guest's kernel is a 64-bit one, so its budget is what counts, and
 * there it has to be read (net.core.optmem_max -- the per-socket figure the
 * kernel checks against, less what the socket already holds, which a probe
 * would have seen and a read cannot); where even that cannot be read, a
 * budget of XFER_STAGE_MAX, some sixteen times the largest default any
 * kernel has shipped, stands in for it rather than none. */
static long optmem_max(void) {
    char buf[32];
    long v = -1;
    fdwin_enter();   /* a descriptor of our own, briefly (machine.h) */
    int fd = open("/proc/sys/net/core/optmem_max", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof buf - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            char *e;
            long p = strtol(buf, &e, 10);
            if (e != buf && p > 0) v = p;
        }
    }
    fdwin_leave();
    return v;
}
static int ctrl_probe(int fd, size_t cl) {
    struct msghdr p;
    memset(&p, 0, sizeof p);
    p.msg_controllen = cl;
    if (sendmsg(fd, &p, MSG_DONTWAIT) >= 0 || errno == EFAULT) return 0;
    if (errno != EINVAL) return -errno;
    long om = optmem_max();
    if (om < 0) om = XFER_STAGE_MAX;
    return cl > (size_t)om ? -ENOBUFS : 0;
}

/* Import a guest msghdr into a host one, into `mi`. The guest's iovec array is
 * read exactly once, and mi->gi keeps that snapshot: a receive writes its data
 * back to those bases after the host call, and re-reading the guest array to
 * find them again would be reading a different array -- a sibling thread
 * sharing the address space can rewrite it (or unmap it) while the call is
 * parked. import_iovec in the kernel snapshots it once and never looks again.
 *
 * Checked in the order ____sys_sendmsg and the protocols meet them: the
 * header and its iovec array, then the control buffer (its size, then its
 * contents), then the destination address, and only then the data -- which a
 * kernel copies last of all, inside the protocol. `sflags` is the send's flags
 * argument (MSG_ZEROCOPY), `fd` the socket. 0 or -errno; msg_release in
 * either case. */
static int msg_import(CPU *c, int fd, u64 va, GMsghdr *g, struct msghdr *h,
                      struct sockaddr_storage *ss, int for_send, int sflags,
                      MsgImport *mi) {
    mi->nseg = 0;
    mi->xfer = 0;
    mi->ctrl = NULL;
    mi->ctrl_cap = 0;
    mi->dfd = -1;
    if (copy_from_guest(c, g, va, sizeof *g) < 0) return -EFAULT;
    memset(h, 0, sizeof *h);
    /* msg_namelen is an int, and __copy_msghdr settles it before the iovec:
     * a NULL msg_name zeroes the length first, so a rubbish value is harmless
     * there; a negative one is then EINVAL, ahead of the EMSGSIZE below and
     * ahead of anything being sent or received; and only after that is an
     * over-long one clamped to sizeof(sockaddr_storage) -- clamped, not
     * refused, which is where this differs from an addrlen passed as its own
     * argument (addr_in). The clamp was already here; the refusal was not, so
     * a guest naming a negative length had 128 bytes read out of msg_name and
     * sent, or a source address written back into a buffer it never offered. */
    if (g->msg_name && (s32)g->msg_namelen < 0) return -EINVAL;
    if (g->msg_name && g->msg_namelen) {
        if (for_send) {
            u32 nl = g->msg_namelen > sizeof *ss ? sizeof *ss : g->msg_namelen;
            memset(ss, 0, sizeof *ss);   /* as addr_in: defined past the length */
            if (copy_from_guest(c, ss, g->msg_name, nl) < 0) return -EFAULT;
            h->msg_name = ss;
            h->msg_namelen = nl;
        } else {
            /* Receiving: give the kernel the whole staging buffer rather than the
             * guest's, so the source address arrives untruncated -- unix_path_out
             * needs the complete sun_path to translate it to the guest view. The
             * writeback clamps to what the guest actually asked for. */
            h->msg_name = ss;
            h->msg_namelen = sizeof *ss;
        }
    }
    /* msg_iovlen is a guest u64 and the kernel checks it as one --
     * copy_msghdr_from_user compares the whole value against UIO_MAXIOV and
     * answers EMSGSIZE, not EINVAL, above it. Casting first threw the high
     * half away, so 2^32 became an empty gather the call went on to perform
     * and 2^32+1 became a one-segment send, where a kernel refuses both.
     * (readv/writev are the opposite case and deliberately do narrow: their
     * vlen reaches the kernel's own `unsigned nr_segs`, so 2^32 really is
     * zero segments there. See iov_import in sys_file.c.) */
    if (g->msg_iovlen > 1024) return -EMSGSIZE;
    unsigned cnt = (unsigned)g->msg_iovlen;
    GIovec *gi = mi->gi;
    if (cnt && copy_from_guest(c, gi, g->msg_iov, sizeof(GIovec) * cnt) < 0) return -EFAULT;
    /* Bound every segment on its own, not just the sum: iov_len is a guest u64,
     * so lengths chosen to wrap the host-width total would pass a sum-only check
     * while each stays huge. The bounds themselves are __import_iovec's own -- a
     * segment whose length is negative as an ssize_t is EINVAL, and the running
     * total is CLAMPED to MAX_RW_COUNT rather than refused, so a vector past
     * that is a short transfer and not an error. The flat 16 MiB ceiling that
     * used to stand here refused both, which made a sendmsg of a large buffer
     * EINVAL where a writev of the same buffer on the same fd went straight
     * through (iov_import, sys_file.c, which follows the same rule). */
    u64 total = 0;
    for (unsigned i = 0; i < cnt; i++) {
        if ((s64)gi[i].iov_len < 0) return -EINVAL;
        if (gi[i].iov_len > A64_MAX_RW_COUNT - total)
            gi[i].iov_len = A64_MAX_RW_COUNT - total;
        total += gi[i].iov_len;
    }
    /* Ancillary data is staged, and its size is the guest's to choose: the
     * kernel bounds msg_controllen only by INT_MAX (____sys_sendmsg /
     * ____sys_recvmsg refuse anything past it) and, on a send, by the socket's
     * own optmem budget, which answers ENOBUFS. The fixed 4 KB staging that
     * used to stand here silently dropped every element past it on a send --
     * the walk stops at the first one the buffer cannot hold and the message
     * went out with the rest of its control data missing, reported as a
     * success -- and cut a receive short with an MSG_CTRUNC the kernel would
     * not have raised. */
    /* A send refuses more than INT_MAX of it with ENOBUFS -- which is what
     * ____sys_sendmsg answers, before it has looked at msg_control at all, so
     * a null pointer is no escape from it. A receive has no such ceiling: the
     * length is only the capacity the kernel may fill, so clamp rather than
     * refuse, which is the same answer for any buffer a guest can actually
     * back and keeps the size_t cast below from truncating on an ILP32 host. */
    if (for_send && g->msg_controllen > INT_MAX) return -ENOBUFS;
    /* And a send then copies the whole of the buffer in, so a non-zero length
     * the guest cannot back is EFAULT -- msg_control == NULL included, which
     * used to be taken for "no ancillary data" and sent the message. A receive
     * only ever writes through the pointer, so there a null one is not an
     * error at all: the kernel has nowhere to put ancillary data and says so
     * with MSG_CTRUNC, which is what the host raises for us. */
    if (g->msg_controllen && (for_send || g->msg_control)) {
        size_t cl = g->msg_controllen > INT_MAX ? (size_t)INT_MAX
                                                : (size_t)g->msg_controllen;
        if (for_send) {
            /* The optmem budget comes first: the kernel sizes the control
             * buffer against it (sock_kmalloc) before it copies a byte, so a
             * length past it is ENOBUFS whatever the pointer holds -- and it
             * is also what bounds the staging below, which a guest could
             * otherwise size to INT_MAX, twice over, out of pages that cost
             * it nothing. Asked of the host kernel for anything the small
             * path would not stage anyway (ctrl_probe); the guest's own
             * length is what is judged, as its kernel would judge it. */
            if (cl > XFER_BOUNCE_MAX) {
                int pr = ctrl_probe(fd, cl);
                if (pr < 0) return pr;
            }
            /* The guest must back all of it, which is what bounds the
             * allocation (as for the iovecs below); the host kernel then
             * applies its own optmem ceiling to the converted buffer. Stage
             * the guest's bytes, then rebuild them in the host's cmsghdr
             * layout -- the two differ on an ILP32 host, where the host's
             * element is the smaller of the two, so no element ever grows.
             *
             * The staging is still one alignment step larger than the guest's
             * own length: the last element's cmsg_len need not be a multiple
             * of the alignment, and the kernel accepts one whose padded size
             * runs off the end of the buffer (CMSG_NXTHDR simply finds no next
             * header), while the conversion writes that element padded. Sizing
             * the staging at the guest's length exactly made such a message
             * EINVAL here where the host sends it. */
            if (rw_room(c, g->msg_control, cl, ACC_READ) < cl) return -EFAULT;
            /* One guest alignment step of slack: that is the most the padded
             * last element can run past the guest's own length, and the host's
             * own step is never the larger of the two. */
            size_t hcap = cl + (size_t)GCMSG_ALIGN(1);
            u8 *gctrl = malloc(cl);
            u8 *hctrl = calloc(1, hcap);
            if (!gctrl || !hctrl) { free(gctrl); free(hctrl); return -ENOMEM; }
            if (copy_from_guest(c, gctrl, g->msg_control, cl) < 0) {
                free(gctrl); free(hctrl); return -EFAULT;
            }
            ssize_t hl = cmsg_g2h(c->m, gctrl, cl, hctrl, hcap);
            free(gctrl);
            if (hl < 0) { free(hctrl); return -EINVAL; }
            mi->ctrl = hctrl;
            mi->ctrl_cap = hcap;
            h->msg_control = hctrl;
            h->msg_controllen = (size_t)hl;
        } else {
            /* Receiving: the host writes its own layout here and the writeback
             * converts. Bounded by what the guest's buffer can actually take,
             * since anything past that is reported as a short controllen plus
             * MSG_CTRUNC either way -- by the kernel when the buffer is short,
             * and by cmsg_h2g when an ILP32 host's more compact elements expand
             * into the guest's layout, exactly as the kernel reports a control
             * buffer it outgrew -- and by the staging cap, which is orders of
             * magnitude past all a kernel ever delivers with one message
             * (SCM_MAX_FD descriptors, a credential, a security label, the
             * timestamps and the IPv6 option headers together come to a few
             * KiB). */
            size_t room = rw_room(c, g->msg_control, cl, ACC_WRITE);
            if (cl > room) cl = room;
            if (cl > XFER_STAGE_MAX) cl = XFER_STAGE_MAX;
            if (cl) {
                u8 *hctrl = calloc(1, cl);
                if (!hctrl) return -ENOMEM;
                mi->ctrl = hctrl;
                mi->ctrl_cap = cl;
                h->msg_control = hctrl;
                h->msg_controllen = cl;
            }
        }
    }
    /* Translate an AF_UNIX destination path: after the control buffer, which
     * the protocol parses before it looks for its peer, and before the data,
     * which it copies last. unix_path_in may open a dirfd (for a path that
     * overflows sun_path), which msg_release closes; it leaves -1 on error. */
    if (for_send && h->msg_name) {
        socklen_t sl = h->msg_namelen;
        int tr = unix_path_in(c, ss, &sl, 1, &mi->dfd);
        if (tr < 0) return tr;
        h->msg_namelen = sl;
    }
    /* The data, as far as the guest's memory goes: the vector is cut where it
     * stops, and the rest of what was named is handed to the host as a fault
     * in the same place (sys.h), so the host kernel's copy stops exactly where
     * the guest's own kernel would, and answers as it would -- on a receive,
     * the bytes of a stream up to there, EFAULT for a datagram that did not
     * fit, and the datagram gone either way; on a send, EFAULT with nothing
     * sent of a datagram, the packets of a stream it copied whole. That is
     * also what bounds the transfer by the guest's own memory rather than by a
     * length it merely named. A receive used to take the whole of what was
     * named into a bounce buffer that size, before anything had even arrived,
     * and a send used to demand all of its data up front: EFAULT for every
     * stream it would have sent part of. */
    size_t backed = 0;
    unsigned nseg = cnt;
    XferCut cut = { 0, 0 };
    for (unsigned i = 0; i < cnt; i++) {
        size_t want = (size_t)gi[i].iov_len;
        size_t room = want ? rw_room(c, gi[i].iov_base, want,
                                     for_send ? ACC_READ : ACC_WRITE) : 0;
        gi[i].iov_len = room;
        backed += room;
        if (room < want) {
            cut.seg = want - room;
            cut.after = (size_t)total - backed - cut.seg;
            nseg = i + 1;
            break;
        }
    }
    mi->nseg = (int)nseg;
    int zc = for_send && (sflags & MSG_ZEROCOPY);
    int r = xfer_begin(c, fd, gi, (int)nseg, !for_send, zc ? XFER_LEND : 0,
                       &cut, mi->iov, &mi->x);
    if (r < 0) return r;
    mi->xfer = 1;
    if (for_send && (r = xfer_send_whole(fd, &mi->x, backed)) < 0) return r;
    /* A zero-copy send leaves its pages referenced by the socket after the
     * call returns, until the peer has them: lent guest pages are exactly
     * that (the guest must not touch them until notified, as on a kernel),
     * but a staged part would be a buffer of ours, freed and reused while
     * the kernel still transmits from it. Refuse it with the ENOBUFS a
     * zero-copy send may always get (the notification budget), which a
     * caller answers by sending with a copy. Only a vector past a thousand
     * separate mappings gets here. (A guarded staging is a file that is no
     * socket, as in sendto.) */
    if (zc && mi->x.stage && !mi->x.guarded) return -ENOBUFS;
    h->msg_iov = mi->x.iov;
    h->msg_iovlen = (size_t)mi->x.n;
    h->msg_flags = g->msg_flags;
    return 0;
}

SYSDEF(sendmsg) {
    if (nl_is_fd(c->m, (int)a0)) return nl_sendmsg(c, (int)a0, a1);
    GMsghdr g;
    struct msghdr h;
    struct sockaddr_storage ss;
    MsgImport mi;
    int r = msg_import(c, (int)a0, a1, &g, &h, &ss, 1, (int)a2, &mi);
    if (r < 0) { msg_release(c, &mi); return (u64)(s64)r; }
    /* As in sendto: note a reconfiguring rtnetlink request from a guest with a
     * faked network namespace. The message is the whole of the vector, in
     * order -- reading only the first segment's worth missed a request whose
     * netlink header straddled two of them, and the refusal it drew was then
     * passed through where the guest was owed the ack. */
    nlr_note_gvec(c, (int)a0, mi.gi, mi.nseg);
    ssize_t n = sendmsg((int)a0, &h, (int)a2);
    u64 e = n < 0 ? host_err() : (u64)n;   /* before the release below */
    msg_release(c, &mi);
    return e;
}

/* Scatter a received message back into the guest: iov data, source address,
 * control, and the updated header at `hdr_va`. `n` is the recvmsg result.
 *
 * Returns 0, or -EFAULT if any of that could not be written. The message is
 * already off the socket by then and cannot be put back -- which is exactly
 * what a kernel does with a datagram whose destination buffer faults: the data
 * is gone and the call reports EFAULT. Reporting success instead would tell
 * the guest bytes were delivered to memory that never received them. */
static int recvmsg_writeback(CPU *c, int fd, u64 hdr_va, GMsghdr *g,
                             struct msghdr *h, MsgImport *mi,
                             struct sockaddr_storage *ss, ssize_t n, int peek) {
    /* The data: whatever of it was staged rather than received straight into
     * the guest's pages goes back now (sys.h, xfer_end). */
    mi->xfer = 0;
    if (xfer_end(c, &mi->x, n > 0 ? (size_t)n : 0) < 0) return -EFAULT;
    /* Turn the refusal of a request against a faked network namespace into
     * the kernel's own ack, before the guest sees the reply. MSG_TRUNC reports
     * the untruncated length, so clamp to what the buffer actually holds. */
    if (n > 0) {
        size_t held = 0;
        for (int i = 0; i < mi->nseg; i++) held += (size_t)mi->gi[i].iov_len;
        nlr_fix_gvec(c, fd, mi->gi, mi->nseg, (size_t)n < held ? (size_t)n : held, peek);
    }
    if (g->msg_name && h->msg_namelen) {
        socklen_t sl = h->msg_namelen;
        unix_path_out(c, ss, &sl);   /* host sun_path -> guest view */
        h->msg_namelen = sl;
        /* Write at most the buffer the guest supplied, but report the true
         * length below -- POSIX: "fromlen shall refer to the value before
         * truncation", which is what the kernel's move_addr_to_user does. */
        u32 out = (u32)sl < g->msg_namelen ? (u32)sl : g->msg_namelen;
        if (out && copy_to_guest(c, g->msg_name, ss, out) < 0) return -EFAULT;
    }
    if (g->msg_control && h->msg_controllen) {
        /* Converted into what msg_import let the kernel write, which is also
         * what the guest's own buffer holds -- the two are the same number. */
        u8 *gctrl = calloc(1, mi->ctrl_cap ? mi->ctrl_cap : 1);
        if (!gctrl) return -ENOMEM;
        int ctrunc = 0;
        size_t gl = cmsg_h2g(c->m, mi->ctrl, h->msg_controllen, gctrl, mi->ctrl_cap,
                             &ctrunc, fd_nofile_cap(c->m));
        int bad = gl && copy_to_guest(c, g->msg_control, gctrl, gl) < 0;
        free(gctrl);
        if (bad) return -EFAULT;
        if (ctrunc) h->msg_flags |= MSG_CTRUNC;
        g->msg_controllen = gl;
    } else {
        g->msg_controllen = h->msg_controllen;
    }
    g->msg_namelen = h->msg_namelen;
    g->msg_flags = h->msg_flags;
    return copy_to_guest(c, hdr_va, g, sizeof *g) < 0 ? -EFAULT : 0;
}

SYSDEF(recvmsg) {
    u64 nlret;   /* as in recvfrom: no pending reply -> the real recvmsg runs */
    if (nl_is_fd(c->m, (int)a0) && nl_maybe_recvmsg(c, (int)a0, a1, (int)a2, &nlret))
        return nlret;
    GMsghdr g;
    struct msghdr h;
    struct sockaddr_storage ss;
    MsgImport mi;
    int r = msg_import(c, (int)a0, a1, &g, &h, &ss, 0, 0, &mi);
    if (r < 0) { msg_release(c, &mi); return (u64)(s64)r; }
    ssize_t n = recvmsg((int)a0, &h, (int)a2);
    if (n < 0) {
        u64 e = host_err();
        msg_release(c, &mi);
        return e;
    }
    int wb = recvmsg_writeback(c, (int)a0, a1, &g, &h, &mi, &ss, n, (int)a2 & MSG_PEEK);
    msg_release(c, &mi);
    return wb < 0 ? (u64)(s64)wb : (u64)n;
}

/* struct mmsghdr = { struct msghdr msg_hdr; unsigned msg_len; } — on arm64 LP64
 * the msghdr is 56 bytes, msg_len at offset 56, whole struct padded to 64. */
#define GMMSG_STRIDE 64
#define GMMSG_LEN_OFF 56

SYSDEF(sendmmsg) {
    unsigned vlen = (unsigned)a2;
    if (vlen > 1024) vlen = 1024;
    int sent = 0;
    MsgImport mis, *mi = &mis;    /* one element at a time, reused */
    for (unsigned i = 0; i < vlen; i++) {
        u64 entry = a1 + (u64)i * GMMSG_STRIDE;
        /* Each element is a sendmsg, so a substituted netlink socket has to be
         * answered here too. Going straight to the host would write the guest's
         * netlink request into the AF_UNIX stand-in as opaque bytes and leave
         * the emulator with no record that a request was ever made. */
        if (nl_is_fd(c->m, (int)a0)) {
            u64 r = nl_sendmsg(c, (int)a0, entry);
            if ((s64)r < 0) return sent ? (u64)sent : r;
            u32 nlen = (u32)r;
            if (copy_to_guest(c, entry + GMMSG_LEN_OFF, &nlen, 4) < 0)
                return sent ? (u64)sent : (u64)(s64)-EFAULT;
            sent++;
            continue;
        }
        GMsghdr g; struct msghdr h; struct sockaddr_storage ss;
        int r = msg_import(c, (int)a0, entry, &g, &h, &ss, 1, (int)a3, mi);
        if (r < 0) {
            msg_release(c, mi);
            return sent ? (u64)sent : (u64)(s64)r;
        }
        /* As sendmsg: note a reconfiguring rtnetlink request from a guest whose
         * network namespace was faked, so its refusal can be rewritten. */
        nlr_note_gvec(c, (int)a0, mi->gi, mi->nseg);
        ssize_t n = sendmsg((int)a0, &h, (int)a3);
        u64 e = n < 0 ? host_err() : 0;    /* before the release below */
        msg_release(c, mi);
        if (n < 0) return sent ? (u64)sent : e;
        u32 mlen = (u32)n;
        if (copy_to_guest(c, entry + GMMSG_LEN_OFF, &mlen, 4) < 0)
            return sent ? (u64)sent : (u64)(s64)-EFAULT;
        sent++;
    }
    return (u64)sent;
}

/* Wait for `fd` to become readable, but never past `deadline` (monotonic ns).
 * 1 readable, 0 the deadline arrived first, -1 error/interrupted (errno set).
 * A deadline further off than poll's int of milliseconds can say is waited
 * for in pieces: the cast alone kept the low 32 bits of the count, which for
 * a span of a few thousand years is some small number of milliseconds, and
 * the wait ended there. */
static int wait_readable(int fd, u64 deadline) {
    for (;;) {
        u64 now = mono_ns();
        if (now >= deadline) return 0;
        u64 ms = (deadline - now + 999999ULL) / 1000000ULL;   /* round up: never early */
        struct pollfd p = { fd, POLLIN, 0 };
        int r = poll(&p, 1, ms > INT_MAX ? INT_MAX : (int)ms);
        if (r != 0) return r > 0 ? 1 : r;
    }
}

/* recvmmsg(fd, msgvec, vlen, flags, timeout).
 *
 * The timeout is a relative CLOCK_MONOTONIC span the kernel turns into a
 * deadline, checks after every datagram it managed to receive, and -- on a
 * call that received at least one -- writes the remainder of back, which is
 * the only way the caller learns how much of it was left. An invalid one is
 * EINVAL and an unreadable one EFAULT, both before anything is received. All
 * of that was simply discarded here, so a guest's timeout meant nothing at
 * all.
 *
 * One deliberate difference: the kernel checks the deadline only AFTER a
 * datagram arrives, so a recvmmsg that blocks waiting for one blocks past the
 * timeout forever -- its own manual page lists this under BUGS. Here the
 * deadline bounds every wait, which is what a caller that passed one asked
 * for; there is nothing to be gained from reproducing a hang. Everything else
 * follows the kernel, including that MSG_DONTWAIT is taken up after the first
 * datagram only when the caller asked for MSG_WAITFORONE -- without it (and
 * without a timeout) the call really does wait for all vlen of them. */
SYSDEF(recvmmsg) {
    unsigned vlen = (unsigned)a2;
    int flags = (int)a3;
    if (vlen > 1024) vlen = 1024;
    int have_tmo = 0;
    u64 deadline = 0;           /* for the waits: monotonic ns, saturating */
    s64 end_sec = 0, end_nsec = 0;   /* for the remainder: the kernel's form */
    if (a4) {
        GTimespec gt;
        if (copy_from_guest(c, &gt, a4, sizeof gt) < 0) return (u64)(s64)-EFAULT;
        if (gt.tv_sec < 0 || (u64)gt.tv_nsec >= 1000000000ULL)
            return (u64)(s64)-EINVAL;
        struct timespec rel = { (time_t)gt.tv_sec, (long)gt.tv_nsec };
        syscall_wait_begin(&rel);   /* a restart keeps the deadline (syscall.c) */
        /* The deadline as the kernel keeps it (poll_select_set_timeout ->
         * timespec64_add_safe): now plus the span, normalized, and the end of
         * time -- TIME64_MAX seconds -- where the sum does not fit. A span too
         * large to hold means "never", and the remainder written back is the
         * end of time minus now. The waits use the same deadline in
         * nanoseconds, saturating the same way (sys.h): multiplied out, the
         * span wrapped -- 2^60 seconds is exactly 0 mod 2^64 -- and the call
         * came back empty, its deadline "already passed". */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        u64 ns = (u64)now.tv_nsec + (u64)rel.tv_nsec;
        u64 sec = (u64)now.tv_sec + (u64)rel.tv_sec + (ns >= 1000000000ULL);
        ns %= 1000000000ULL;
        if (sec < (u64)now.tv_sec || sec < (u64)rel.tv_sec || sec > (u64)INT64_MAX) {
            end_sec = INT64_MAX;
            end_nsec = 0;
        } else {
            end_sec = (s64)sec;
            end_nsec = (s64)ns;
        }
        deadline = span_ns_sat((u64)end_sec, (u64)end_nsec);
        have_tmo = 1;
    }
    int got = 0;
    MsgImport mis, *mi = &mis;    /* one element at a time, reused */
    for (unsigned i = 0; i < vlen; i++) {
        u64 entry = a1 + (u64)i * GMMSG_STRIDE;
        int mf = flags & ~MSG_WAITFORONE;
        /* MSG_WAITFORONE turns on MSG_DONTWAIT after one packet -- and only it. */
        if (got > 0 && (flags & MSG_WAITFORONE)) mf |= MSG_DONTWAIT;
        if (have_tmo && !(mf & MSG_DONTWAIT)) {
            int w = wait_readable((int)a0, deadline);
            if (w == 0) break;                       /* the timeout ran out */
            if (w < 0) { if (got) break; return host_err(); }
            mf |= MSG_DONTWAIT;   /* readable now; do not sleep past the deadline */
        }
        /* A substituted netlink socket answers from the reply it recorded, one
         * datagram per element, exactly as recvmsg does. */
        u64 nlret;
        if (nl_is_fd(c->m, (int)a0) &&
            nl_maybe_recvmsg(c, (int)a0, entry, mf, &nlret)) {
            if ((s64)nlret < 0) {
                if (got) break;
                return nlret;
            }
            u32 nlen = (u32)nlret;
            if (copy_to_guest(c, entry + GMMSG_LEN_OFF, &nlen, 4) < 0) {
                if (got) break;
                return (u64)(s64)-EFAULT;
            }
            got++;
            continue;
        }
        GMsghdr g; struct msghdr h; struct sockaddr_storage ss;
        int r = msg_import(c, (int)a0, entry, &g, &h, &ss, 0, 0, mi);
        if (r < 0) {
            msg_release(c, mi);
            return got ? (u64)got : (u64)(s64)r;
        }
        ssize_t n = recvmsg((int)a0, &h, mf);
        if (n < 0) {
            u64 e = host_err();
            msg_release(c, mi);
            if (got) break;   /* return the messages received so far */
            return e;
        }
        /* The data, the faked-namespace rewrite and the rest, as recvmsg. */
        int wb = recvmsg_writeback(c, (int)a0, entry, &g, &h, mi, &ss, n, mf & MSG_PEEK);
        u32 mlen = (u32)n;
        if (wb == 0 && copy_to_guest(c, entry + GMMSG_LEN_OFF, &mlen, 4) < 0)
            wb = -EFAULT;
        msg_release(c, mi);
        /* A message that could not be handed over is still a message that was
         * received: report the ones before it, as the kernel does, and let the
         * next call answer with the error. */
        if (wb < 0) {
            if (got) break;
            return (u64)(s64)wb;
        }
        got++;
        if (have_tmo && mono_ns() >= deadline) break;
    }
    /* The remainder goes back only on a call that received something, as the
     * kernel does (it returns early for 0 and for an error). */
    if (have_tmo && got > 0) {
        /* timespec64_sub(end_time, now), clamped at zero as the kernel clamps
         * it -- in the kernel's own form, so a saturated deadline reads back
         * as the end of time minus now rather than as some other number. */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        s64 ls = end_sec - (s64)now.tv_sec, ln = end_nsec - (s64)now.tv_nsec;
        if (ln < 0) { ls--; ln += 1000000000LL; }
        if (ls < 0) { ls = 0; ln = 0; }
        GTimespec out = { ls, ln };
        if (copy_to_guest(c, a4, &out, sizeof out) < 0) return (u64)(s64)-EFAULT;
    }
    return (u64)got;
}
