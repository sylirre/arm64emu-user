/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Socket syscalls. sockaddr layouts (sockaddr_in/in6/un) are identical across
 * arm64/arm/x86; msghdr and cmsghdr differ only in pointer/size_t width and are
 * converted explicitly, so the code is correct on ILP32 hosts too. AF_UNIX
 * pathname sockets carry a filesystem path in sun_path, so bind/connect/sendto/
 * sendmsg rewrite it through the rootfs resolver (unix_path_in) and the address
 * the kernel reports back is stripped to its guest view (unix_path_out). A
 * translated path that overflows the 108-byte sun_path is reached relative to a
 * parent-directory fd via /proc/self/fd (unix_path_in fallback). Abstract
 * sockets, which have no filesystem node, are instead isolated per rootfs by a
 * name tag (abs_tag_in/out) unless --share-abstract-sockets is given. */
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/netlink.h>   /* AF_NETLINK, NETLINK_ROUTE, NETLINK_AUDIT */

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
        nl_mark_fd(c->m, fd);
        return (u64)fd;
    }
    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        /* fake_id0-style shim: a would-be-root guest that the host denies a
         * NETLINK_AUDIT socket gets EPROTONOSUPPORT ("audit not built in")
         * rather than a hard permission error. */
        if (c->m->fake_id && c->m->cred.euid == 0 &&
            domain == AF_NETLINK && protocol == NETLINK_AUDIT &&
            (errno == EPERM || errno == EACCES))
            return (u64)(s64)-EPROTONOSUPPORT;
        return host_err();
    }
    /* A real NETLINK_ROUTE socket still needs the ack emulation when the guest
     * believes it configures a network namespace of its own (sys_netlink.c). */
    if (domain == AF_NETLINK && protocol == NETLINK_ROUTE)
        nlr_mark_fd(c->m, fd);
    return (u64)fd;
}

SYSDEF(socketpair) {
    int sv[2];
    if (socketpair((int)a0, (int)a1, (int)a2, sv) < 0) return host_err();
    s32 g[2] = { sv[0], sv[1] };
    return copy_to_guest(c, a3, g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* Import a guest sockaddr (raw bytes; layout is arch-independent). */
static int addr_in(CPU *c, u64 va, u32 len, struct sockaddr_storage *ss, socklen_t *out) {
    if (len > sizeof *ss) len = sizeof *ss;
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
 * or differently tagged) don't. No-op with --share-abstract-sockets, or when
 * the tag would push the name past the 108-byte sun_path (left untagged). */
static void abs_tag_in(CPU *c, struct sockaddr_un *un, socklen_t *sl, size_t poff) {
    size_t T = c->m->abs_tag_len, total = (size_t)*sl - poff;
    if (c->m->share_abstract || T == 0 || total + T > sizeof un->sun_path) return;
    memmove(un->sun_path + 1 + T, un->sun_path + 1, total - 1);
    memcpy(un->sun_path + 1, c->m->abs_tag, T);
    *sl = (socklen_t)(*sl + T);
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
    if (ss->ss_family != AF_UNIX) return 0;
    struct sockaddr_un *un = (struct sockaddr_un *)ss;
    const size_t poff = offsetof(struct sockaddr_un, sun_path);
    if (*sl <= poff) return 0;                 /* unnamed / autobind */
    if (un->sun_path[0] == '\0') {             /* abstract namespace */
        abs_tag_in(c, un, sl, poff);
        return 0;
    }
    size_t maxp = (size_t)*sl - poff;
    if (maxp > sizeof un->sun_path) maxp = sizeof un->sun_path;
    char gpath[PATH_MAX];
    size_t i = 0;
    for (; i < maxp && un->sun_path[i]; i++) {
        if (i + 1 >= sizeof gpath) return -ENAMETOOLONG;
        gpath[i] = un->sun_path[i];
    }
    gpath[i] = 0;
    char host[PATH_MAX];
    int r = path_resolve(c->m, G_AT_FDCWD, gpath,
                         follow ? 0 : PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return r;
    size_t hl = strlen(host);
    if (hl + 1 <= sizeof un->sun_path) {       /* fits directly */
        memcpy(un->sun_path, host, hl + 1);
        *sl = (socklen_t)(poff + hl + 1);
        return 0;
    }
    /* Overlong: bind/connect relative to the parent dir so only the basename
     * lands in sun_path. Needs a caller that will close the returned fd. */
    if (!dirfd_out) return -ENAMETOOLONG;
    char *slash = strrchr(host, '/');
    if (!slash || slash == host) return -ENAMETOOLONG;   /* need a real parent */
    *slash = 0;                                /* host := parent dir */
    const char *base = slash + 1;
    int dfd = open(host, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return -errno;
    char proc[sizeof un->sun_path];
    int n = snprintf(proc, sizeof proc, "/proc/self/fd/%d/%s", dfd, base);
    if (n < 0 || (size_t)n >= sizeof proc) { close(dfd); return -ENAMETOOLONG; }
    memcpy(un->sun_path, proc, (size_t)n + 1);
    *sl = (socklen_t)(poff + (size_t)n + 1);
    *dirfd_out = dfd;
    return 0;
}

/* Reverse of unix_path_in: rewrite a host sun_path the kernel reports back
 * (getsockname/getpeername/accept/recvfrom/recvmsg) to its guest view, so the
 * guest never sees a host path (pathname) or our rootfs tag (abstract). No-op
 * for non-AF_UNIX and unnamed addresses. Rewrites address and length in place. */
static void unix_path_out(CPU *c, struct sockaddr_storage *ss, socklen_t *sl) {
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
    if (nl_is_fd(c->m, (int)a0)) return 0;   /* fake netlink socket: silent success */
    struct sockaddr_storage ss;
    socklen_t sl;
    int dfd, r = addr_in(c, a1, (u32)a2, &ss, &sl);
    if (r < 0) return (u64)(s64)r;
    if ((r = unix_path_in(c, &ss, &sl, 0, &dfd)) < 0) return (u64)(s64)r;
    u64 ret = bind((int)a0, (struct sockaddr *)&ss, sl) < 0 ? host_err() : 0;
    if (dfd >= 0) close(dfd);
    return ret;
}

SYSDEF(connect) {
    struct sockaddr_storage ss;
    socklen_t sl;
    int dfd, r = addr_in(c, a1, (u32)a2, &ss, &sl);
    if (r < 0) return (u64)(s64)r;
    if ((r = unix_path_in(c, &ss, &sl, 1, &dfd)) < 0) return (u64)(s64)r;
    u64 ret = connect((int)a0, (struct sockaddr *)&ss, sl) < 0 ? host_err() : 0;
    if (dfd >= 0) close(dfd);
    return ret;
}

SYSDEF(listen) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return listen((int)a0, (int)a1) < 0 ? host_err() : 0;
}

/* Write back a sockaddr result (accept/getsockname/getpeername/recvfrom). */
static u64 addr_out(CPU *c, u64 addr_va, u64 len_va, struct sockaddr_storage *ss,
                    socklen_t sl) {
    if (!addr_va || !len_va) return 0;
    unix_path_out(c, ss, &sl);   /* host sun_path -> guest view */
    u32 glen;
    if (copy_from_guest(c, &glen, len_va, 4) < 0) return (u64)(s64)-EFAULT;
    u32 out = sl < glen ? sl : glen;
    if (out && copy_to_guest(c, addr_va, ss, out) < 0) return (u64)(s64)-EFAULT;
    u32 real = sl;
    if (copy_to_guest(c, len_va, &real, 4) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(accept) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd = accept((int)a0, (struct sockaddr *)&ss, &sl);
    if (fd < 0) return host_err();
    u64 e = addr_out(c, a1, a2, &ss, sl);
    if ((s64)e < 0) { close(fd); return e; }
    return (u64)fd;
}

SYSDEF(accept4) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd = accept4((int)a0, (struct sockaddr *)&ss, &sl, (int)a3);
    if (fd < 0) return host_err();
    u64 e = addr_out(c, a1, a2, &ss, sl);
    if ((s64)e < 0) { close(fd); return e; }
    return (u64)fd;
}

SYSDEF(getsockname) {
    if (nl_is_fd(c->m, (int)a0)) return nl_getsockname(c, a1, a2);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getsockname((int)a0, (struct sockaddr *)&ss, &sl) < 0) return host_err();
    return addr_out(c, a1, a2, &ss, sl);
}

SYSDEF(getpeername) {
    if (nl_is_fd(c->m, (int)a0)) return nl_getsockname(c, a1, a2);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getpeername((int)a0, (struct sockaddr *)&ss, &sl) < 0) return host_err();
    return addr_out(c, a1, a2, &ss, sl);
}

SYSDEF(sendto) {
    if (nl_is_fd(c->m, (int)a0)) return nl_sendto(c, (int)a0, a1, a2);
    size_t len = (size_t)a2;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    if (len && copy_from_guest(c, buf, a1, len) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    struct sockaddr *dp = NULL;
    int dfd = -1;
    if (a4 && a5) {
        if (addr_in(c, a4, (u32)a5, &ss, &sl) < 0) { free(buf); return (u64)(s64)-EFAULT; }
        int tr = unix_path_in(c, &ss, &sl, 1, &dfd);
        if (tr < 0) { free(buf); return (u64)(s64)tr; }
        dp = (struct sockaddr *)&ss;
    }
    /* A reconfiguring rtnetlink request from a guest with a faked network
     * namespace: note it, so the kernel's refusal becomes an ack on receive. */
    if (len) nlr_note_request(c->m, (int)a0, buf, len);
    ssize_t n = sendto((int)a0, buf, len, (int)a3, dp, sl);
    free(buf);
    if (dfd >= 0) close(dfd);
    return n < 0 ? host_err() : (u64)n;
}

SYSDEF(recvfrom) {
    if (nl_is_fd(c->m, (int)a0))
        return nl_recvfrom(c, (int)a0, a1, a2, (int)a3, a4, a5);
    size_t len = (size_t)a2;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    ssize_t n = recvfrom((int)a0, buf, len, (int)a3, (struct sockaddr *)&ss, &sl);
    if (n < 0) { free(buf); return host_err(); }
    /* Turn the refusal of a request against a faked network namespace into the
     * kernel's own ack, before the guest sees the reply. MSG_TRUNC reports the
     * untruncated length, so clamp to what the buffer actually holds. */
    if (n > 0)
        nlr_fix_reply(c->m, (int)a0, buf,
                      (size_t)n < len ? (size_t)n : len, (int)a3 & MSG_PEEK);
    if (n > 0 && copy_to_guest(c, a1, buf, (size_t)n) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    free(buf);
    u64 e = addr_out(c, a4, a5, &ss, sl);
    if ((s64)e < 0) return e;
    return (u64)n;
}

SYSDEF(shutdown) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return shutdown((int)a0, (int)a1) < 0 ? host_err() : 0;
}

SYSDEF(setsockopt) {
    size_t len = (size_t)a4;
    if (len > 4096) return (u64)(s64)-EINVAL;
    u8 buf[4096];
    if (len && copy_from_guest(c, buf, a3, len) < 0) return (u64)(s64)-EFAULT;
    return setsockopt((int)a0, (int)a1, (int)a2, buf, (socklen_t)len) < 0 ? host_err() : 0;
}

SYSDEF(getsockopt) {
    u32 glen = 0;
    if (a4 && copy_from_guest(c, &glen, a4, 4) < 0) return (u64)(s64)-EFAULT;
    if (glen > 4096) glen = 4096;
    u8 buf[4096];
    socklen_t sl = glen;
    if (getsockopt((int)a0, (int)a1, (int)a2, buf, &sl) < 0) return host_err();
    /* -fake-id: SO_PEERCRED reports the peer's *real* invoking uid/gid; present
     * the fake identity instead (same remap as stat ownership), so peer-uid
     * checks — tmux's server ACL, polkit, ... — agree with getuid(). struct
     * ucred is {pid,uid,gid}, three u32s; the layout is identical on arm64/x86.
     * The pid is left as the host pid (no guest-view consumer checks it). */
    if (c->m->fake_id && (int)a1 == SOL_SOCKET && (int)a2 == SO_PEERCRED && sl >= 12) {
        u32 uid, gid;
        memcpy(&uid, buf + 4, 4);
        memcpy(&gid, buf + 8, 4);
        uid = remap_uid(c->m, uid);
        gid = remap_gid(c->m, gid);
        memcpy(buf + 4, &uid, 4);
        memcpy(buf + 8, &gid, 4);
    }
    if (a3 && sl && copy_to_guest(c, a3, buf, sl) < 0) return (u64)(s64)-EFAULT;
    u32 real = sl;
    if (a4 && copy_to_guest(c, a4, &real, 4) < 0) return (u64)(s64)-EFAULT;
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

static int msg_import(CPU *c, u64 va, GMsghdr *g, struct msghdr *h,
                      struct iovec **iov_out, u8 **bounce_out,
                      struct sockaddr_storage *ss, u8 *ctrl, size_t ctrl_cap,
                      int for_send, int *dirfd_out) {
    if (copy_from_guest(c, g, va, sizeof *g) < 0) return -EFAULT;
    memset(h, 0, sizeof *h);
    if (g->msg_name && g->msg_namelen) {
        u32 nl = g->msg_namelen > sizeof *ss ? sizeof *ss : g->msg_namelen;
        if (copy_from_guest(c, ss, g->msg_name, nl) < 0) return -EFAULT;
        h->msg_name = ss;
        h->msg_namelen = nl;
    }
    unsigned cnt = (unsigned)g->msg_iovlen;
    if (cnt > 1024) return -EINVAL;
    GIovec gi[1024];
    if (cnt && copy_from_guest(c, gi, g->msg_iov, sizeof(GIovec) * cnt) < 0) return -EFAULT;
    size_t total = 0;
    for (unsigned i = 0; i < cnt; i++) total += gi[i].iov_len;
    if (total > (1u << 24)) return -EINVAL;
    u8 *bounce = malloc(total ? total : 1);
    struct iovec *iov = malloc(sizeof(struct iovec) * (cnt ? cnt : 1));
    if (!bounce || !iov) { free(bounce); free(iov); return -ENOMEM; }
    size_t off = 0;
    for (unsigned i = 0; i < cnt; i++) {
        iov[i].iov_base = bounce + off;
        iov[i].iov_len = gi[i].iov_len;
        if (for_send && gi[i].iov_len &&
            copy_from_guest(c, bounce + off, gi[i].iov_base, gi[i].iov_len) < 0) {
            free(bounce); free(iov); return -EFAULT;
        }
        off += gi[i].iov_len;
    }
    h->msg_iov = iov;
    h->msg_iovlen = cnt;
    if (g->msg_control && g->msg_controllen) {
        size_t cl = g->msg_controllen > ctrl_cap ? ctrl_cap : g->msg_controllen;
        if (for_send && copy_from_guest(c, ctrl, g->msg_control, cl) < 0) {
            free(bounce); free(iov); return -EFAULT;
        }
        h->msg_control = ctrl;
        h->msg_controllen = cl;
    }
    h->msg_flags = g->msg_flags;
    *iov_out = iov;
    *bounce_out = bounce;
    /* Translate an AF_UNIX destination path last: unix_path_in may open a dirfd
     * (for a path that overflows sun_path) which the caller closes after the
     * send, so doing it after every fallible step above means an error can never
     * leak that fd. dirfd_out is left -1 by unix_path_in on any error. */
    if (for_send && h->msg_name) {
        socklen_t sl = h->msg_namelen;
        int tr = unix_path_in(c, ss, &sl, 1, dirfd_out);
        if (tr < 0) { free(iov); free(bounce); return tr; }
        h->msg_namelen = sl;
    }
    return (int)cnt;
}

SYSDEF(sendmsg) {
    if (nl_is_fd(c->m, (int)a0)) return nl_sendmsg(c, (int)a0, a1);
    GMsghdr g;
    struct msghdr h;
    struct iovec *iov;
    u8 *bounce;
    struct sockaddr_storage ss;
    u8 ctrl[4096];
    int dfd = -1;
    int cnt = msg_import(c, a1, &g, &h, &iov, &bounce, &ss, ctrl, sizeof ctrl, 1, &dfd);
    if (cnt < 0) return (u64)(s64)cnt;   /* dfd == -1 on error: nothing to close */
    /* As in sendto: note a reconfiguring rtnetlink request from a guest with a
     * faked network namespace. The message starts at the first iovec, which
     * msg_import laid at the head of the bounce buffer. */
    if (cnt > 0) nlr_note_request(c->m, (int)a0, bounce, iov[0].iov_len);
    ssize_t n = sendmsg((int)a0, &h, (int)a2);
    free(iov); free(bounce);
    if (dfd >= 0) close(dfd);
    return n < 0 ? host_err() : (u64)n;
}

/* Scatter a received message back into the guest: iov data, source address,
 * control, and the updated header at `hdr_va`. `n` is the recvmsg result. */
static void recvmsg_writeback(CPU *c, u64 hdr_va, GMsghdr *g, struct msghdr *h,
                              struct iovec *iov, u8 *bounce,
                              struct sockaddr_storage *ss, u8 *ctrl, ssize_t n) {
    int cnt = (int)h->msg_iovlen;
    GIovec gi[1024];
    copy_from_guest(c, gi, g->msg_iov, sizeof(GIovec) * (unsigned)cnt);
    ssize_t left = n;
    size_t off = 0;
    for (int i = 0; i < cnt && left > 0; i++) {
        size_t chunk = (size_t)left < iov[i].iov_len ? (size_t)left : iov[i].iov_len;
        if (chunk) copy_to_guest(c, gi[i].iov_base, bounce + off, chunk);
        off += iov[i].iov_len;
        left -= (ssize_t)chunk;
    }
    if (g->msg_name && h->msg_namelen) {
        socklen_t sl = h->msg_namelen;
        unix_path_out(c, ss, &sl);   /* host sun_path -> guest view */
        h->msg_namelen = sl;
        copy_to_guest(c, g->msg_name, ss, h->msg_namelen);
    }
    if (g->msg_control && h->msg_controllen)
        copy_to_guest(c, g->msg_control, ctrl, h->msg_controllen);
    g->msg_namelen = h->msg_namelen;
    g->msg_controllen = h->msg_controllen;
    g->msg_flags = h->msg_flags;
    copy_to_guest(c, hdr_va, g, sizeof *g);
}

SYSDEF(recvmsg) {
    if (nl_is_fd(c->m, (int)a0)) return nl_recvmsg(c, (int)a0, a1, (int)a2);
    GMsghdr g;
    struct msghdr h;
    struct iovec *iov;
    u8 *bounce;
    struct sockaddr_storage ss;
    u8 ctrl[4096];
    int cnt = msg_import(c, a1, &g, &h, &iov, &bounce, &ss, ctrl, sizeof ctrl, 0, NULL);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n = recvmsg((int)a0, &h, (int)a2);
    if (n < 0) { free(iov); free(bounce); return host_err(); }
    /* Rewrite a faked-namespace refusal before the reply is scattered back to
     * the guest. The received bytes are contiguous at the head of the bounce
     * buffer (msg_import concatenates the iovecs in order), so the whole
     * datagram is walkable regardless of how the caller split it. */
    if (n > 0) {
        size_t total = 0;
        for (int i = 0; i < cnt; i++) total += iov[i].iov_len;
        nlr_fix_reply(c->m, (int)a0, bounce,
                      (size_t)n < total ? (size_t)n : total, (int)a2 & MSG_PEEK);
    }
    recvmsg_writeback(c, a1, &g, &h, iov, bounce, &ss, ctrl, n);
    free(iov); free(bounce);
    return (u64)n;
}

/* struct mmsghdr = { struct msghdr msg_hdr; unsigned msg_len; } — on arm64 LP64
 * the msghdr is 56 bytes, msg_len at offset 56, whole struct padded to 64. */
#define GMMSG_STRIDE 64
#define GMMSG_LEN_OFF 56

SYSDEF(sendmmsg) {
    unsigned vlen = (unsigned)a2;
    if (vlen > 1024) vlen = 1024;
    int sent = 0;
    for (unsigned i = 0; i < vlen; i++) {
        u64 entry = a1 + (u64)i * GMMSG_STRIDE;
        GMsghdr g; struct msghdr h; struct iovec *iov; u8 *bounce;
        struct sockaddr_storage ss; u8 ctrl[4096];
        int dfd = -1;
        int cnt = msg_import(c, entry, &g, &h, &iov, &bounce, &ss, ctrl, sizeof ctrl, 1, &dfd);
        if (cnt < 0) return sent ? (u64)sent : (u64)(s64)cnt;   /* dfd == -1 */
        ssize_t n = sendmsg((int)a0, &h, (int)a3);
        free(iov); free(bounce);
        if (dfd >= 0) close(dfd);
        if (n < 0) return sent ? (u64)sent : host_err();
        u32 mlen = (u32)n;
        if (copy_to_guest(c, entry + GMMSG_LEN_OFF, &mlen, 4) < 0)
            return sent ? (u64)sent : (u64)(s64)-EFAULT;
        sent++;
    }
    return (u64)sent;
}

SYSDEF(recvmmsg) {
    unsigned vlen = (unsigned)a2;
    int flags = (int)a3;
    (void)a4;   /* timeout: honored only as "block for the first message" */
    if (vlen > 1024) vlen = 1024;
    int got = 0;
    for (unsigned i = 0; i < vlen; i++) {
        u64 entry = a1 + (u64)i * GMMSG_STRIDE;
        GMsghdr g; struct msghdr h; struct iovec *iov; u8 *bounce;
        struct sockaddr_storage ss; u8 ctrl[4096];
        int cnt = msg_import(c, entry, &g, &h, &iov, &bounce, &ss, ctrl, sizeof ctrl, 0, NULL);
        if (cnt < 0) return got ? (u64)got : (u64)(s64)cnt;
        int mf = flags & ~MSG_WAITFORONE;
        if (got > 0) mf |= MSG_DONTWAIT;   /* only the first message blocks */
        ssize_t n = recvmsg((int)a0, &h, mf);
        if (n < 0) {
            free(iov); free(bounce);
            if (got) break;   /* return the messages received so far */
            return host_err();
        }
        recvmsg_writeback(c, entry, &g, &h, iov, bounce, &ss, ctrl, n);
        u32 mlen = (u32)n;
        copy_to_guest(c, entry + GMMSG_LEN_OFF, &mlen, 4);
        free(iov); free(bounce);
        got++;
    }
    return (u64)got;
}
