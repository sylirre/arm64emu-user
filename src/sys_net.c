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
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if ((size_t)*sl <= poff) return 0;         /* unnamed / autobind */
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
    if (dfd >= 0) close(dfd);
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
    u32 out = (u32)sl < glen ? (u32)sl : glen;
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
    /* Bounded, but never shortened: a datagram that does not fit is refused
     * (EMSGSIZE, by the host), not sent truncated -- so the whole buffer has
     * to be there, which is what the copy below would have found out after
     * allocating for it. */
    size_t len = rw_count(a2);
    if (len && rw_room(c, a1, len, ACC_READ) < len) return (u64)(s64)-EFAULT;
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
     * it does have, so the room cannot be demanded up front either. */
    size_t len = rw_count(a2);
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
    /* Copy only what the buffer holds -- with MSG_TRUNC n is the untruncated
     * datagram length, which exceeds both the bounce allocation and the guest
     * buffer -- but still report n, as the kernel does. */
    size_t got = (size_t)n < len ? (size_t)n : len;
    if (n > 0 && copy_to_guest(c, a1, buf, got) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    free(buf);
    u64 e = addr_out(c, a4, a5, &ss, sl);
    if ((s64)e < 0) return e;
    return (u64)n;
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

SYSDEF(setsockopt) {
    size_t len = (size_t)a4;
    if (len > 4096) return (u64)(s64)-EINVAL;
    u8 buf[4096];
    if (len && copy_from_guest(c, buf, a3, len) < 0) return (u64)(s64)-EFAULT;
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

SYSDEF(getsockopt) {
    u32 glen = 0;
    if (a4 && copy_from_guest(c, &glen, a4, 4) < 0) return (u64)(s64)-EFAULT;
    /* The reverse of setsockopt's SO_RCVTIMEO/SO_SNDTIMEO conversion: on a
     * host whose timeval is not the guest's 16-byte one the kernel would
     * write 8 bytes where the guest expects 16, read back as a garbage
     * tv_sec. Same macro-renumbering note as there. */
    if ((SO_RCVTIMEO != 20 || sizeof(struct timeval) != 16) &&
        (int)a1 == SOL_SOCKET && ((int)a2 == 20 || (int)a2 == 21)) {
        struct timeval tv;
        socklen_t tl = sizeof tv;
        if (getsockopt((int)a0, SOL_SOCKET,
                       (int)a2 == 20 ? SO_RCVTIMEO : SO_SNDTIMEO, &tv, &tl) < 0)
            return host_err();
        u8 g[16];
        s64 v = (s64)tv.tv_sec;  memcpy(g, &v, 8);
        v = (s64)tv.tv_usec;     memcpy(g + 8, &v, 8);
        u32 outl = glen < 16 ? glen : 16;   /* kernel: len = min(len, lv) */
        if (a3 && outl && copy_to_guest(c, a3, g, outl) < 0) return (u64)(s64)-EFAULT;
        if (a4 && copy_to_guest(c, a4, &outl, 4) < 0) return (u64)(s64)-EFAULT;
        return 0;
    }
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
#define MSG_CTRL_MAX   4096   /* both callers' staging buffers are this big */

/* Guest control buffer -> host. Returns the host controllen, or -1 if the
 * result would not fit (the caller reports EINVAL, as the kernel does for a
 * control buffer it cannot hold). */
static ssize_t cmsg_g2h(const u8 *gb, size_t glen, u8 *hb, size_t hcap) {
    size_t goff = 0, hoff = 0;
    while (goff + GCMSG_HDRLEN <= glen) {
        u64 clen;
        s32 level, type;
        memcpy(&clen, gb + goff, 8);
        memcpy(&level, gb + goff + 8, 4);
        memcpy(&type, gb + goff + 12, 4);
        /* Bound by subtraction: clen is a guest u64 and must not be trusted to
         * advance the walk (see the netlink walks for the same hazard). */
        if (clen < GCMSG_HDRLEN || clen > glen - goff) break;
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
        hoff += hstep;
        goff += (size_t)GCMSG_ALIGN(clen);
    }
    return (ssize_t)hoff;
}

/* Host control buffer -> guest, in the guest's layout and bounded by the
 * guest's buffer. Sets *ctrunc when anything had to be dropped or cut short. */
static size_t cmsg_h2g(const u8 *hb, size_t hlen, u8 *gb, size_t gcap,
                       int *ctrunc) {
    size_t hoff = 0, goff = 0;
    while (hoff + CMSG_ALIGN(sizeof(struct cmsghdr)) <= hlen) {
        struct cmsghdr ch;
        memcpy(&ch, hb + hoff, sizeof ch);
        size_t clen = ch.cmsg_len;
        if (clen < CMSG_LEN(0) || clen > hlen - hoff) break;
        size_t dlen = clen - CMSG_LEN(0);
        u64 gel = GCMSG_HDRLEN + (u64)dlen;
        size_t avail = gcap - goff;
        if (gel > avail) {
            /* Too big for what is left. The kernel's put_cmsg does not drop
             * the element -- it writes the header with the *truncated* length,
             * copies as much payload as fits, and raises MSG_CTRUNC. An ILP32
             * host reaches this where a real LP64 kernel would, because the
             * guest's element is four bytes bigger than the host's. */
            *ctrunc = 1;
            if (avail < GCMSG_HDRLEN) break;   /* not even a header fits */
            gel = avail;
            dlen = (size_t)gel - GCMSG_HDRLEN;
        }
        size_t gstep = (size_t)GCMSG_ALIGN(gel);
        if (gstep > avail) gstep = avail;      /* last element: no room to pad */
        s32 level = ch.cmsg_level, type = ch.cmsg_type;
        if (level == SOL_SOCKET && type == SCM_RIGHTS) {
            /* Arriving descriptors may be another process's tier memfds: the
             * classification cache must stop assuming these numbers are
             * plain files (full element, not the possibly truncated copy --
             * the fds are installed either way). */
            size_t nfd = (clen - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < nfd; i++) {
                int rfd;
                memcpy(&rfd, hb + hoff + CMSG_ALIGN(sizeof(struct cmsghdr)) +
                             i * sizeof(int), sizeof rfd);
                mfd_track_recv(rfd);
            }
        }
        memset(gb + goff, 0, gstep);
        memcpy(gb + goff, &gel, 8);
        memcpy(gb + goff + 8, &level, 4);
        memcpy(gb + goff + 12, &type, 4);
        memcpy(gb + goff + GCMSG_HDRLEN,
               hb + hoff + CMSG_ALIGN(sizeof(struct cmsghdr)), dlen);
        goff += gstep;
        hoff += CMSG_ALIGN(clen);
    }
    if (hoff < hlen) *ctrunc = 1;   /* elements left over that never fit */
    return goff;
}

/* Import a guest msghdr into a host one. `gbase_out` comes back holding the
 * guest base of every segment, taken from the single reading of the guest's
 * iovec array below: a receive has to write the data back to those bases after
 * the host call, and re-reading the guest array to find them again would be
 * reading a different array -- a sibling thread sharing the address space can
 * rewrite it (or unmap it) while the call is parked. import_iovec in the
 * kernel snapshots it once and never looks again. Every out-parameter is the
 * caller's to free. */
static int msg_import(CPU *c, u64 va, GMsghdr *g, struct msghdr *h,
                      struct iovec **iov_out, u64 **gbase_out, u8 **bounce_out,
                      struct sockaddr_storage *ss, u8 *ctrl, size_t ctrl_cap,
                      int for_send, int *dirfd_out) {
    if (copy_from_guest(c, g, va, sizeof *g) < 0) return -EFAULT;
    memset(h, 0, sizeof *h);
    if (g->msg_name && g->msg_namelen) {
        if (for_send) {
            u32 nl = g->msg_namelen > sizeof *ss ? sizeof *ss : g->msg_namelen;
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
     * zero segments there. See iov_from_guest in sys_file.c.) */
    if (g->msg_iovlen > 1024) return -EMSGSIZE;
    unsigned cnt = (unsigned)g->msg_iovlen;
    GIovec gi[1024];
    if (cnt && copy_from_guest(c, gi, g->msg_iov, sizeof(GIovec) * cnt) < 0) return -EFAULT;
    /* Bound every segment on its own, not just the sum: iov_len is a guest u64,
     * so lengths chosen to wrap the host-width total would pass a sum-only check
     * while each stays huge, and the per-segment copy below uses the unclamped
     * length. Accumulate in u64 (cnt <= 1024, each <= 2^24: no wrap). */
    u64 total = 0;
    for (unsigned i = 0; i < cnt; i++) {
        if (gi[i].iov_len > (1u << 24)) return -EINVAL;
        total += gi[i].iov_len;
        if (total > (1u << 24)) return -EINVAL;
    }
    u8 *bounce = malloc(total ? (size_t)total : 1);
    struct iovec *iov = malloc(sizeof(struct iovec) * (cnt ? cnt : 1));
    u64 *gbase = malloc(sizeof(u64) * (cnt ? cnt : 1));
    if (!bounce || !iov || !gbase) {
        free(bounce); free(iov); free(gbase); return -ENOMEM;
    }
    size_t off = 0;
    for (unsigned i = 0; i < cnt; i++) {
        iov[i].iov_base = bounce + off;
        iov[i].iov_len = gi[i].iov_len;
        gbase[i] = gi[i].iov_base;
        if (for_send && gi[i].iov_len &&
            copy_from_guest(c, bounce + off, gi[i].iov_base, gi[i].iov_len) < 0) {
            free(bounce); free(iov); free(gbase); return -EFAULT;
        }
        off += gi[i].iov_len;
    }
    h->msg_iov = iov;
    h->msg_iovlen = cnt;
    if (g->msg_control && g->msg_controllen) {
        size_t cl = g->msg_controllen > ctrl_cap ? ctrl_cap : g->msg_controllen;
        if (cl > MSG_CTRL_MAX) cl = MSG_CTRL_MAX;
        if (for_send) {
            /* Stage the guest's buffer, then rebuild it in the host's cmsghdr
             * layout -- the two differ on an ILP32 host. */
            u8 gctrl[MSG_CTRL_MAX];
            if (copy_from_guest(c, gctrl, g->msg_control, cl) < 0) {
                free(bounce); free(iov); free(gbase); return -EFAULT;
            }
            ssize_t hl = cmsg_g2h(gctrl, cl, ctrl, ctrl_cap);
            if (hl < 0) { free(bounce); free(iov); free(gbase); return -EINVAL; }
            h->msg_controllen = (size_t)hl;
        } else {
            /* Receiving: the host writes its own layout here and the writeback
             * converts. A host element is never larger than the guest's, so on
             * an ILP32 host the conversion can expand past what the guest
             * offered; that is reported as a short controllen plus MSG_CTRUNC,
             * exactly as the kernel reports a control buffer it outgrew. */
            h->msg_controllen = cl;
        }
        h->msg_control = ctrl;
    }
    h->msg_flags = g->msg_flags;
    *iov_out = iov;
    *gbase_out = gbase;
    *bounce_out = bounce;
    /* Translate an AF_UNIX destination path last: unix_path_in may open a dirfd
     * (for a path that overflows sun_path) which the caller closes after the
     * send, so doing it after every fallible step above means an error can never
     * leak that fd. dirfd_out is left -1 by unix_path_in on any error. */
    if (for_send && h->msg_name) {
        socklen_t sl = h->msg_namelen;
        int tr = unix_path_in(c, ss, &sl, 1, dirfd_out);
        if (tr < 0) { free(iov); free(gbase); free(bounce); return tr; }
        h->msg_namelen = sl;
    }
    return (int)cnt;
}

SYSDEF(sendmsg) {
    if (nl_is_fd(c->m, (int)a0)) return nl_sendmsg(c, (int)a0, a1);
    GMsghdr g;
    struct msghdr h;
    struct iovec *iov;
    u64 *gbase;
    u8 *bounce;
    struct sockaddr_storage ss;
    u8 ctrl[4096];
    int dfd = -1;
    int cnt = msg_import(c, a1, &g, &h, &iov, &gbase, &bounce, &ss, ctrl, sizeof ctrl, 1, &dfd);
    if (cnt < 0) return (u64)(s64)cnt;   /* dfd == -1 on error: nothing to close */
    /* As in sendto: note a reconfiguring rtnetlink request from a guest with a
     * faked network namespace. The message starts at the first iovec, which
     * msg_import laid at the head of the bounce buffer. */
    if (cnt > 0) nlr_note_request(c->m, (int)a0, bounce, iov[0].iov_len);
    ssize_t n = sendmsg((int)a0, &h, (int)a2);
    free(iov); free(gbase); free(bounce);
    if (dfd >= 0) close(dfd);
    return n < 0 ? host_err() : (u64)n;
}

/* Scatter a received message back into the guest: iov data, source address,
 * control, and the updated header at `hdr_va`. `n` is the recvmsg result.
 *
 * Returns 0, or -EFAULT if any of that could not be written. The message is
 * already off the socket by then and cannot be put back -- which is exactly
 * what a kernel does with a datagram whose destination buffer faults: the data
 * is gone and the call reports EFAULT. Reporting success instead would tell
 * the guest bytes were delivered to memory that never received them. */
static int recvmsg_writeback(CPU *c, u64 hdr_va, GMsghdr *g, struct msghdr *h,
                             struct iovec *iov, const u64 *gbase, u8 *bounce,
                             struct sockaddr_storage *ss, u8 *ctrl, ssize_t n) {
    int cnt = (int)h->msg_iovlen;
    ssize_t left = n;
    size_t off = 0;
    for (int i = 0; i < cnt && left > 0; i++) {
        size_t chunk = (size_t)left < iov[i].iov_len ? (size_t)left : iov[i].iov_len;
        if (chunk && copy_to_guest(c, gbase[i], bounce + off, chunk) < 0)
            return -EFAULT;
        off += iov[i].iov_len;
        left -= (ssize_t)chunk;
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
        u8 gctrl[MSG_CTRL_MAX];
        size_t gcap = g->msg_controllen > MSG_CTRL_MAX ? MSG_CTRL_MAX
                                                       : (size_t)g->msg_controllen;
        int ctrunc = 0;
        size_t gl = cmsg_h2g(ctrl, h->msg_controllen, gctrl, gcap, &ctrunc);
        if (gl && copy_to_guest(c, g->msg_control, gctrl, gl) < 0) return -EFAULT;
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
    struct iovec *iov;
    u64 *gbase;
    u8 *bounce;
    struct sockaddr_storage ss;
    u8 ctrl[4096];
    int cnt = msg_import(c, a1, &g, &h, &iov, &gbase, &bounce, &ss, ctrl, sizeof ctrl, 0, NULL);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n = recvmsg((int)a0, &h, (int)a2);
    if (n < 0) { free(iov); free(gbase); free(bounce); return host_err(); }
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
    int wb = recvmsg_writeback(c, a1, &g, &h, iov, gbase, bounce, &ss, ctrl, n);
    free(iov); free(gbase); free(bounce);
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
        GMsghdr g; struct msghdr h; struct iovec *iov; u64 *gbase; u8 *bounce;
        struct sockaddr_storage ss; u8 ctrl[4096];
        int dfd = -1;
        int cnt = msg_import(c, entry, &g, &h, &iov, &gbase, &bounce, &ss, ctrl, sizeof ctrl, 1, &dfd);
        if (cnt < 0) return sent ? (u64)sent : (u64)(s64)cnt;   /* dfd == -1 */
        /* As sendmsg: note a reconfiguring rtnetlink request from a guest whose
         * network namespace was faked, so its refusal can be rewritten. */
        if (cnt > 0) nlr_note_request(c->m, (int)a0, bounce, iov[0].iov_len);
        ssize_t n = sendmsg((int)a0, &h, (int)a3);
        free(iov); free(gbase); free(bounce);
        if (dfd >= 0) close(dfd);
        if (n < 0) return sent ? (u64)sent : host_err();
        u32 mlen = (u32)n;
        if (copy_to_guest(c, entry + GMMSG_LEN_OFF, &mlen, 4) < 0)
            return sent ? (u64)sent : (u64)(s64)-EFAULT;
        sent++;
    }
    return (u64)sent;
}

/* CLOCK_MONOTONIC now, in nanoseconds -- the clock recvmmsg's timeout runs on
 * (poll_select_set_timeout uses ktime_get_ts64). */
static u64 mono_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (u64)t.tv_sec * 1000000000ULL + (u64)t.tv_nsec;
}

/* Wait for `fd` to become readable, but never past `deadline` (monotonic ns).
 * 1 readable, 0 the deadline arrived first, -1 error/interrupted (errno set). */
static int wait_readable(int fd, u64 deadline) {
    u64 now = mono_ns();
    if (now >= deadline) return 0;
    u64 left = deadline - now;
    int ms = (int)((left + 999999ULL) / 1000000ULL);   /* round up: never early */
    if (ms < 0) ms = -1;                               /* absurdly far: block */
    struct pollfd p = { fd, POLLIN, 0 };
    int r = poll(&p, 1, ms);
    return r > 0 ? 1 : r;
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
    u64 deadline = 0;
    if (a4) {
        GTimespec gt;
        if (copy_from_guest(c, &gt, a4, sizeof gt) < 0) return (u64)(s64)-EFAULT;
        if (gt.tv_sec < 0 || (u64)gt.tv_nsec >= 1000000000ULL)
            return (u64)(s64)-EINVAL;
        struct timespec rel = { (time_t)gt.tv_sec, (long)gt.tv_nsec };
        syscall_wait_begin(&rel);   /* a restart keeps the deadline (syscall.c) */
        deadline = mono_ns() +
                   (u64)rel.tv_sec * 1000000000ULL + (u64)rel.tv_nsec;
        have_tmo = 1;
    }
    int got = 0;
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
        GMsghdr g; struct msghdr h; struct iovec *iov; u64 *gbase; u8 *bounce;
        struct sockaddr_storage ss; u8 ctrl[4096];
        int cnt = msg_import(c, entry, &g, &h, &iov, &gbase, &bounce, &ss, ctrl, sizeof ctrl, 0, NULL);
        if (cnt < 0) return got ? (u64)got : (u64)(s64)cnt;
        ssize_t n = recvmsg((int)a0, &h, mf);
        if (n < 0) {
            free(iov); free(gbase); free(bounce);
            if (got) break;   /* return the messages received so far */
            return host_err();
        }
        /* Rewrite a faked-namespace refusal, as recvmsg does. */
        if (n > 0) {
            size_t total = 0;
            for (int k = 0; k < cnt; k++) total += iov[k].iov_len;
            nlr_fix_reply(c->m, (int)a0, bounce,
                          (size_t)n < total ? (size_t)n : total, mf & MSG_PEEK);
        }
        int wb = recvmsg_writeback(c, entry, &g, &h, iov, gbase, bounce, &ss, ctrl, n);
        u32 mlen = (u32)n;
        if (wb == 0 && copy_to_guest(c, entry + GMMSG_LEN_OFF, &mlen, 4) < 0)
            wb = -EFAULT;
        free(iov); free(gbase); free(bounce);
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
        u64 now = mono_ns();
        u64 left = now < deadline ? deadline - now : 0;
        GTimespec out = { (s64)(left / 1000000000ULL),
                          (s64)(left % 1000000000ULL) };
        if (copy_to_guest(c, a4, &out, sizeof out) < 0) return (u64)(s64)-EFAULT;
    }
    return (u64)got;
}
