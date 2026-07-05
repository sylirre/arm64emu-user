/* Socket syscalls. sockaddr layouts (sockaddr_in/in6/un) are identical across
 * arm64/arm/x86; msghdr and cmsghdr differ only in pointer/size_t width and are
 * converted explicitly, so the code is correct on ILP32 hosts too. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "sys.h"

SYSDEF(socket) {
    (void)a3; (void)a4; (void)a5;
    int fd = socket((int)a0, (int)a1, (int)a2);
    return fd < 0 ? host_err() : (u64)fd;
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

SYSDEF(bind) {
    struct sockaddr_storage ss;
    socklen_t sl;
    int r = addr_in(c, a1, (u32)a2, &ss, &sl);
    if (r < 0) return (u64)(s64)r;
    return bind((int)a0, (struct sockaddr *)&ss, sl) < 0 ? host_err() : 0;
}

SYSDEF(connect) {
    struct sockaddr_storage ss;
    socklen_t sl;
    int r = addr_in(c, a1, (u32)a2, &ss, &sl);
    if (r < 0) return (u64)(s64)r;
    return connect((int)a0, (struct sockaddr *)&ss, sl) < 0 ? host_err() : 0;
}

SYSDEF(listen) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return listen((int)a0, (int)a1) < 0 ? host_err() : 0;
}

/* Write back a sockaddr result (accept/getsockname/getpeername/recvfrom). */
static u64 addr_out(CPU *c, u64 addr_va, u64 len_va, struct sockaddr_storage *ss,
                    socklen_t sl) {
    if (!addr_va || !len_va) return 0;
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
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getsockname((int)a0, (struct sockaddr *)&ss, &sl) < 0) return host_err();
    return addr_out(c, a1, a2, &ss, sl);
}

SYSDEF(getpeername) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getpeername((int)a0, (struct sockaddr *)&ss, &sl) < 0) return host_err();
    return addr_out(c, a1, a2, &ss, sl);
}

SYSDEF(sendto) {
    size_t len = (size_t)a2;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    if (len && copy_from_guest(c, buf, a1, len) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    struct sockaddr *dp = NULL;
    if (a4 && a5) {
        if (addr_in(c, a4, (u32)a5, &ss, &sl) < 0) { free(buf); return (u64)(s64)-EFAULT; }
        dp = (struct sockaddr *)&ss;
    }
    ssize_t n = sendto((int)a0, buf, len, (int)a3, dp, sl);
    free(buf);
    return n < 0 ? host_err() : (u64)n;
}

SYSDEF(recvfrom) {
    size_t len = (size_t)a2;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    ssize_t n = recvfrom((int)a0, buf, len, (int)a3, (struct sockaddr *)&ss, &sl);
    if (n < 0) { free(buf); return host_err(); }
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
                      int for_send) {
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
    return (int)cnt;
}

SYSDEF(sendmsg) {
    GMsghdr g;
    struct msghdr h;
    struct iovec *iov;
    u8 *bounce;
    struct sockaddr_storage ss;
    u8 ctrl[4096];
    int cnt = msg_import(c, a1, &g, &h, &iov, &bounce, &ss, ctrl, sizeof ctrl, 1);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n = sendmsg((int)a0, &h, (int)a2);
    free(iov); free(bounce);
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
    if (g->msg_name && h->msg_namelen)
        copy_to_guest(c, g->msg_name, ss, h->msg_namelen);
    if (g->msg_control && h->msg_controllen)
        copy_to_guest(c, g->msg_control, ctrl, h->msg_controllen);
    g->msg_namelen = h->msg_namelen;
    g->msg_controllen = h->msg_controllen;
    g->msg_flags = h->msg_flags;
    copy_to_guest(c, hdr_va, g, sizeof *g);
}

SYSDEF(recvmsg) {
    GMsghdr g;
    struct msghdr h;
    struct iovec *iov;
    u8 *bounce;
    struct sockaddr_storage ss;
    u8 ctrl[4096];
    int cnt = msg_import(c, a1, &g, &h, &iov, &bounce, &ss, ctrl, sizeof ctrl, 0);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n = recvmsg((int)a0, &h, (int)a2);
    if (n < 0) { free(iov); free(bounce); return host_err(); }
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
        int cnt = msg_import(c, entry, &g, &h, &iov, &bounce, &ss, ctrl, sizeof ctrl, 1);
        if (cnt < 0) return sent ? (u64)sent : (u64)(s64)cnt;
        ssize_t n = sendmsg((int)a0, &h, (int)a3);
        free(iov); free(bounce);
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
        int cnt = msg_import(c, entry, &g, &h, &iov, &bounce, &ss, ctrl, sizeof ctrl, 0);
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
