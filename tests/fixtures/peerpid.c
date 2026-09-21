/* A socket peer's pid as the guest may see it: SO_PEERCRED and
 * SCM_CREDENTIALS -- and a descriptor's async owner, F_GETOWN / F_GETOWN_EX.
 *
 * Guest pids are host pids, and both faces used to hand the guest the pid
 * the host reported -- so a guest connected to a host daemon's socket (any
 * bind of /run or /tmp brings one in reach) read the daemon's host pid, a
 * process it can see nowhere else. A kernel answers a caller in a pid
 * namespace of its own with pid_vnr: the peer's number when it was allocated
 * in the caller's namespace, 0 otherwise. The socket keeps a reference on
 * the peer's pid, so a guest client that has already exited is still named
 * (a server that asks after a short-lived client has gone reads its pid, as
 * on a kernel). The uid/gid stay the real ones without -fake-id.
 *
 * An fd's async owner is the same story: F_SETOWN admits only ids the guest
 * can see, but a descriptor received over SCM_RIGHTS from a host process
 * arrives with its owner already set, and F_GETOWN reported it raw -- and
 * reported every group-owned descriptor (-pgid) as an error besides.
 *
 * Rows: a guest child as the peer (its pid, live and after it exited, from
 * both faces), this process's own owners (itself, its thread, its group,
 * both query forms), and -- with a host peer's socket path and pid named on
 * the command line -- a host process as the peer (0 from both, the uid still
 * the caller's own) handing over descriptors it owns (0 from both forms).
 * Self-checking: qemu-user forwards the raw answer, and the host block is
 * what the kernel prints for a caller in a child pid namespace. Run as
 *   arm64chroot / tests/fixtures/peerpid.bin [<host socket path> <host pid>] */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* How the reported pid relates to the peer's real one. */
static const char *pidname(int pid, int peer) {
    return pid == 0 ? "0" : pid == peer ? "peer" : pid == getpid() ? "self" : "other";
}
static void peercred(const char *label, int fd, int child) {
    struct ucred cr;
    socklen_t l = sizeof cr;
    memset(&cr, 0, sizeof cr);
    int r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &l);
    printf("%s=%s pid=%s uid_self=%d\n", label, r < 0 ? strerror(errno) : "ok",
           r < 0 ? "?" : pidname((int)cr.pid, child), cr.uid == getuid());
    /* The first four bytes alone are the pid, and are translated alone. */
    int pid = -7;
    l = 4;
    r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &pid, &l);
    printf("%s_short=%s len=%d pid=%s\n", label, r < 0 ? strerror(errno) : "ok",
           (int)l, r < 0 ? "?" : pidname(pid, child));
}
/* Receives one byte with its credentials, and any descriptors sent with it
 * into fds[0..1] (-1 when none came). */
static void creds_recv(const char *label, int fd, int child, int *fds) {
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof one);
    char b, cbuf[256];
    struct iovec iov = { &b, 1 };
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov; mh.msg_iovlen = 1;
    mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
    ssize_t n = recvmsg(fd, &mh, 0);
    const char *got = "none";
    int uid_self = 0;
    fds[0] = fds[1] = -1;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_CREDENTIALS) {
            struct ucred cr;
            memcpy(&cr, CMSG_DATA(cm), sizeof cr);
            got = pidname((int)cr.pid, child);
            uid_self = cr.uid == getuid();
        }
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
            cm->cmsg_len >= CMSG_LEN(2 * sizeof(int)))
            memcpy(fds, CMSG_DATA(cm), 2 * sizeof(int));
    }
    printf("%s=%zd pid=%s uid_self=%d\n", label, n, got, uid_self);
}
/* F_GETOWN and F_GETOWN_EX on one descriptor. `peer` is the owner's real
 * pid (or the group leader's), so the report is named relative to it. */
static void owner(const char *label, int fd, int peer) {
    errno = 0;
    int r = fcntl(fd, F_GETOWN);
    int e = errno;
    struct f_owner_ex ex = { -1, -1 };
    int rx = fcntl(fd, F_GETOWN_EX, &ex);
    printf("%s: getown=%s%s getown_ex=%s type=%d pid=%s\n", label,
           r < 0 && e ? strerror(e) : r < 0 ? "-" : "",
           r < 0 && e ? "" : pidname(r < 0 ? -r : r, peer),
           rx < 0 ? strerror(errno) : "ok", rx < 0 ? -1 : (int)ex.type,
           rx < 0 ? "?" : pidname((int)ex.pid, peer));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* A guest child as the peer. */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) return 1;
    pid_t k = fork();
    if (k < 0) return 1;
    if (k == 0) {
        close(sp[0]);
        struct ucred cr = { getpid(), getuid(), getgid() };
        char cbuf[CMSG_SPACE(sizeof cr)];
        memset(cbuf, 0, sizeof cbuf);
        struct iovec iov = { "x", 1 };
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_iov = &iov; mh.msg_iovlen = 1;
        mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_CREDENTIALS;
        cm->cmsg_len = CMSG_LEN(sizeof cr);
        memcpy(CMSG_DATA(cm), &cr, sizeof cr);
        if (sendmsg(sp[1], &mh, 0) != 1) _exit(1);
        char c;
        if (read(sp[1], &c, 1) < 0) _exit(1);   /* until the parent says so */
        _exit(0);
    }
    close(sp[1]);
    /* A socketpair's ends are both this process's: the peer pid it reports is
     * the creator's, ours, which is the kernel's answer too. The child's pid
     * arrives in its credentials. */
    peercred("pair_peercred", sp[0], (int)k);
    int fds[2];
    creds_recv("child_creds", sp[0], (int)k, fds);
    /* This process's own owners, every form: pid, tid, group (which it must
     * lead to name it; setpgid puts it at the head of one of its own). */
    owner("own_none", sp[0], (int)getpid());
    if (fcntl(sp[0], F_SETOWN, getpid()) < 0) return 1;
    owner("own_pid", sp[0], (int)getpid());
    struct f_owner_ex tex = { F_OWNER_TID, (int)getpid() };
    if (fcntl(sp[0], F_SETOWN_EX, &tex) < 0) return 1;
    owner("own_tid", sp[0], (int)getpid());
    if (setpgid(0, 0) < 0 || fcntl(sp[0], F_SETOWN, -getpid()) < 0) return 1;
    owner("own_pgrp", sp[0], (int)getpid());
    /* A connection the child makes: the peer is the child, alive and then
     * gone -- the socket keeps its pid. */
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "./.peerpid.%d", (int)getpid());
    unlink(a.sun_path);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0 || listen(ls, 1) < 0) {
        printf("SKIP: no writable directory\n");
        return 0;
    }
    pid_t k2 = fork();
    if (k2 == 0) {
        int cs = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(cs, (struct sockaddr *)&a, sizeof a) < 0) _exit(1);
        char c;
        if (read(cs, &c, 1) < 0) _exit(1);      /* until the parent says so */
        _exit(0);
    }
    int cs = accept(ls, NULL, NULL);
    unlink(a.sun_path);
    peercred("conn_peercred", cs, (int)k2);
    if (write(cs, "q", 1) != 1) return 1;
    int st;
    waitpid(k2, &st, 0);
    peercred("gone_peercred", cs, (int)k2);
    close(cs); close(ls);
    if (write(sp[0], "q", 1) != 1) return 1;
    waitpid(k, &st, 0);
    close(sp[0]);

    if (argc >= 3) {
        /* A host process as the peer. */
        int hs = socket(AF_UNIX, SOCK_STREAM, 0);
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        snprintf(a.sun_path, sizeof a.sun_path, "%s", argv[1]);
        if (connect(hs, (struct sockaddr *)&a, sizeof a) < 0) {
            printf("host_connect=%s\n", strerror(errno));
            return 1;
        }
        peercred("host_peercred", hs, atoi(argv[2]));
        creds_recv("host_creds", hs, atoi(argv[2]), fds);
        printf("host_fds=%d\n", fds[0] >= 0 && fds[1] >= 0);
        /* Its descriptors, owned by it and by its group. The group's leader is
         * not known here, so a raw answer reads "other". */
        if (fds[0] >= 0) owner("host_fd_pid", fds[0], atoi(argv[2]));
        if (fds[1] >= 0) owner("host_fd_pgrp", fds[1], atoi(argv[2]));
        close(hs);
    }
    printf("done\n");
    return 0;
}
