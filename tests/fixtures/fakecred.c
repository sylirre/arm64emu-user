/* SCM_CREDENTIALS under --fake-id. A guest sends its own identity as it
 * knows it -- {getpid(), getuid(), getgid()}, which is what dbus
 * authentication, sd_notify and polkit put in the element -- and the kernel
 * judges the uid and gid against the sender's REAL credentials
 * (scm_check_creds): a fake root sending uid 0 was refused EPERM by a host
 * whose task is not root. The emulator now sends the host identity the fake
 * one stands for and hands the receiver the fake one back, the way
 * SO_PEERCRED already did; what the receiver reads must agree with what the
 * sender's getuid() said. Self-checking: qemu-user does not model --fake-id.
 * Also the credentials of a peer that never sent any (SO_PASSCRED makes the
 * kernel attach them), and a third party's credentials the fake root has no
 * host right to claim, which stays the host's refusal. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int send_creds(int fd, pid_t pid, uid_t uid, gid_t gid) {
    struct ucred uc = { pid, uid, gid };
    char cbuf[CMSG_SPACE(sizeof uc)];
    struct iovec iov = { "h", 1 };
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov; mh.msg_iovlen = 1;
    mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_CREDENTIALS;
    cm->cmsg_len = CMSG_LEN(sizeof uc);
    memcpy(CMSG_DATA(cm), &uc, sizeof uc);
    return sendmsg(fd, &mh, 0) < 0 ? -errno : 0;
}

static int recv_creds(int fd, struct ucred *out) {
    char rb[8], rc[128];
    struct iovec iov = { rb, sizeof rb };
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov; mh.msg_iovlen = 1;
    mh.msg_control = rc; mh.msg_controllen = sizeof rc;
    if (recvmsg(fd, &mh, 0) < 0) return -errno;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS) {
            memcpy(out, CMSG_DATA(c), sizeof *out);
            return 1;
        }
    return 0;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 1;
    int one = 1;
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof one);
    printf("me uid=%d gid=%d\n", (int)getuid(), (int)getgid());

    /* Our own credentials, as we know them. */
    int r = send_creds(sv[0], getpid(), getuid(), getgid());
    printf("send_own=%d\n", r);
    struct ucred uc;
    if (r == 0 && recv_creds(sv[1], &uc) == 1)
        printf("recv_own pid_ok=%d uid=%d gid=%d\n", uc.pid == getpid(), (int)uc.uid, (int)uc.gid);
    /* The effective ids pass too (the kernel accepts real, effective or saved). */
    r = send_creds(sv[0], getpid(), geteuid(), getegid());
    printf("send_eff=%d\n", r);
    if (r == 0 && recv_creds(sv[1], &uc) == 1)
        printf("recv_eff uid=%d gid=%d\n", (int)uc.uid, (int)uc.gid);
    /* No element at all: SO_PASSCRED makes the kernel attach the sender's
     * own, which the receiver must see as the fake identity. */
    if (write(sv[0], "x", 1) == 1 && recv_creds(sv[1], &uc) == 1)
        printf("passcred pid_ok=%d uid=%d gid=%d\n", uc.pid == getpid(), (int)uc.uid, (int)uc.gid);
    /* SO_PEERCRED agrees. */
    struct ucred pc; socklen_t pl = sizeof pc;
    if (getsockopt(sv[1], SOL_SOCKET, SO_PEERCRED, &pc, &pl) == 0)
        printf("peercred uid=%d gid=%d\n", (int)pc.uid, (int)pc.gid);
    /* Somebody else's identity: the host's refusal, whatever we think we are. */
    r = send_creds(sv[0], getpid(), 54321, 54321);
    printf("send_other=%d\n", r);
    /* A pid that is not ours: refused before the ids are looked at. */
    r = send_creds(sv[0], 1, getuid(), getgid());
    printf("send_pid1=%d\n", r);
    printf("done\n");
    return 0;
}
