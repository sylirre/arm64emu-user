/* Ancillary data over AF_UNIX -- SCM_RIGHTS and SCM_CREDENTIALS -- against the
 * qemu-aarch64 oracle.
 *
 * The guest's cmsghdr is LP64: an 8-byte cmsg_len, then level and type, data
 * at +16, elements padded to a multiple of 8. The emulator has to rebuild that
 * in the host's layout, which is only the same shape on a 64-bit host; an
 * ILP32 host has a 4-byte cmsg_len, a 12-byte header and 4-byte padding. This
 * pins down the parts that layout mistakes destroy: the header fields as the
 * receiver reads them, the payload landing at the right offset, a second
 * element found at the right stride, and a control buffer too small to hold
 * the reply reporting MSG_CTRUNC.
 *
 * Everything printed is a comparison rather than a raw value: pids and fd
 * numbers must not leak into the diff. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { printf("pair=fail\n"); return 1; }

    int pfd[2];
    if (pipe(pfd) != 0) { printf("pipe=fail\n"); return 1; }

    /* --- one SCM_RIGHTS element --- */
    char body = 'a';
    struct iovec iov = { &body, 1 };
    union { struct cmsghdr al; char buf[CMSG_SPACE(sizeof(int))]; } cu;
    memset(&cu, 0, sizeof cu);
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cu.buf;
    mh.msg_controllen = sizeof cu.buf;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &pfd[1], sizeof(int));
    printf("send=%zd\n", sendmsg(sv[0], &mh, 0));

    char rbody = 0;
    struct iovec riov = { &rbody, 1 };
    union { struct cmsghdr al; char buf[CMSG_SPACE(sizeof(int))]; } ru;
    memset(&ru, 0, sizeof ru);
    struct msghdr rh;
    memset(&rh, 0, sizeof rh);
    rh.msg_iov = &riov;
    rh.msg_iovlen = 1;
    rh.msg_control = ru.buf;
    rh.msg_controllen = sizeof ru.buf;
    ssize_t n = recvmsg(sv[1], &rh, 0);
    struct cmsghdr *rc = CMSG_FIRSTHDR(&rh);
    printf("recv=%zd body=%d ctrunc=%d\n", n, rbody == 'a',
           (rh.msg_flags & MSG_CTRUNC) != 0);
    printf("cmsg=%d level=%d type=%d len=%d\n", rc != NULL,
           rc && rc->cmsg_level == SOL_SOCKET,
           rc && rc->cmsg_type == SCM_RIGHTS,
           rc && rc->cmsg_len == CMSG_LEN(sizeof(int)));

    /* The descriptor has to be a working one, at the right offset in the
     * payload: write through it and read the bytes out of the pipe. */
    int got = -1;
    if (rc) memcpy(&got, CMSG_DATA(rc), sizeof got);
    printf("fd_valid=%d distinct=%d\n", got >= 0, got != pfd[1]);
    if (got >= 0) {
        ssize_t w = write(got, "ping", 4);
        char rb[8] = { 0 };
        ssize_t r = read(pfd[0], rb, 4);
        printf("through_fd w=%zd r=%zd data=%d\n", w, r, strcmp(rb, "ping") == 0);
        close(got);
    }

    /* --- two elements: the kernel adds SCM_CREDENTIALS when the receiver asks
     * for it, so the reply has to be walked with CMSG_NXTHDR at the right
     * stride. --- */
    int on = 1;
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
    memset(&cu, 0, sizeof cu);
    mh.msg_control = cu.buf;
    mh.msg_controllen = sizeof cu.buf;
    cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &pfd[0], sizeof(int));
    body = 'b';
    printf("send2=%zd\n", sendmsg(sv[0], &mh, 0));

    char big[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
    memset(big, 0, sizeof big);
    rh.msg_control = big;
    rh.msg_controllen = sizeof big;
    rbody = 0;
    n = recvmsg(sv[1], &rh, 0);
    int saw_rights = 0, saw_cred = 0, cred_ok = 0, nelem = 0, passed = -1;
    for (rc = CMSG_FIRSTHDR(&rh); rc; rc = CMSG_NXTHDR(&rh, rc)) {
        nelem++;
        if (rc->cmsg_level != SOL_SOCKET) continue;
        if (rc->cmsg_type == SCM_RIGHTS) {
            saw_rights = 1;
            memcpy(&passed, CMSG_DATA(rc), sizeof passed);
        } else if (rc->cmsg_type == SCM_CREDENTIALS) {
            struct ucred uc;
            memcpy(&uc, CMSG_DATA(rc), sizeof uc);
            saw_cred = 1;
            cred_ok = uc.pid == getpid() && uc.uid == getuid() && uc.gid == getgid();
        }
    }
    printf("recv2=%zd body=%d n=%d rights=%d cred=%d cred_ok=%d fd=%d\n",
           n, rbody == 'b', nelem, saw_rights, saw_cred, cred_ok, passed >= 0);
    if (passed >= 0) close(passed);

    /* --- a control buffer too small for the reply must report MSG_CTRUNC --- */
    memset(&cu, 0, sizeof cu);
    mh.msg_control = cu.buf;
    mh.msg_controllen = sizeof cu.buf;
    cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &pfd[0], sizeof(int));
    body = 'c';
    sendmsg(sv[0], &mh, 0);
    char tiny[CMSG_LEN(0)];
    memset(tiny, 0, sizeof tiny);
    rh.msg_control = tiny;
    rh.msg_controllen = sizeof tiny;
    rbody = 0;
    n = recvmsg(sv[1], &rh, 0);
    printf("trunc recv=%zd body=%d ctrunc=%d\n", n, rbody == 'c',
           (rh.msg_flags & MSG_CTRUNC) != 0);

    /* --- no ancillary data at all: controllen must come back zero --- */
    body = 'd';
    mh.msg_control = NULL;
    mh.msg_controllen = 0;
    sendmsg(sv[0], &mh, 0);
    char none[CMSG_SPACE(sizeof(int))];
    rh.msg_control = none;
    rh.msg_controllen = sizeof none;
    rbody = 0;
    n = recvmsg(sv[1], &rh, 0);
    printf("plain recv=%zd body=%d ctl=%d first=%d\n", n, rbody == 'd',
           (int)rh.msg_controllen, CMSG_FIRSTHDR(&rh) == NULL);

    printf("done\n");
    return 0;
}
