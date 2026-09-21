/* Host-side helper: a Unix-socket peer outside the guest.
 *
 * What SO_PEERCRED and SCM_CREDENTIALS report about a peer the guest cannot
 * see is only testable with such a peer, and only a process on this side of
 * the emulator is one. Listens on the path given, prints "ready" (the harness
 * waits for that line), accepts one connection, sends a byte with its own
 * credentials attached explicitly and two descriptors whose async owner
 * (F_SETOWN) it has set to itself and to its process group -- what F_GETOWN
 * reports for a descriptor a host process handed over -- and holds the
 * connection until the peer closes it.
 *
 * Built with the HOST compiler, like tests/hostlock.c -- nothing here is
 * guest code. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", argv[1]);
    unlink(argv[1]);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 1) < 0) return 1;
    printf("ready\n");
    fflush(stdout);
    int c = accept(s, NULL, NULL);
    if (c < 0) return 1;
    struct ucred cr = { getpid(), getuid(), getgid() };
    int owned[2];                              /* owner: our pid; our group */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, owned) < 0) return 1;
    if (fcntl(owned[0], F_SETOWN, getpid()) < 0 ||
        fcntl(owned[1], F_SETOWN, -getpgrp()) < 0) return 1;
    char cbuf[CMSG_SPACE(sizeof cr) + CMSG_SPACE(sizeof owned)];
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
    cm = CMSG_NXTHDR(&mh, cm);
    cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof owned);
    memcpy(CMSG_DATA(cm), owned, sizeof owned);
    if (sendmsg(c, &mh, 0) != 1) return 1;
    char b;
    while (read(c, &b, 1) > 0) ;
    return 0;
}
