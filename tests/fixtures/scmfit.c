/* SCM_RIGHTS against a control buffer too small for every descriptor sent:
 * the kernel installs only as many as the caller's buffer can REPORT
 * (scm_detach_fds: fdmax from the remaining controllen, one header's worth
 * subtracted first, so a buffer that holds only the header carries none and
 * emits no element at all), releases the rest unopened and raises MSG_CTRUNC.
 * Every descriptor in the receiver's table is therefore one it was told
 * about.
 *
 * The emulator has the host install descriptors into a buffer of the host's
 * layout and converts afterwards. On an ILP32 host that layout is four bytes
 * tighter per element than the guest's, so the host fits descriptors the
 * guest's buffer cannot report -- and those used to stay open, unreported: a
 * hidden entry in the guest's own table per truncated receive. Self-checking
 * rather than qemu-diffed: qemu-user receives into a buffer of its own and
 * trims the target's afterwards, so it installs every descriptor sent and
 * never raises MSG_CTRUNC -- the very defect. The expectations are the
 * kernel's own answers (the same program, compiled natively, prints the same
 * block), and they hold on every host width. Each row reports what the
 * receive said and, separately, what the table says -- the count of entries
 * in /proc/self/fd before and after -- which is where a leak shows.
 *
 * Rows: a buffer with room for one of three descriptors; one with room for
 * the header alone; a SCM_CREDENTIALS element ahead of the rights (SO_PASSCRED)
 * that leaves the rights element no room at all, and one that leaves it less
 * than a header; and a buffer with room for everything, as the control. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static void row(const char *label, size_t controllen, int passcred) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) { printf("%s: socketpair\n", label); return; }
    if (passcred) {
        int one = 1;
        setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof one);
    }
    int fds[3];
    for (int i = 0; i < 3; i++) fds[i] = open("/dev/null", O_RDONLY);
    /* Send three descriptors with one byte of data. */
    char cbuf[CMSG_SPACE(sizeof fds)];
    memset(cbuf, 0, sizeof cbuf);
    char byte = 'x';
    struct iovec iov = { &byte, 1 };
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov; mh.msg_iovlen = 1;
    mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof fds);
    memcpy(CMSG_DATA(cm), fds, sizeof fds);
    ssize_t sn = sendmsg(sv[0], &mh, 0);
    for (int i = 0; i < 3; i++) close(fds[i]);
    int before = fd_count();
    /* Receive into a buffer of the given size. */
    char rbuf[256];
    memset(rbuf, 0, sizeof rbuf);
    struct msghdr rh;
    memset(&rh, 0, sizeof rh);
    rh.msg_iov = &iov; rh.msg_iovlen = 1;
    rh.msg_control = rbuf; rh.msg_controllen = controllen;
    ssize_t rn = recvmsg(sv[1], &rh, 0);
    int after = fd_count();
    int got = 0, creds = 0, rights_len = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&rh); c; c = CMSG_NXTHDR(&rh, c)) {
        if (c->cmsg_level != SOL_SOCKET) continue;
        if (c->cmsg_type == SCM_RIGHTS) {
            rights_len = (int)c->cmsg_len;
            int n = (int)((c->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            for (int i = 0; i < n; i++) {
                int fd;
                memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof fd);
                got++;
                close(fd);
            }
        } else if (c->cmsg_type == SCM_CREDENTIALS) {
            creds++;
        }
    }
    printf("%s: sent=%zd recv=%zd ctrunc=%d controllen=%zu creds=%d rights_len=%d "
           "reported=%d installed=%d\n",
           label, sn, rn, (rh.msg_flags & MSG_CTRUNC) != 0,
           (size_t)rh.msg_controllen, creds, rights_len, got, after - before);
    close(sv[0]); close(sv[1]);
}

int main(void) {
    row("one_fits",   CMSG_LEN(sizeof(int)), 0);      /* 20: one of three */
    row("header",     CMSG_LEN(0), 0);                /* 16: none, no element */
    row("cred_zero",  CMSG_SPACE(12) + CMSG_LEN(0), 1);   /* rights: header only */
    row("cred_short", CMSG_SPACE(12) + 8, 1);         /* rights: less than a header */
    row("all",        CMSG_SPACE(sizeof(int) * 3), 0);
    printf("done\n");
    return 0;
}
