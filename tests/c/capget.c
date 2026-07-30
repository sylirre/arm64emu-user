/* capget(2)'s header protocol, against the qemu-aarch64 oracle.
 *
 * The header is both an input and an output. A version the kernel does not
 * recognise is answered by writing the preferred version back into it, and
 * libcap's startup probe relies on precisely that: it calls capget with a
 * deliberately bogus version and a NULL data pointer, purely to read the
 * kernel's answer out of the header. That probe reports success; a call that
 * actually wanted data gets EINVAL. The pid field is an input too -- asking
 * about a process that does not exist is ESRCH, not a capability set.
 *
 * No capability *values* are printed: they legitimately differ between a
 * plain run and one under --fake-id, and the point here is the protocol. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct caphdr { unsigned version; int pid; };
struct capdat { unsigned eff, perm, inh; };

#define VER_1 0x19980330u
#define VER_2 0x20071026u
#define VER_3 0x20080522u

static int capget_(struct caphdr *h, struct capdat *d) {
    return (int)syscall(SYS_capget, h, d);
}

int main(void) {
    struct caphdr h;
    struct capdat d[2];

    /* libcap's probe: bad version, no data buffer. */
    memset(&h, 0, sizeof h);
    errno = 0;
    int r = capget_(&h, NULL);
    printf("probe rc=%d version_is_v3=%d\n", r, h.version == VER_3);

    /* Bad version but data wanted: EINVAL, and still writes the version. */
    memset(&h, 0, sizeof h);
    h.version = 0xdeadbeef;
    errno = 0;
    r = capget_(&h, d);
    printf("badver rc=%d einval=%d version_is_v3=%d\n", r,
           r < 0 && errno == EINVAL, h.version == VER_3);

    /* Each known version is accepted. */
    unsigned vers[3] = { VER_1, VER_2, VER_3 };
    for (int i = 0; i < 3; i++) {
        memset(&h, 0, sizeof h);
        h.version = vers[i];
        h.pid = 0;
        errno = 0;
        r = capget_(&h, d);
        printf("v%d rc=%d\n", i + 1, r);
    }

    /* A pid naming no process. */
    memset(&h, 0, sizeof h);
    h.version = VER_3;
    h.pid = 0x7ffffff;
    errno = 0;
    r = capget_(&h, d);
    printf("badpid rc=%d esrch=%d\n", r, r < 0 && errno == ESRCH);

    /* A negative pid is rejected outright. */
    memset(&h, 0, sizeof h);
    h.version = VER_3;
    h.pid = -5;
    errno = 0;
    r = capget_(&h, d);
    printf("negpid rc=%d einval=%d\n", r, r < 0 && errno == EINVAL);

    /* Our own pid, spelled both ways. */
    memset(&h, 0, sizeof h);
    h.version = VER_3;
    h.pid = 0;
    printf("self_zero rc=%d\n", capget_(&h, d));
    memset(&h, 0, sizeof h);
    h.version = VER_3;
    h.pid = getpid();
    printf("self_pid rc=%d\n", capget_(&h, d));

    printf("done\n");
    return 0;
}
