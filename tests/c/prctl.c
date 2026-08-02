/* SAME-HOST-ONLY: the capability bounding set is real host state (Android
 * drops caps an x86 host keeps). */
/* prctl: capability bounding set + keepcaps are passed straight through to
 * the host kernel (sys_proc.c), so emulator output must match qemu-aarch64
 * exactly -- both are real syscalls against the same host kernel. */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/prctl.h>

static void show(const char *what, long r) {
    if (r < 0) printf("%s=-1 errno=%s\n", what, strerror(errno));
    else printf("%s=%ld\n", what, r);
}

int main(void) {
    errno = 0;
    show("capbset_read(0)", prctl(PR_CAPBSET_READ, 0));
    errno = 0;
    show("capbset_read(huge)", prctl(PR_CAPBSET_READ, 999999));

    errno = 0;
    show("set_keepcaps(1)", prctl(PR_SET_KEEPCAPS, 1));
    errno = 0;
    show("get_keepcaps", prctl(PR_GET_KEEPCAPS));

    errno = 0;
    show("set_keepcaps(0)", prctl(PR_SET_KEEPCAPS, 0));
    errno = 0;
    show("get_keepcaps", prctl(PR_GET_KEEPCAPS));
    return 0;
}
