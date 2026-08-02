/* getrandom(2): semantics only -- byte content is random by definition, so
 * the probes print lengths and errnos, never bytes. The suite runs this
 * against the raw-syscall path; run_tests.sh re-runs it with
 * A64_GETRANDOM_FORCE_DEV=1 so the /dev-backed fallback tier -- what a host
 * kernel without getrandom (Android 7's 3.x) is served by -- must answer
 * with identical semantics. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static long gr(void *buf, size_t len, unsigned flags) {
    long r = syscall(SYS_getrandom, buf, len, flags);
    return r < 0 ? -errno : r;
}

int main(void) {
    unsigned char b[512];
    printf("len64=%ld\n", gr(b, 64, 0));
    printf("len0=%ld\n", gr(b, 0, 0));
    printf("len512=%ld\n", gr(b, 512, 0));
    printf("nonblock=%ld\n", gr(b, 16, 0x1 /* GRND_NONBLOCK */));
    printf("insecure=%ld\n", gr(b, 16, 0x4 /* GRND_INSECURE */));
    printf("rnd_nb=%ld\n", gr(b, 16, 0x2 | 0x1 /* GRND_RANDOM|NONBLOCK */));
    printf("badflag=%ld\n", gr(b, 16, 0x100));
    printf("conflict=%ld\n", gr(b, 16, 0x2 | 0x4 /* RANDOM|INSECURE */));
    gr(b, 64, 0);
    int varies = 0;
    for (int i = 1; i < 64; i++)
        if (b[i] != b[0]) { varies = 1; break; }
    printf("varies=%d\n", varies);
    return 0;
}
