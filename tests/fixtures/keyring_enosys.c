/* Under tests/seccomp_wrap the host keyring syscalls are trapped; the guest
 * must see a clean ENOSYS from each (via the SIGSYS net + host_err), not a
 * dead emulator. Self-checking: the qemu oracle is not seccomp-wrapped. */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

static const char *res(long r) {
    return (r < 0 && errno == ENOSYS) ? "ENOSYS" : "other";
}

int main(void) {
    long r;
    errno = 0;
    r = syscall(219, 0, -3, 0, 0, 0);       /* keyctl KEYCTL_GET_KEYRING_ID */
    printf("keyctl=%s\n", res(r));
    errno = 0;
    r = syscall(217, "user", "t", "v", 1L, -3); /* add_key */
    printf("add_key=%s\n", res(r));
    errno = 0;
    r = syscall(218, "user", "t", (void *)0, -3); /* request_key */
    printf("request_key=%s\n", res(r));
    return 0;
}
