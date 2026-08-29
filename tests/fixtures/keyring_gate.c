/* The key-management family is absent unless --host-keyring asks for it.
 *
 * The host keyring is not scoped to a rootfs and cannot be made so from inside
 * the emulator -- a fresh session keyring could be joined, but the user and
 * user-session keyrings are per-uid whatever we do, and an absolute serial
 * names a key directly -- so a guest with the passthrough reads, adds to and
 * revokes the invoking user's own keys. Off by default; the option is for a
 * caller that wants it.
 *
 * Self-checking: the qemu oracle forwards all three to the host keyring, which
 * is the behaviour being removed. Nothing here creates a key that outlives the
 * call: two of the three only look things up, and the add_key names a key TYPE
 * the kernel does not have, which it refuses before allocating anything.
 *
 * Every probe has to be one the HOST answers, or the row stops describing the
 * gate. The add_key probe was an over-cap payload length at first, and the
 * emulator bounds that length itself -- so on a host where the family is
 * trapped or missing (the Android seccomp tier, or under qemu-arm) that row
 * said "present" from the emulator's own EINVAL while the other two said
 * ENOSYS, and the pair matched neither tier. An unknown key type reaches the
 * kernel and comes back ENODEV. */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#define PROCESS_KEYRING (-2)

/* Only the one distinction matters, and spelling it this way keeps the answer
 * off whatever the host's keyring happens to hold: the family is either absent
 * or it reached the kernel. */
static const char *res(long r) {
    return (r < 0 && errno == ENOSYS) ? "ENOSYS" : "present";
}

int main(void) {
    errno = 0;   /* KEYCTL_GET_KEYRING_ID, no create: ok or ENOKEY */
    printf("keyctl=%s\n", res(syscall(SYS_keyctl, 0L, (long)PROCESS_KEYRING, 0L)));
    errno = 0;   /* a key type the kernel has not got: ENODEV, no key made */
    printf("add_key=%s\n", res(syscall(SYS_add_key, "a64-no-such-type",
                                       "a64-gate-probe", (void *)0, 0L,
                                       (long)PROCESS_KEYRING)));
    errno = 0;   /* a description nothing holds: ENOKEY */
    printf("request_key=%s\n", res(syscall(SYS_request_key, "user",
                                           "a64-gate-probe-absent", (void *)0,
                                           (long)PROCESS_KEYRING)));
    printf("done\n");
    return 0;
}
