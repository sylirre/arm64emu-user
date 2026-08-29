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
 * call: the add_key payload length is over the kernel's 1 MB cap (EINVAL before
 * anything is allocated) and the other two only look things up. */
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
    errno = 0;   /* payload past the kernel's cap: EINVAL, no key made */
    printf("add_key=%s\n", res(syscall(SYS_add_key, "user", "a64-gate-probe",
                                       (void *)0, (long)(2u << 20),
                                       (long)PROCESS_KEYRING)));
    errno = 0;   /* a description nothing holds: ENOKEY */
    printf("request_key=%s\n", res(syscall(SYS_request_key, "user",
                                           "a64-gate-probe-absent", (void *)0,
                                           (long)PROCESS_KEYRING)));
    printf("done\n");
    return 0;
}
