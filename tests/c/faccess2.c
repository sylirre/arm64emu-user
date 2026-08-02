/* faccessat2 flag handling. AT_EACCESS must be honored, not handed to the
 * host libc: Bionic's faccessat wrapper rejects ANY flags with EINVAL, and
 * dash's `test -r` uses AT_EACCESS -- through apt-key that turned into every
 * Debian InRelease signature failing NO_PUBKEY, because the unreadable-seeming
 * archive keyring was silently replaced with /dev/null. An unknown flag must
 * still be EINVAL, exactly as the kernel answers. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static long acc2(const char *path, int mode, int flags) {
    long r = syscall(439 /* faccessat2 */, AT_FDCWD, path, mode, flags);
    return r < 0 ? -errno : r;
}

int main(int argc, char **argv) {
    (void)argc;
    /* argv[0] is a file that exists, is readable, and is executable. */
    printf("r_eaccess=%ld\n", acc2(argv[0], R_OK, 0x200 /* AT_EACCESS */));
    printf("x_eaccess=%ld\n", acc2(argv[0], X_OK, 0x200));
    printf("r_plain=%ld\n", acc2(argv[0], R_OK, 0));
    printf("r_nofollow=%ld\n", acc2(argv[0], R_OK, 0x100 /* AT_SYMLINK_NOFOLLOW */));
    /* An unknown flag is EINVAL on a kernel (and on the emulator) -- but old
     * qemu-user implements faccessat2 as host faccessat WITHOUT validating
     * flags and answers 0, so an exact value cannot be diffed against every
     * oracle. Assert the relationship instead: anything but those two
     * answers (a stray errno, a crash) still fails on both sides. */
    long bf = acc2(argv[0], R_OK, 0x4000);
    printf("badflag_ok=%d\n", bf == 0 || bf == -EINVAL);
    printf("missing=%ld\n", acc2("/nonexistent-faccess2-probe", R_OK, 0x200));
    return 0;
}
