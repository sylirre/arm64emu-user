/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
/* execveat (nr 281): error paths first, then a chained self-exec --
 * AT_EMPTY_PATH by fd (stage2), then a plain path (stage3). The exec chain
 * runs only when statically linked: a successful exec of a *dynamic* guest
 * under qemu -L re-enters through binfmt without the -L prefix and can't
 * find the loader (and the dyn harness spoofs argv[0], our self-path). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/auxv.h>
#include <sys/syscall.h>

static long xat(int fd, const char *p, char **av, char **ev, int fl) {
    return syscall(SYS_execveat, fd, p, av, ev, fl);
}

int main(int argc, char **argv) {
    /* Unbuffered: buffered output would be discarded by a successful exec. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "stage2")) {
        printf("stage2 env=%s\n", getenv("EXEV") ? getenv("EXEV") : "-");
        char *av[] = { argv[0], "stage3", 0 };
        char *ev[] = { "EXEV=99", 0 };
        long r = xat(AT_FDCWD, argv[0], av, ev, 0);
        printf("stage2 exec rc=%ld err=%d\n", r, errno);   /* not reached */
        return 1;
    }
    if (argc > 1 && !strcmp(argv[1], "stage3")) {
        printf("stage3 env=%s\n", getenv("EXEV") ? getenv("EXEV") : "-");
        return 0;
    }

    char *av[] = { argv[0], "stage2", 0 };
    char *ev[] = { "EXEV=42", 0 };

    errno = 0;
    long r = xat(AT_FDCWD, argv[0], av, ev, 0x2 /*bogus flag*/);
    printf("badflag rc=%ld err=%d\n", r, errno);
    errno = 0;
    r = xat(AT_FDCWD, "", av, ev, 0);
    printf("emptypath rc=%ld err=%d\n", r, errno);
    errno = 0;
    r = xat(1234, "somefile", av, ev, 0);
    printf("badfd rc=%ld err=%d\n", r, errno);

    /* A final symlink is refused under AT_SYMLINK_NOFOLLOW (even a broken
     * one); without the flag it is followed and the bogus target is ENOENT. */
    unlink("/tmp/arm64emu_exat_link");
    if (symlink("arm64emu_exat_nx", "/tmp/arm64emu_exat_link") != 0) return 9;
    errno = 0;
    r = xat(AT_FDCWD, "/tmp/arm64emu_exat_link", av, ev, AT_SYMLINK_NOFOLLOW);
    printf("link_nofollow rc=%ld err=%d\n", r, errno);
    errno = 0;
    r = xat(AT_FDCWD, "/tmp/arm64emu_exat_link", av, ev, 0);
    printf("link_follow rc=%ld err=%d\n", r, errno);
    unlink("/tmp/arm64emu_exat_link");

    if (getauxval(AT_BASE) != 0) {   /* dynamically linked: see header */
        printf("dyn: skip exec chain\n");
        return 0;
    }

    /* Success: exec self by fd (fexecve style). */
    int fd = open(argv[0], O_RDONLY);
    printf("selffd=%d\n", fd >= 3);
    r = xat(fd, "", av, ev, AT_EMPTY_PATH);
    printf("unreached rc=%ld err=%d\n", r, errno);
    return 1;
}
