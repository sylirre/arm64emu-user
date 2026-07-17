/* /proc/self/auxv must agree with the auxv the process was actually started
 * with (getauxval reads the initial-stack copy). Without synthesis the host
 * passthrough file shows the EMULATOR's auxv — the wrong ISA's AT_HWCAP,
 * which on an AArch64 host advertises pauth/SVE the emulator doesn't have
 * and sends gdb chasing regsets the ptrace shim EINVALs. qemu-user
 * synthesizes /proc/self/auxv too, so this is differential-safe; only
 * consistency booleans are printed (the raw values legitimately differ
 * between the two guests). */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/auxv.h>

int main(void) {
    int fd = open("/proc/self/auxv", O_RDONLY);
    if (fd < 0) { printf("open failed\n"); return 1; }
    unsigned long long pair[2], hwcap = 0, pagesz = 0, uid = -1ULL, entry = 0;
    int n = 0;
    while (read(fd, pair, 16) == 16 && pair[0] != 0) {
        if (pair[0] == 16) hwcap = pair[1];   /* AT_HWCAP */
        if (pair[0] == 6)  pagesz = pair[1];  /* AT_PAGESZ */
        if (pair[0] == 11) uid = pair[1];     /* AT_UID */
        if (pair[0] == 9)  entry = pair[1];   /* AT_ENTRY */
        n++;
    }
    close(fd);
    printf("entries>10: %d\n", n > 10);
    printf("hwcap match: %d\n", hwcap == getauxval(AT_HWCAP) && hwcap != 0);
    printf("pagesz match: %d\n", pagesz == getauxval(AT_PAGESZ));
    printf("uid match: %d\n", uid == (unsigned long long)getuid());
    printf("entry match: %d\n", entry == getauxval(AT_ENTRY) && entry != 0);
    return 0;
}
