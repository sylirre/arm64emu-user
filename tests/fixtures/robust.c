/* set_robust_list/get_robust_list state round-trip. Self-checking: qemu-user
 * returns ENOSYS for the pair, so it cannot be a differential test. glibc
 * registers its own head at startup, so the first get sees a nonzero head. */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
    unsigned long head = 0, len = 0;
    long r = syscall(SYS_get_robust_list, 0, &head, &len);
    printf("get0 rc=%ld len=%lu head_set=%d\n", r, len, head != 0);
    r = syscall(SYS_set_robust_list, 0x12340UL, 16UL);
    printf("set_badlen rc=%ld err=%d\n", r, r < 0 ? errno : 0);
    r = syscall(SYS_set_robust_list, 0x12340UL, 24UL);
    printf("set rc=%ld\n", r);
    head = len = 0;
    r = syscall(SYS_get_robust_list, 0, &head, &len);
    printf("get rc=%ld head=%#lx len=%lu\n", r, head, len);
    errno = 0;
    r = syscall(SYS_get_robust_list, 0x7ffffff0, &head, &len);
    printf("get_nopid rc=%ld err=%d\n", r, errno);
    return 0;
}
