/* set_robust_list/get_robust_list state round-trip. Self-checking: qemu-user
 * returns ENOSYS for the pair, so it cannot be a differential test.
 *
 * What the FIRST get sees is the C library's business, not the emulator's:
 * glibc registers a head of its own during startup, Bionic does not, so
 * asserting a nonzero head there only ever tested which libc built the guest
 * (and failed on Termux). The pristine get is still checked for rc and for the
 * architectural head length; that the emulator reports back exactly the head
 * the guest registered is what the set/get pair below proves — including that
 * it survives a rejected set, which is the interesting part. */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
    unsigned long head = 0, len = 0;
    long r = syscall(SYS_get_robust_list, 0, &head, &len);
    printf("get0 rc=%ld len=%lu\n", r, len);
    unsigned long head0 = head;
    r = syscall(SYS_set_robust_list, 0x12340UL, 16UL);
    printf("set_badlen rc=%ld err=%d\n", r, r < 0 ? errno : 0);
    /* the rejected set must not have disturbed the registered head */
    head = len = 0;
    syscall(SYS_get_robust_list, 0, &head, &len);
    printf("kept rc=0 same=%d\n", head == head0);
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
