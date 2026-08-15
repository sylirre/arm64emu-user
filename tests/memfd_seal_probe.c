/* Host-side probe: does this kernel allow a read-only MAP_SHARED of a
 * write-sealed memfd that was opened read-write?
 *
 * Kernels from 6.x on allow it, stripping VM_MAYWRITE; older ones refuse it
 * outright (measured on the 5.15 kernel of an Android 13 phone). The emulator's
 * unlinked-file memfd tier implements the former, which is the vintage it
 * advertises through sys_uname — but the oracle for that test row is the host's
 * own memfd_create, so on an older host the row compares two kernels rather
 * than two implementations. run_tests.sh runs this first and names the skip.
 *
 * Exit: 0 host allows (comparable), 1 host refuses, 2 cannot tell. Built with
 * the HOST compiler, like tests/seccomp_wrap.c — nothing here is guest code. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS  1033
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

int main(void) {
    long fd = syscall(SYS_memfd_create, "sealprobe", MFD_ALLOW_SEALING);
    if (fd < 0) return 2;                       /* no memfd here at all */
    if (ftruncate((int)fd, 4096) != 0) return 2;
    if (fcntl((int)fd, F_ADD_SEALS, F_SEAL_WRITE) != 0) return 2;
    void *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, (int)fd, 0);
    if (p == MAP_FAILED) return 1;
    munmap(p, 4096);
    return 0;
}
