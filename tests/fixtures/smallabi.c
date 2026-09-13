/* Small kernel-ABI facts a sweep found the emulator answering its own way,
 * each checked against a real kernel: uname's domainname ("(none)" where no
 * NIS domain was set, never empty); F_GETFL showing O_LARGEFILE, which a
 * 64-bit task gets on every open (force_o_largefile); getdents64 writing the
 * records that fit the MAPPED part of the buffer and stopping there (EFAULT
 * only when the first does not), the directory position left at the record
 * that did not fit; statx and fchownat refusing the flags words they refuse,
 * in the order they judge them (sigaltstack's own rows are in
 * altstackflags.c); the interface ioctls answered on a socket alone (ENOTTY
 * elsewhere, EFAULT for a pointer they cannot copy through); and a
 * classic-BPF seccomp filter shifting by X of 32 or more, which the kernel
 * masks to five bits. Self-checking: qemu-user hands getdents64 an EFAULT for
 * the partial buffer, drops O_LARGEFILE and has no seccomp; the expected block
 * is what this program prints built for the host and run on a real kernel
 * (O_LARGEFILE being the host arch's own bit there). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef AT_STATX_SYNC_TYPE
#define AT_STATX_SYNC_TYPE 0x6000
#endif
#ifdef __x86_64__
#define KERNEL_O_LARGEFILE 0100000   /* x86-64's bit, for the native run */
#else
#define KERNEL_O_LARGEFILE 0400000   /* asm-generic: arm64 */
#endif

static int E(long r) { return r < 0 ? errno : 0; }

int main(void) {
    struct utsname u; uname(&u);
    printf("domainname=[%s]\n", u.domainname);

    int fd = open("/dev/null", O_RDONLY);
    int fl = fcntl(fd, F_GETFL);
    printf("getfl_largefile=%d\n", (fl & KERNEL_O_LARGEFILE) != 0);
    close(fd);

    /* getdents64 into a buffer whose tail is unmapped: 32 bytes mapped before
     * the hole take one short record; the rest wait at the position. */
    fd = open("/", O_RDONLY | O_DIRECTORY);
    char *m = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(m + 4096, 4096);
    errno = 0; long r = syscall(SYS_getdents64, fd, m + 4096 - 32, 8192);
    printf("getdents_short: r=%s errno=%d\n", r < 0 ? "err" : (r > 0 && r <= 32 ? "one" : "many"), E(r));
    long pos = lseek(fd, 0, SEEK_CUR);
    errno = 0; r = syscall(SYS_getdents64, fd, m + 4096, 8192);
    printf("getdents_unmapped: r=%ld errno=%d pos_kept=%d\n", r, E(r), lseek(fd, 0, SEEK_CUR) == pos);
    errno = 0; r = syscall(SYS_getdents64, fd, m, 4096);
    printf("getdents_rest: r=%s errno=%d\n", r > 0 ? "some" : "none", E(r));
    close(fd);

    unsigned char sx[256];
    errno = 0; r = syscall(SYS_statx, AT_FDCWD, "/", 0x8000, 0x7ff, sx); printf("statx_badflag: %d\n", E(r));
    errno = 0; r = syscall(SYS_statx, AT_FDCWD, "/", AT_STATX_SYNC_TYPE, 0x7ff, sx); printf("statx_synctype_both: %d\n", E(r));
    errno = 0; r = syscall(SYS_statx, AT_FDCWD, "/", 0, 0x80000000u, sx); printf("statx_reserved_mask: %d\n", E(r));
    errno = 0; r = syscall(SYS_statx, AT_FDCWD, "/nonexistent", 0x8000, 0x7ff, sx); printf("statx_badflag_noent: %d\n", E(r));
    errno = 0; r = syscall(SYS_statx, AT_FDCWD, "/", 0, 0x7ff, sx); printf("statx_ok: %d\n", E(r));
    errno = 0; r = syscall(SYS_fchownat, AT_FDCWD, "/nonexistent", -1, -1, 0x8000); printf("fchownat_badflag: %d\n", E(r));
    errno = 0; r = syscall(SYS_fchownat, AT_FDCWD, "/", -1, -1, AT_SYMLINK_NOFOLLOW); printf("fchownat_ok: %d\n", E(r));

    struct ifreq ifr; memset(&ifr, 0, sizeof ifr); strcpy(ifr.ifr_name, "lo");
    int nf = open("/dev/null", O_RDONLY);
    errno = 0; r = ioctl(nf, SIOCGIFFLAGS, &ifr); printf("ifflags_devnull: %d\n", E(r));
    errno = 0; r = ioctl(nf, SIOCGIFCONF, (void *)0x10); printf("ifconf_devnull_fault: %d\n", E(r));
    errno = 0; r = ioctl(nf, SIOCGIFNAME, (void *)0); printf("ifname_devnull_null: %d\n", E(r));
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    errno = 0; r = ioctl(s, SIOCGIFFLAGS, &ifr); printf("ifflags_sock: r=%d errno=%d up=%d\n", (int)r, E(r), (ifr.ifr_flags & IFF_UP) != 0);
    errno = 0; r = ioctl(s, SIOCGIFFLAGS, (void *)0x10); printf("ifflags_fault: %d\n", E(r));
    errno = 0; r = ioctl(s, SIOCGIFFLAGS, (void *)0); printf("ifflags_null: %d\n", E(r));
    errno = 0; r = ioctl(s, SIOCGIFCONF, (void *)0x10); printf("ifconf_fault: %d\n", E(r));
    errno = 0; r = ioctl(s, SIOCGIFNAME, (void *)0x10); printf("ifname_fault: %d\n", E(r));
    errno = 0; r = ioctl(-1, SIOCGIFFLAGS, &ifr); printf("ifflags_badfd: %d\n", E(r));

    /* A seccomp filter shifting by X = 33: getppid is answered with the
     * errno the shift computes when the amount is masked to 1, and the
     * thread is killed if the shift ended the program. In a child. */
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        struct sock_filter f[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),                    /* nr */
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 4),
            BPF_STMT(BPF_LD | BPF_IMM, (SECCOMP_RET_ERRNO | 5) << 1),  /* EIO, doubled */
            BPF_STMT(BPF_LDX | BPF_IMM, 33),
            BPF_STMT(BPF_ALU | BPF_RSH | BPF_X, 0),                   /* >> (33 & 31) */
            BPF_STMT(BPF_RET | BPF_A, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = { sizeof f / sizeof f[0], f };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(2);
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) _exit(3);
        errno = 0;
        long g = syscall(SYS_getppid);
        _exit(g < 0 && errno == EIO ? 0 : 4);
    }
    int st; waitpid(k, &st, 0);
    printf("seccomp_shift_x: exited=%d code=%d\n", WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    printf("done\n");
    return 0;
}
