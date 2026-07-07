/* seccomp_wrap — Android-seccomp mimic for the differential suite.
 *
 * Installs a SECCOMP_RET_TRAP filter (under PR_SET_NO_NEW_PRIVS, so it
 * survives the exec) for the host-arch numbers of the Android-8-blocked
 * syscalls the emulator's handlers could forward, then execs its argv.
 * Running the emulator through this proves its SIGSYS net converts a
 * trapped forward into -ENOSYS instead of the process being killed —
 * on an ordinary Linux CI box, no device needed.
 *
 * Deliberately NOT trapped: rseq, clone3, set_robust_list, membarrier.
 * glibc issues those during startup, before the emulator's main() arms the
 * net (a CI-only artifact: Bionic never issues them). They are guest-facing
 * quiet-ENOSYS entries in the dispatcher and are never forwarded anyway.
 * For the same reason the harness only wraps LP64 emulator builds: 32-bit
 * glibc with _TIME_BITS=64 statx()es inside ld.so, before main() runs.
 *
 * Usage: seccomp_wrap prog [args...]     exits 97 if seccomp is unavailable.
 */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__)
#define WRAP_ARCH AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define WRAP_ARCH AUDIT_ARCH_I386
#elif defined(__aarch64__)
#define WRAP_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define WRAP_ARCH AUDIT_ARCH_ARM
#else
#error "unknown host arch"
#endif

static const unsigned trapped[] = {
#ifdef __NR_statx
    __NR_statx,
#endif
#ifdef __NR_keyctl
    __NR_keyctl,
#endif
#ifdef __NR_add_key
    __NR_add_key,
#endif
#ifdef __NR_request_key
    __NR_request_key,
#endif
#ifdef __NR_msgget
    __NR_msgget, __NR_msgsnd, __NR_msgrcv, __NR_msgctl,
#endif
#ifdef __NR_semget
    __NR_semget, __NR_semctl,
#endif
#ifdef __NR_semop
    __NR_semop,
#endif
#ifdef __NR_semtimedop
    __NR_semtimedop,
#endif
#ifdef __NR_shmget
    __NR_shmget, __NR_shmat, __NR_shmdt, __NR_shmctl,
#endif
#ifdef __NR_mq_open
    __NR_mq_open, __NR_mq_unlink, __NR_mq_timedsend, __NR_mq_timedreceive,
    __NR_mq_notify, __NR_mq_getsetattr,
#endif
#ifdef __NR_name_to_handle_at
    __NR_name_to_handle_at,
#endif
#ifdef __NR_userfaultfd
    __NR_userfaultfd,
#endif
#ifdef __NR_fanotify_init
    __NR_fanotify_init, __NR_fanotify_mark,
#endif
};
#define NTRAP (sizeof trapped / sizeof trapped[0])

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s prog [args...]\n", argv[0]);
        return 2;
    }

    /* [0] load arch  [1] arch match? -> [3] : [2]
     * [2] RET ALLOW (foreign arch, e.g. a 32-bit child under a 64-bit wrap)
     * [3] load nr
     * [4+i] nr == trapped[i]? -> shared TRAP at [4+NTRAP+1] : fall through
     * [4+NTRAP] RET ALLOW    [4+NTRAP+1] RET TRAP */
    struct sock_filter prog[NTRAP + 6];
    unsigned n = 0;
    prog[n++] = (struct sock_filter){ BPF_LD | BPF_W | BPF_ABS, 0, 0,
                                      offsetof(struct seccomp_data, arch) };
    prog[n++] = (struct sock_filter){ BPF_JMP | BPF_JEQ | BPF_K, 1, 0,
                                      WRAP_ARCH };
    prog[n++] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0,
                                      SECCOMP_RET_ALLOW };
    prog[n++] = (struct sock_filter){ BPF_LD | BPF_W | BPF_ABS, 0, 0,
                                      offsetof(struct seccomp_data, nr) };
    for (unsigned i = 0; i < NTRAP; i++)
        prog[n++] = (struct sock_filter){ BPF_JMP | BPF_JEQ | BPF_K,
                                          (unsigned char)(NTRAP - i), 0,
                                          trapped[i] };
    prog[n++] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0,
                                      SECCOMP_RET_ALLOW };
    prog[n++] = (struct sock_filter){ BPF_RET | BPF_K, 0, 0,
                                      SECCOMP_RET_TRAP };
    struct sock_fprog fprog = { .len = (unsigned short)n, .filter = prog };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) != 0) {
        fprintf(stderr, "seccomp_wrap: seccomp unavailable: %s\n",
                strerror(errno));
        return 97;
    }
    execvp(argv[1], argv + 1);
    fprintf(stderr, "seccomp_wrap: exec %s: %s\n", argv[1], strerror(errno));
    return 126;
}
