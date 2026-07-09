/* seccomp_wrap — Android-seccomp mimic for the differential suite.
 *
 * Installs a SECCOMP_RET_TRAP filter (under PR_SET_NO_NEW_PRIVS, so it
 * survives the exec) for the host-arch numbers of the full Android-8 (Oreo)
 * blocked set — categories A (blacklisted), B (whitelist gaps) and C
 * (post-Oreo) of ANDROID_FORBIDDEN_SYSCALLS.md — then execs its argv.
 * `make test-seccomp` runs the ENTIRE differential suite with the emulator
 * under this filter: it proves no handler forwards a blocked syscall, and
 * that the SIGSYS net converts anything that still slips through into
 * -ENOSYS — on an ordinary Linux CI box, no device needed.
 *
 * Deliberately NOT trapped (each is either never forwarded by our handlers
 * or a host-libc difference that cannot occur on Bionic):
 *  - rseq, set_robust_list: host glibc issues them during its own startup,
 *    before the emulator's main() arms the net (CI-only artifact; guest-side
 *    they are quiet-ENOSYS/emulated, never forwarded).
 *  - clone3, membarrier: newer host glibc probes clone3 from fork/
 *    pthread_create inside the emulator's runtime; Bionic's wrappers use
 *    plain clone and never issue either. Guest-side: quiet-ENOSYS.
 *  - accept: glibc's accept() really issues SYS_accept, but Bionic's routes
 *    to the whitelisted accept4 — trapping it would kill a forward that is
 *    safe on every Android device.
 * For the startup reason the harness only wraps LP64 emulator builds: 32-bit
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
    /* -- Category A: explicitly blacklisted on Oreo -- */
#ifdef __NR_swapon
    __NR_swapon, __NR_swapoff,
#endif
    /* -- Category B: kernel-era syscalls absent from the Oreo whitelist -- */
#ifdef __NR_get_robust_list
    __NR_get_robust_list,   /* set_robust_list exempt: host-glibc startup */
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
#ifdef __NR_remap_file_pages
    __NR_remap_file_pages,
#endif
#ifdef __NR_mbind
    __NR_mbind, __NR_get_mempolicy, __NR_set_mempolicy,
#endif
#ifdef __NR_name_to_handle_at
    __NR_name_to_handle_at, __NR_open_by_handle_at,
#endif
#ifdef __NR_fanotify_init
    __NR_fanotify_init, __NR_fanotify_mark,
#endif
#ifdef __NR_userfaultfd
    __NR_userfaultfd,
#endif
#ifdef __NR_kcmp
    __NR_kcmp,
#endif
#ifdef __NR_bpf
    __NR_bpf,
#endif
#ifdef __NR_pkey_mprotect
    __NR_pkey_mprotect,
#endif
#ifdef __NR_io_setup
    __NR_io_setup, __NR_io_destroy, __NR_io_submit, __NR_io_cancel,
    __NR_io_getevents,
#endif
#ifdef __NR_io_pgetevents
    __NR_io_pgetevents,
#endif
#ifdef __NR_vhangup
    __NR_vhangup,
#endif
#ifdef __NR_kexec_load
    __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
    __NR_kexec_file_load,
#endif
#ifdef __NR_finit_module
    __NR_finit_module,
#endif
    /* -- Category C: post-Oreo numbers (SIGSYS instead of ENOSYS) -- */
#ifdef __NR_statx
    __NR_statx,
#endif
#ifdef __NR_faccessat2
    __NR_faccessat2,
#endif
#ifdef __NR_close_range
    __NR_close_range,
#endif
#ifdef __NR_openat2
    __NR_openat2,
#endif
#ifdef __NR_pidfd_send_signal
    __NR_pidfd_send_signal,
#endif
#ifdef __NR_pidfd_open
    __NR_pidfd_open,
#endif
#ifdef __NR_pidfd_getfd
    __NR_pidfd_getfd,
#endif
#ifdef __NR_io_uring_setup
    __NR_io_uring_setup, __NR_io_uring_enter, __NR_io_uring_register,
#endif
#ifdef __NR_open_tree
    __NR_open_tree, __NR_move_mount, __NR_fsopen, __NR_fsconfig,
    __NR_fsmount, __NR_fspick,
#endif
#ifdef __NR_mount_setattr
    __NR_mount_setattr,
#endif
#ifdef __NR_process_madvise
    __NR_process_madvise,
#endif
#ifdef __NR_epoll_pwait2
    __NR_epoll_pwait2,
#endif
#ifdef __NR_landlock_create_ruleset
    __NR_landlock_create_ruleset, __NR_landlock_add_rule,
    __NR_landlock_restrict_self,
#endif
#ifdef __NR_memfd_secret
    __NR_memfd_secret,
#endif
#ifdef __NR_process_mrelease
    __NR_process_mrelease,
#endif
#ifdef __NR_futex_waitv
    __NR_futex_waitv,
#endif
#ifdef __NR_set_mempolicy_home_node
    __NR_set_mempolicy_home_node,
#endif
#ifdef __NR_cachestat
    __NR_cachestat,
#endif
#ifdef __NR_fchmodat2
    __NR_fchmodat2,
#endif
#ifdef __NR_map_shadow_stack
    __NR_map_shadow_stack,
#endif
#ifdef __NR_futex_wake
    __NR_futex_wake, __NR_futex_wait, __NR_futex_requeue,
#endif
#ifdef __NR_statmount
    __NR_statmount, __NR_listmount,
#endif
#ifdef __NR_lsm_get_self_attr
    __NR_lsm_get_self_attr, __NR_lsm_set_self_attr, __NR_lsm_list_modules,
#endif
#ifdef __NR_mseal
    __NR_mseal,
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
