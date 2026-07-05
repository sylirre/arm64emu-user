/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* AArch64 Linux guest ABI: syscall numbers (asm-generic), auxv tags, and the
 * guest-side struct layouts the syscall layer marshals to/from. Guest structs
 * are spelled out with fixed-width types (LP64 arm64 layout) so the same
 * conversion code is correct on ILP32 hosts. */
#ifndef A64_GUEST_ABI_H
#define A64_GUEST_ABI_H

#include "types.h"

/* ---- syscall numbers (arch/arm64 uses asm-generic/unistd.h) ---- */
#define G_NR_getcwd            17
#define G_NR_eventfd2          19
#define G_NR_epoll_create1     20
#define G_NR_epoll_ctl         21
#define G_NR_epoll_pwait       22
#define G_NR_dup               23
#define G_NR_dup3              24
#define G_NR_fcntl             25
#define G_NR_inotify_init1     26
#define G_NR_ioctl             29
#define G_NR_mkdirat           34
#define G_NR_unlinkat          35
#define G_NR_symlinkat         36
#define G_NR_linkat            37
#define G_NR_renameat          38
#define G_NR_umount2           39
#define G_NR_mount             40
#define G_NR_statfs            43
#define G_NR_fstatfs           44
#define G_NR_truncate          45
#define G_NR_ftruncate         46
#define G_NR_fallocate         47
#define G_NR_faccessat         48
#define G_NR_chdir             49
#define G_NR_fchdir            50
#define G_NR_chroot            51
#define G_NR_fchmod            52
#define G_NR_fchmodat          53
#define G_NR_fchownat          54
#define G_NR_fchown            55
#define G_NR_openat            56
#define G_NR_close             57
#define G_NR_vhangup           58
#define G_NR_pipe2             59
#define G_NR_quotactl          60
#define G_NR_getdents64        61
#define G_NR_lseek             62
#define G_NR_read              63
#define G_NR_write             64
#define G_NR_readv             65
#define G_NR_writev            66
#define G_NR_pread64           67
#define G_NR_pwrite64          68
#define G_NR_preadv            69
#define G_NR_pwritev           70
#define G_NR_sendfile          71
#define G_NR_pselect6          72
#define G_NR_ppoll             73
#define G_NR_signalfd4         74
#define G_NR_vmsplice          75
#define G_NR_splice            76
#define G_NR_tee               77
#define G_NR_readlinkat        78
#define G_NR_newfstatat        79
#define G_NR_fstat             80
#define G_NR_sync              81
#define G_NR_fsync             82
#define G_NR_fdatasync         83
#define G_NR_sync_file_range   84
#define G_NR_timerfd_create    85
#define G_NR_timerfd_settime   86
#define G_NR_timerfd_gettime   87
#define G_NR_utimensat         88
#define G_NR_acct              89
#define G_NR_capget            90
#define G_NR_capset            91
#define G_NR_personality       92
#define G_NR_exit              93
#define G_NR_exit_group        94
#define G_NR_waitid            95
#define G_NR_set_tid_address   96
#define G_NR_unshare           97
#define G_NR_futex             98
#define G_NR_set_robust_list   99
#define G_NR_get_robust_list   100
#define G_NR_nanosleep         101
#define G_NR_getitimer         102
#define G_NR_setitimer         103
#define G_NR_kexec_load        104
#define G_NR_init_module       105
#define G_NR_delete_module     106
#define G_NR_timer_create      107
#define G_NR_timer_gettime     108
#define G_NR_timer_getoverrun  109
#define G_NR_timer_settime     110
#define G_NR_timer_delete      111
#define G_NR_clock_settime     112
#define G_NR_clock_gettime     113
#define G_NR_clock_getres      114
#define G_NR_clock_nanosleep   115
#define G_NR_syslog            116
#define G_NR_ptrace            117
#define G_NR_sched_setparam    118
#define G_NR_sched_setscheduler 119
#define G_NR_sched_getscheduler 120
#define G_NR_sched_getparam    121
#define G_NR_sched_setaffinity 122
#define G_NR_sched_getaffinity 123
#define G_NR_sched_yield       124
#define G_NR_sched_get_priority_max 125
#define G_NR_sched_get_priority_min 126
#define G_NR_sched_rr_get_interval  127
#define G_NR_restart_syscall   128
#define G_NR_kill              129
#define G_NR_tkill             130
#define G_NR_tgkill            131
#define G_NR_sigaltstack       132
#define G_NR_rt_sigsuspend     133
#define G_NR_rt_sigaction      134
#define G_NR_rt_sigprocmask    135
#define G_NR_rt_sigpending     136
#define G_NR_rt_sigtimedwait   137
#define G_NR_rt_sigqueueinfo   138
#define G_NR_rt_sigreturn      139
#define G_NR_setpriority       140
#define G_NR_getpriority       141
#define G_NR_reboot            142
#define G_NR_setregid          143
#define G_NR_setgid            144
#define G_NR_setreuid          145
#define G_NR_setuid            146
#define G_NR_setresuid         147
#define G_NR_getresuid         148
#define G_NR_setresgid         149
#define G_NR_getresgid         150
#define G_NR_setfsuid          151
#define G_NR_setfsgid          152
#define G_NR_times             153
#define G_NR_setpgid           154
#define G_NR_getpgid           155
#define G_NR_getsid            156
#define G_NR_setsid            157
#define G_NR_getgroups         158
#define G_NR_setgroups         159
#define G_NR_uname             160
#define G_NR_sethostname       161
#define G_NR_setdomainname     162
#define G_NR_getrlimit         163
#define G_NR_setrlimit         164
#define G_NR_getrusage         165
#define G_NR_umask             166
#define G_NR_prctl             167
#define G_NR_getcpu            168
#define G_NR_gettimeofday      169
#define G_NR_settimeofday      170
#define G_NR_adjtimex          171
#define G_NR_getpid            172
#define G_NR_getppid           173
#define G_NR_getuid            174
#define G_NR_geteuid           175
#define G_NR_getgid            176
#define G_NR_getegid           177
#define G_NR_gettid            178
#define G_NR_sysinfo           179
#define G_NR_mq_open           180
#define G_NR_msgget            186
#define G_NR_semget            190
#define G_NR_shmget            194
#define G_NR_shmat             196
#define G_NR_socket            198
#define G_NR_socketpair        199
#define G_NR_bind              200
#define G_NR_listen            201
#define G_NR_accept            202
#define G_NR_connect           203
#define G_NR_getsockname       204
#define G_NR_getpeername       205
#define G_NR_sendto            206
#define G_NR_recvfrom          207
#define G_NR_setsockopt        208
#define G_NR_getsockopt        209
#define G_NR_shutdown          210
#define G_NR_sendmsg           211
#define G_NR_recvmsg           212
#define G_NR_readahead         213
#define G_NR_brk               214
#define G_NR_munmap            215
#define G_NR_mremap            216
#define G_NR_add_key           217
#define G_NR_request_key       218
#define G_NR_keyctl            219
#define G_NR_clone             220
#define G_NR_execve            221
#define G_NR_mmap              222
#define G_NR_fadvise64         223
#define G_NR_swapon            224
#define G_NR_swapoff           225
#define G_NR_mprotect          226
#define G_NR_msync             227
#define G_NR_mlock             228
#define G_NR_munlock           229
#define G_NR_mlockall          230
#define G_NR_munlockall        231
#define G_NR_mincore           232
#define G_NR_madvise           233
#define G_NR_remap_file_pages  234
#define G_NR_mbind             235
#define G_NR_get_mempolicy     236
#define G_NR_set_mempolicy     237
#define G_NR_accept4           242
#define G_NR_recvmmsg          243
#define G_NR_wait4             260
#define G_NR_prlimit64         261
#define G_NR_fanotify_init    262
#define G_NR_name_to_handle_at 264
#define G_NR_clock_adjtime     266
#define G_NR_syncfs            267
#define G_NR_setns             268
#define G_NR_sendmmsg          269
#define G_NR_process_vm_readv  270
#define G_NR_process_vm_writev 271
#define G_NR_kcmp              272
#define G_NR_finit_module      273
#define G_NR_sched_setattr     274
#define G_NR_sched_getattr     275
#define G_NR_renameat2         276
#define G_NR_seccomp           277
#define G_NR_getrandom         278
#define G_NR_memfd_create      279
#define G_NR_bpf               280
#define G_NR_execveat          281
#define G_NR_userfaultfd       282
#define G_NR_membarrier        283
#define G_NR_mlock2            284
#define G_NR_copy_file_range   285
#define G_NR_preadv2           286
#define G_NR_pwritev2          287
#define G_NR_pkey_mprotect     288
#define G_NR_statx             291
#define G_NR_io_pgetevents     292
#define G_NR_rseq              293
#define G_NR_kexec_file_load   294
#define G_NR_pidfd_send_signal 424
#define G_NR_io_uring_setup    425
#define G_NR_io_uring_enter    426
#define G_NR_io_uring_register 427
#define G_NR_open_tree         428
#define G_NR_move_mount        429
#define G_NR_fsopen            430
#define G_NR_fsconfig          431
#define G_NR_fsmount           432
#define G_NR_fspick            433
#define G_NR_pidfd_open        434
#define G_NR_clone3            435
#define G_NR_close_range       436
#define G_NR_openat2           437
#define G_NR_pidfd_getfd       438
#define G_NR_faccessat2        439
#define G_NR_process_madvise   440
#define G_NR_epoll_pwait2      441
#define G_NR_mount_setattr     442
#define G_NR_landlock_create_ruleset 444
#define G_NR_memfd_secret      447
#define G_NR_process_mrelease  448
#define G_NR_futex_waitv       449
#define G_NR_set_mempolicy_home_node 450
#define G_NR_cachestat         451
#define G_NR_fchmodat2         452
#define G_NR_map_shadow_stack  453
#define G_NR_futex_wake        454
#define G_NR_futex_wait        455
#define G_NR_futex_requeue     456
#define G_NR_statmount         457
#define G_NR_listmount         458
#define G_NR_lsm_get_self_attr 459
#define G_NR_lsm_set_self_attr 460
#define G_NR_lsm_list_modules  461
#define G_NR_mseal             462

#define G_NR_MAX               512

/* ---- auxv tags ---- */
#define G_AT_NULL      0
#define G_AT_PHDR      3
#define G_AT_PHENT     4
#define G_AT_PHNUM     5
#define G_AT_PAGESZ    6
#define G_AT_BASE      7
#define G_AT_FLAGS     8
#define G_AT_ENTRY     9
#define G_AT_UID       11
#define G_AT_EUID      12
#define G_AT_GID       13
#define G_AT_EGID      14
#define G_AT_PLATFORM  15
#define G_AT_HWCAP     16
#define G_AT_CLKTCK    17
#define G_AT_SECURE    23
#define G_AT_RANDOM    25
#define G_AT_HWCAP2    26
#define G_AT_EXECFN    31
#define G_AT_MINSIGSTKSZ 51

/* ---- arm64 AT_HWCAP bits (implemented subset advertised) ---- */
#define G_HWCAP_FP      (1u << 0)
#define G_HWCAP_ASIMD   (1u << 1)
#define G_HWCAP_AES     (1u << 3)
#define G_HWCAP_PMULL   (1u << 4)
#define G_HWCAP_SHA1    (1u << 5)
#define G_HWCAP_SHA2    (1u << 6)
#define G_HWCAP_CRC32   (1u << 7)
#define G_HWCAP_ATOMICS (1u << 8)   /* advertised from M6 (LSE implemented) */
#define G_HWCAP_CPUID   (1u << 11)
#define G_HWCAP_SHA3    (1u << 17)
#define G_HWCAP_SHA512  (1u << 21)

/* ---- guest struct layouts (arm64 LP64) ---- */

/* Bionic <sys/stat.h> defines st_{a,m,c}time_nsec as macros (-> st_Xtim.tv_nsec),
 * and sys.h includes <sys/stat.h> before this header, so those macros would
 * corrupt the guest field names below. Host stat is only ever read via its raw
 * st_Xtim members (see sys_file.c), never these macros, so drop them. glibc does
 * not define them, so this is a no-op there. */
#undef st_atime_nsec
#undef st_mtime_nsec
#undef st_ctime_nsec

/* asm-generic struct stat for arm64 (128 bytes). */
typedef struct {
    u64 st_dev;
    u64 st_ino;
    u32 st_mode;
    u32 st_nlink;
    u32 st_uid;
    u32 st_gid;
    u64 st_rdev;
    u64 __pad1;
    s64 st_size;
    s32 st_blksize;
    s32 __pad2;
    s64 st_blocks;
    s64 st_atime_sec;
    s64 st_atime_nsec;
    s64 st_mtime_sec;
    s64 st_mtime_nsec;
    s64 st_ctime_sec;
    s64 st_ctime_nsec;
    u32 __unused4;
    u32 __unused5;
} GStat;

typedef struct { u64 iov_base; u64 iov_len; } GIovec;
typedef struct { s64 tv_sec; s64 tv_nsec; } GTimespec;
typedef struct { s64 tv_sec; s64 tv_usec; } GTimeval;
typedef struct { u64 rlim_cur; u64 rlim_max; } GRlimit;

/* struct new_utsname */
typedef struct {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
} GUtsname;

/* linux_dirent64 header (name follows) */
typedef struct {
    u64 d_ino;
    s64 d_off;
    u16 d_reclen;
    u8  d_type;
    /* char d_name[]; */
} GDirent64;

/* struct sigaction (arm64 kernel layout: handler, flags, restorer, mask) */
typedef struct {
    u64 handler;
    u64 flags;
    u64 restorer;
    u64 mask;
} GSigactionK;

/* Guest fcntl/open flag values: arm64 uses asm-generic values, which are the
 * same as x86/arm32 for the flags we pass through (O_CREAT 0100, O_EXCL 0200,
 * O_TRUNC 01000, O_APPEND 02000, O_NONBLOCK 04000, O_CLOEXEC 02000000...).
 * O_DIRECTORY/O_NOFOLLOW/O_DIRECT/O_LARGEFILE differ per-arch and are
 * translated explicitly in the file-syscall layer. */
#define G_O_DIRECTORY  040000
#define G_O_NOFOLLOW  0100000
#define G_O_DIRECT     0200000
#define G_O_LARGEFILE 0400000

#define G_AT_FDCWD             (-100)
#define G_AT_SYMLINK_NOFOLLOW  0x100
#define G_AT_REMOVEDIR         0x200
#define G_AT_SYMLINK_FOLLOW    0x400
#define G_AT_EMPTY_PATH        0x1000

#endif /* A64_GUEST_ABI_H */
