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
#define G_NR_setxattr          5
#define G_NR_lsetxattr         6
#define G_NR_fsetxattr         7
#define G_NR_getxattr          8
#define G_NR_lgetxattr         9
#define G_NR_fgetxattr         10
#define G_NR_listxattr         11
#define G_NR_llistxattr        12
#define G_NR_flistxattr        13
#define G_NR_removexattr       14
#define G_NR_lremovexattr      15
#define G_NR_fremovexattr      16
#define G_NR_getcwd            17
#define G_NR_eventfd2          19
#define G_NR_epoll_create1     20
#define G_NR_epoll_ctl         21
#define G_NR_epoll_pwait       22
#define G_NR_dup               23
#define G_NR_dup3              24
#define G_NR_fcntl             25
#define G_NR_inotify_init1     26
#define G_NR_inotify_add_watch 27
#define G_NR_inotify_rm_watch  28
#define G_NR_ioctl             29
#define G_NR_mknodat           33
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
#define G_NR_msgctl            187
#define G_NR_msgrcv            188
#define G_NR_msgsnd            189
#define G_NR_semget            190
#define G_NR_semctl            191
#define G_NR_semtimedop        192
#define G_NR_semop             193
#define G_NR_shmget            194
#define G_NR_shmctl            195
#define G_NR_shmat             196
#define G_NR_shmdt             197
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
#define G_HWCAP_FPHP    (1u << 9)   /* FEAT_FP16: scalar half-precision arithmetic */
#define G_HWCAP_ASIMDHP (1u << 10)  /* FEAT_FP16: SIMD half-precision arithmetic */
#define G_HWCAP_CPUID   (1u << 11)
#define G_HWCAP_ASIMDRDM (1u << 12) /* FEAT_RDM: SQRDMLAH/SQRDMLSH */
#define G_HWCAP_JSCVT   (1u << 13)  /* FEAT_JSCVT: FJCVTZS */
#define G_HWCAP_FCMA    (1u << 14)  /* FEAT_FCMA: FCMLA/FCADD */
#define G_HWCAP_LRCPC   (1u << 15)  /* FEAT_LRCPC: LDAPR */
#define G_HWCAP_SHA3    (1u << 17)
#define G_HWCAP_ASIMDDP (1u << 20)  /* FEAT_DotProd: SDOT/UDOT */
#define G_HWCAP_SHA512  (1u << 21)
#define G_HWCAP_ASIMDFHM (1u << 23) /* FEAT_FHM: FMLAL/FMLSL */
#define G_HWCAP_ILRCPC  (1u << 26)  /* FEAT_LRCPC2: LDAPUR/STLUR */
#define G_HWCAP_FLAGM   (1u << 27)  /* FEAT_FLAGM: CFINV/RMIF/SETF8/16 */
#define G_HWCAP2_FLAGM2 (1u << 7)   /* FEAT_FLAGM2: AXFLAG/XAFLAG */
#define G_HWCAP2_MOPS   (1ULL << 43) /* FEAT_MOPS: CPYx/CPYFx/SETx */

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

/* struct epoll_event. On arm64 (and every arch except x86) it is unpacked, so
 * the u64 data is 8-aligned: events@0, 4 bytes padding, data@8, size 16. The
 * host struct is packed only on x86 (data@4, size 12), hence the marshalling in
 * the epoll handlers rather than a raw copy. */
typedef struct { u32 events; u32 __pad; u64 data; } GEpollEvent;

typedef struct { s64 tv_sec; s64 tv_nsec; } GTimespec;
typedef struct { s64 tv_sec; s64 tv_usec; } GTimeval;
typedef struct { u64 rlim_cur; u64 rlim_max; } GRlimit;

/* struct sigevent (LP64, 64 bytes total = SIGEV_MAX_SIZE): the sigval union,
 * signo, notify, then the notify union whose first word is the target tid for
 * SIGEV_THREAD_ID (the SIGEV_THREAD function/attribute pointers never reach
 * the syscall level -- guest libc implements that flavor in userspace). */
typedef struct {
    u64 sigev_value;          /* union sigval, 8 bytes on LP64 */
    s32 sigev_signo;
    s32 sigev_notify;
    s32 sigev_tid;            /* first word of the notify union */
    u8  pad[44];
} GSigevent;

/* sigev_notify values (shared kernel constants). */
#define G_SIGEV_SIGNAL    0
#define G_SIGEV_NONE      1
#define G_SIGEV_THREAD_ID 4

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

/* mount(2) flags (arch-uniform) and umount2(2) flags, for the bind-mount
 * emulation in sys_file.c. MS_MGC_VAL is the legacy magic some tools still OR
 * into the high 16 bits; modern kernels ignore it when MS_MGC_MSK matches. */
#define G_MS_RDONLY      0x0001
#define G_MS_NOSUID      0x0002
#define G_MS_NODEV       0x0004
#define G_MS_NOEXEC      0x0008
#define G_MS_REMOUNT     0x0020
#define G_MS_BIND        0x1000
#define G_MS_MOVE        0x2000
#define G_MS_REC         0x4000
#define G_MS_UNBINDABLE  0x20000    /* (1<<17) */
#define G_MS_PRIVATE     0x40000    /* (1<<18) */
#define G_MS_SLAVE       0x80000    /* (1<<19) */
#define G_MS_SHARED      0x100000   /* (1<<20) */
#define G_MS_MGC_VAL     0xC0ED0000
#define G_MS_MGC_MSK     0xFFFF0000

#define G_MNT_FORCE       0x1
#define G_MNT_DETACH      0x2
#define G_MNT_EXPIRE      0x4
#define G_UMOUNT_NOFOLLOW 0x8

/* ---- ptrace(2) ABI (sys_ptrace.c / ptracetab.c) ---- */

/* Requests. arm64 has no legacy PTRACE_GETREGS/GETFPREGS: the register file is
 * read/written only through GETREGSET/SETREGSET with an NT_* note type. */
#define G_PTRACE_TRACEME       0
#define G_PTRACE_PEEKTEXT      1
#define G_PTRACE_PEEKDATA      2
#define G_PTRACE_PEEKUSR       3
#define G_PTRACE_POKETEXT      4
#define G_PTRACE_POKEDATA      5
#define G_PTRACE_POKEUSR       6
#define G_PTRACE_CONT          7
#define G_PTRACE_KILL          8
#define G_PTRACE_SINGLESTEP    9
#define G_PTRACE_ATTACH        16
#define G_PTRACE_DETACH        17
#define G_PTRACE_SYSCALL       24
#define G_PTRACE_SETOPTIONS    0x4200
#define G_PTRACE_GETEVENTMSG   0x4201
#define G_PTRACE_GETSIGINFO    0x4202
#define G_PTRACE_SETSIGINFO    0x4203
#define G_PTRACE_GETREGSET     0x4204
#define G_PTRACE_SETREGSET     0x4205
#define G_PTRACE_SEIZE         0x4206
#define G_PTRACE_INTERRUPT     0x4207
#define G_PTRACE_LISTEN        0x4208

/* SETOPTIONS bits. */
#define G_PTRACE_O_TRACESYSGOOD   0x00000001
#define G_PTRACE_O_TRACEFORK      0x00000002
#define G_PTRACE_O_TRACEVFORK     0x00000004
#define G_PTRACE_O_TRACECLONE     0x00000008
#define G_PTRACE_O_TRACEEXEC      0x00000010
#define G_PTRACE_O_TRACEVFORKDONE 0x00000020
#define G_PTRACE_O_TRACEEXIT      0x00000040
#define G_PTRACE_O_EXITKILL       0x00000100
#define G_PTRACE_O_MASK           0x000003ff

/* Event codes reported in status bits [15:8] of a WIFSTOPPED status. */
#define G_PTRACE_EVENT_FORK        1
#define G_PTRACE_EVENT_VFORK       2
#define G_PTRACE_EVENT_CLONE       3
#define G_PTRACE_EVENT_EXEC        4
#define G_PTRACE_EVENT_VFORK_DONE  5
#define G_PTRACE_EVENT_EXIT        6
#define G_PTRACE_EVENT_STOP        128

/* regset note types (linux/elf.h). */
#define G_NT_PRSTATUS        1
#define G_NT_PRFPREG         2
#define G_NT_ARM_TLS         0x401
#define G_NT_ARM_SYSTEM_CALL 0x404

/* NT_PRSTATUS payload for arm64: struct user_pt_regs (34 * 8 = 272 bytes). */
typedef struct {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
} GUserRegs;

/* NT_PRFPREG payload for arm64: struct user_fpsimd_state (528 bytes). */
typedef struct {
    V128 vregs[32];
    u32  fpsr;
    u32  fpcr;
    u32  __reserved[2];
} GUserFpsimd;

/* ---- System V IPC (shared memory) ---- */

/* shmget() shmflg: the low 9 bits are the permission mode; these are the
 * control flags above them (asm-generic == every arch). */
#define G_IPC_CREAT   01000     /* create if key nonexistent */
#define G_IPC_EXCL    02000     /* fail if key exists */
#define G_IPC_NOWAIT  04000     /* return error on wait */
#define G_IPC_PRIVATE 0         /* private key: always a fresh segment */

/* shmctl() cmd. IPC_RMID/SET/STAT are the generic ops; SHM_* are shm-specific. */
#define G_IPC_RMID    0
#define G_IPC_SET     1
#define G_IPC_STAT    2
#define G_IPC_INFO    3
#define G_SHM_LOCK    11
#define G_SHM_UNLOCK  12
#define G_SHM_STAT    13
#define G_SHM_INFO    14
#define G_SHM_STAT_ANY 15

/* shmat() shmflg. */
#define G_SHM_RDONLY  010000    /* attach read-only */
#define G_SHM_RND     020000    /* round attach address down to SHMLBA */
#define G_SHM_REMAP   040000    /* take over an existing mapping at the address */
#define G_SHM_EXEC    0100000   /* execute permission on the segment */

/* SHMLBA (attach-address low-boundary): one guest page here. */
#define G_SHMLBA      4096

/* asm-generic struct ipc64_perm (48 bytes). Fixed-width fields with explicit
 * padding place every 8-byte member at an 8-aligned offset, so the layout is
 * identical whether the host aligns u64 to 4 (i386) or 8 (arm64) — see GStat. */
typedef struct {
    s32 key;
    u32 uid, gid, cuid, cgid;
    u32 mode;
    u16 seq;
    u16 __pad2;
    u32 __pad3;               /* aligns __unused1 to offset 32 */
    u64 __unused1, __unused2;
} GIpc64Perm;

/* asm-generic struct shmid64_ds for arm64 (LP64: shm_[adc]time are 8 bytes). */
typedef struct {
    GIpc64Perm shm_perm;      /* @0  operation permission struct */
    u64 shm_segsz;            /* @48 size of segment in bytes */
    s64 shm_atime;            /* @56 last attach time */
    s64 shm_dtime;            /* @64 last detach time */
    s64 shm_ctime;            /* @72 last change time */
    s32 shm_cpid;             /* @80 pid of creator */
    s32 shm_lpid;             /* @84 pid of last shmat/shmdt */
    u64 shm_nattch;           /* @88 number of current attaches */
    u64 __unused4, __unused5; /* @96 */
} GShmid64Ds;                 /* 112 bytes */

/* struct shm_info (SHM_INFO output), asm-generic LP64 (48 bytes). */
typedef struct {
    s32 used_ids;
    s32 __pad;                /* aligns shm_tot to offset 8 */
    u64 shm_tot;              /* total allocated shm pages */
    u64 shm_rss;              /* resident pages (approximated as shm_tot here) */
    u64 shm_swp;              /* swapped pages (0) */
    u64 swap_attempts;        /* deprecated (0) */
    u64 swap_successes;       /* deprecated (0) */
} GShmInfo;

/* struct shminfo64 (IPC_INFO output), asm-generic LP64 (72 bytes). */
typedef struct {
    u64 shmmax, shmmin, shmmni, shmseg, shmall;
    u64 __unused1, __unused2, __unused3, __unused4;
} GShmInfo64;

/* ---- System V IPC (semaphores) ---- */

/* semctl() cmd (semaphore-specific ops; IPC_RMID/SET/STAT/INFO above). */
#define G_GETPID      11        /* sempid of last modifier */
#define G_GETVAL      12
#define G_GETALL      13
#define G_GETNCNT     14        /* # waiters for the value to increase */
#define G_GETZCNT     15        /* # waiters for the value to become zero */
#define G_SETVAL      16
#define G_SETALL      17
#define G_SEM_STAT    18        /* by kernel-array index (ipcs) */
#define G_SEM_INFO    19
#define G_SEM_STAT_ANY 20

/* semop() sem_flg (IPC_NOWAIT above). */
#define G_SEM_UNDO    0x1000    /* roll the op back when the process exits */

/* Enforced limits, reported via IPC_INFO/SEM_INFO. SEMVMX/SEMAEM are the
 * kernel's hard ABI bounds; the others are this implementation's caps (the
 * broker allocates per-set state dynamically, so SEMMSL costs nothing when
 * unused). */
#define G_SEMVMX      32767     /* max semaphore value */
#define G_SEMAEM      32767     /* max |semadj| (undo adjustment) */
#define G_SEMMSL      32000     /* max semaphores per set (kernel default) */
#define G_SEMMNI      1024      /* max sets (SEM_SET_MAX in the broker) */
#define G_SEMOPM      500       /* max sops per semop (kernel default) */

/* struct sembuf (asm-generic, 6 bytes, naturally packed: three 2-byte fields). */
typedef struct {
    u16 sem_num;
    s16 sem_op;
    s16 sem_flg;
} GSembuf;

/* asm-generic struct semid64_ds for arm64 (LP64). */
typedef struct {
    GIpc64Perm sem_perm;      /* @0  operation permission struct */
    s64 sem_otime;            /* @48 last semop time */
    s64 sem_ctime;            /* @56 last change time */
    u64 sem_nsems;            /* @64 number of semaphores in the set */
    u64 __unused3, __unused4; /* @72 */
} GSemid64Ds;                 /* 88 bytes */

/* struct seminfo (IPC_INFO/SEM_INFO output), ten native ints (40 bytes).
 * SEM_INFO repurposes semusz = # of existing sets, semaem = # of existing
 * semaphores over all sets. */
typedef struct {
    s32 semmap, semmni, semmns, semmnu, semmsl, semopm;
    s32 semume, semusz, semvmx, semaem;
} GSemInfo;

/* ---- System V IPC (message queues) ---- */

/* msgctl() cmd (queue-specific ops; IPC_RMID/SET/STAT/INFO above). */
#define G_MSG_STAT    11        /* by kernel-array index (ipcs) */
#define G_MSG_INFO    12
#define G_MSG_STAT_ANY 13

/* msgsnd()/msgrcv() msgflg (IPC_NOWAIT above). */
#define G_MSG_NOERROR 010000    /* truncate an oversized message silently */
#define G_MSG_EXCEPT  020000    /* msgtyp > 0: receive any type != msgtyp */
#define G_MSG_COPY    040000    /* checkpoint/restore peek: not supported */

/* Enforced limits (the kernel defaults), reported via IPC_INFO/MSG_INFO. */
#define G_MSGMAX      8192      /* max bytes per message */
#define G_MSGMNB      16384     /* default max bytes per queue (msg_qbytes) */
#define G_MSGMNI      1024      /* max queues (MSG_QUEUE_MAX in the broker) */

/* asm-generic struct msqid64_ds for arm64 (LP64). */
typedef struct {
    GIpc64Perm msg_perm;      /* @0   operation permission struct */
    s64 msg_stime;            /* @48  last msgsnd time */
    s64 msg_rtime;            /* @56  last msgrcv time */
    s64 msg_ctime;            /* @64  last change time */
    u64 msg_cbytes;           /* @72  bytes currently on the queue */
    u64 msg_qnum;             /* @80  messages currently on the queue */
    u64 msg_qbytes;           /* @88  max bytes allowed on the queue */
    s32 msg_lspid;            /* @96  pid of last msgsnd */
    s32 msg_lrpid;            /* @100 pid of last msgrcv */
    u64 __unused4, __unused5; /* @104 */
} GMsqid64Ds;                 /* 120 bytes */

/* struct msginfo (IPC_INFO/MSG_INFO output), 7 ints + a short (32 bytes with
 * tail padding, which the kernel zeroes — so an explicit pad field here).
 * MSG_INFO repurposes msgpool = # of existing queues, msgmap = # of messages
 * over all queues, msgtql = bytes over all queues. */
typedef struct {
    s32 msgpool, msgmap, msgmax, msgmnb, msgmni, msgssz, msgtql;
    u16 msgseg;
    u16 __pad;
} GMsgInfo;

#endif /* A64_GUEST_ABI_H */
