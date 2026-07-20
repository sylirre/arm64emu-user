/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* --strace-full argument decoder. A per-syscall argument-type table drives a
 * set of small formatters: symbolic flags (O_*, PROT_*, MAP_*, AT_*, MS_*,
 * signals, SEEK_*, AF_*, SOCK_*), quoted strings, execve argv/envp arrays,
 * errno-named returns, and {field=...} pretty-printing of the common structs
 * defined in guest_abi.h (stat, timespec, timeval, rlimit, utsname, sockaddr).
 * Arguments a syscall's descriptor does not cover fall back to hex, so coverage
 * grows one table row at a time without breaking anything.
 *
 * All flag/enum values below are the arm64 asm-generic ABI numbers (the guest
 * ABI), spelled as literals so the decoder is self-contained; struct layouts
 * and G_AT_FDCWD come from guest_abi.h. Guest memory is read with the bulk
 * copy_*_from_guest helpers, which never raise guest exceptions, so decoding
 * cannot perturb the traced program. */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "cpu.h"
#include "mmu.h"
#include "guest_abi.h"
#include "strace.h"

/* ---- argument type codes -------------------------------------------------- */
enum {
    AT_NONE = 0,   /* slot unused; also marks the end of a syscall's arg list */
    AT_INT,        /* signed decimal */
    AT_UINT,       /* unsigned decimal */
    AT_HEX,        /* 0x… (opaque value / undecoded pointer) */
    AT_PTR,        /* pointer: NULL or 0x… */
    AT_STR,        /* NUL-terminated string (captured pre-call) */
    AT_STRARRAY,   /* argv/envp: NULL-terminated array of strings (pre-call) */
    AT_STR_OUT,    /* NUL-terminated string the call writes (getcwd); on success */
    AT_BUF_IN,     /* input byte buffer, length = the next arg (write/send data) */
    AT_BUF_OUT,    /* output byte buffer, length = the return value (read/recv) */
    AT_FD,         /* file descriptor: signed decimal */
    AT_DIRFD,      /* dirfd: AT_FDCWD or signed decimal */
    AT_OFLAGS,     /* open()/openat() flags */
    AT_MODE,       /* mode_t: octal */
    AT_PROT,       /* mmap/mprotect protection */
    AT_MAPFLAGS,   /* mmap flags */
    AT_MSFLAGS,    /* mount(2) flags */
    AT_ATFLAGS,    /* AT_* (…at) flags */
    AT_UMOUNTFLAGS,/* umount2(2) flags */
    AT_SIG,        /* signal number → name */
    AT_WHENCE,     /* lseek whence */
    AT_SIGHOW,     /* rt_sigprocmask how */
    AT_SODOMAIN,   /* socket domain (AF_*) */
    AT_SOTYPE,     /* socket type (SOCK_* base + flag bits) */
    /* structs — the *_O variants are kernel outputs: on a failed call the buffer
     * was not written, so they print as a raw pointer instead of stale fields. */
    AT_STAT,       /* struct stat *   (output) */
    AT_UTSNAME,    /* struct utsname *(output) */
    AT_TIMESPEC,   /* struct timespec * (input) */
    AT_TIMESPEC_O, /* struct timespec * (output) */
    AT_TIMEVAL_O,  /* struct timeval *  (output) */
    AT_RLIMIT,     /* struct rlimit *   (input) */
    AT_RLIMIT_O,   /* struct rlimit *   (output) */
    AT_SOCKADDR,   /* struct sockaddr * (input) */
    AT_SOCKADDR_O, /* struct sockaddr * (output) */
};

/* ---- per-syscall descriptors ---------------------------------------------- */
/* t[i] is the type of argument i (a0..a5); AT_NONE ends the list. rt is the
 * return-value render: AT_INT (default, signed decimal + errno decode) or
 * AT_HEX (address-returning calls print success as 0x…). Syscalls absent here
 * print all six args as hex — the same readability as plain --strace. */
static const struct { u16 nr; u8 t[6]; u8 rt; } argdefs[] = {
    /* file & fd */
    { G_NR_openat,    { AT_DIRFD, AT_STR, AT_OFLAGS, AT_MODE }, 0 },
    { G_NR_close,     { AT_FD }, 0 },
    { G_NR_read,      { AT_FD, AT_BUF_OUT, AT_UINT }, 0 },
    { G_NR_write,     { AT_FD, AT_BUF_IN, AT_UINT }, 0 },
    { G_NR_pread64,   { AT_FD, AT_BUF_OUT, AT_UINT, AT_INT }, 0 },
    { G_NR_pwrite64,  { AT_FD, AT_BUF_IN, AT_UINT, AT_INT }, 0 },
    { G_NR_readv,     { AT_FD, AT_PTR, AT_INT }, 0 },
    { G_NR_writev,    { AT_FD, AT_PTR, AT_INT }, 0 },
    { G_NR_lseek,     { AT_FD, AT_INT, AT_WHENCE }, 0 },
    { G_NR_fstat,     { AT_FD, AT_STAT }, 0 },
    { G_NR_newfstatat,{ AT_DIRFD, AT_STR, AT_STAT, AT_ATFLAGS }, 0 },
    { G_NR_statx,     { AT_DIRFD, AT_STR, AT_ATFLAGS, AT_HEX, AT_PTR }, 0 },
    { G_NR_readlinkat,{ AT_DIRFD, AT_STR, AT_BUF_OUT, AT_UINT }, 0 },
    { G_NR_getdents64,{ AT_FD, AT_PTR, AT_UINT }, 0 },
    { G_NR_unlinkat,  { AT_DIRFD, AT_STR, AT_ATFLAGS }, 0 },
    { G_NR_mknodat,   { AT_DIRFD, AT_STR, AT_MODE, AT_HEX }, 0 },
    { G_NR_mkdirat,   { AT_DIRFD, AT_STR, AT_MODE }, 0 },
    { G_NR_renameat,  { AT_DIRFD, AT_STR, AT_DIRFD, AT_STR }, 0 },
    { G_NR_renameat2, { AT_DIRFD, AT_STR, AT_DIRFD, AT_STR, AT_HEX }, 0 },
    { G_NR_linkat,    { AT_DIRFD, AT_STR, AT_DIRFD, AT_STR, AT_ATFLAGS }, 0 },
    { G_NR_symlinkat, { AT_STR, AT_DIRFD, AT_STR }, 0 },
    { G_NR_faccessat, { AT_DIRFD, AT_STR, AT_INT }, 0 },
    { G_NR_faccessat2,{ AT_DIRFD, AT_STR, AT_INT, AT_ATFLAGS }, 0 },
    { G_NR_fchmodat,  { AT_DIRFD, AT_STR, AT_MODE }, 0 },
    { G_NR_fchmod,    { AT_FD, AT_MODE }, 0 },
    { G_NR_fchownat,  { AT_DIRFD, AT_STR, AT_INT, AT_INT, AT_ATFLAGS }, 0 },
    { G_NR_fchown,    { AT_FD, AT_INT, AT_INT }, 0 },
    { G_NR_dup,       { AT_FD }, 0 },
    { G_NR_dup3,      { AT_FD, AT_FD, AT_OFLAGS }, 0 },
    { G_NR_fcntl,     { AT_FD, AT_INT, AT_HEX }, 0 },
    { G_NR_ioctl,     { AT_FD, AT_HEX, AT_HEX }, 0 },
    { G_NR_ftruncate, { AT_FD, AT_INT }, 0 },
    { G_NR_truncate,  { AT_STR, AT_INT }, 0 },
    { G_NR_fsync,     { AT_FD }, 0 },
    { G_NR_fdatasync, { AT_FD }, 0 },
    { G_NR_fchdir,    { AT_FD }, 0 },
    { G_NR_chdir,     { AT_STR }, 0 },
    { G_NR_chroot,    { AT_STR }, 0 },
    { G_NR_statfs,    { AT_STR, AT_PTR }, 0 },
    { G_NR_fstatfs,   { AT_FD, AT_PTR }, 0 },
    { G_NR_getcwd,    { AT_STR_OUT, AT_UINT }, 0 },
    { G_NR_pipe2,     { AT_PTR, AT_OFLAGS }, 0 },
    { G_NR_mount,     { AT_STR, AT_STR, AT_STR, AT_MSFLAGS, AT_PTR }, 0 },
    { G_NR_umount2,   { AT_STR, AT_UMOUNTFLAGS }, 0 },
    /* memory */
    { G_NR_mmap,      { AT_PTR, AT_UINT, AT_PROT, AT_MAPFLAGS, AT_FD, AT_HEX }, AT_HEX },
    { G_NR_munmap,    { AT_PTR, AT_UINT }, 0 },
    { G_NR_mprotect,  { AT_PTR, AT_UINT, AT_PROT }, 0 },
    { G_NR_mremap,    { AT_PTR, AT_UINT, AT_UINT, AT_HEX, AT_PTR }, AT_HEX },
    { G_NR_brk,       { AT_PTR }, AT_HEX },
    { G_NR_madvise,   { AT_PTR, AT_UINT, AT_INT }, 0 },
    { G_NR_mlock,     { AT_PTR, AT_UINT }, 0 },
    { G_NR_munlock,   { AT_PTR, AT_UINT }, 0 },
    { G_NR_msync,     { AT_PTR, AT_UINT, AT_HEX }, 0 },
    /* process */
    { G_NR_execve,    { AT_STR, AT_STRARRAY, AT_STRARRAY }, 0 },
    { G_NR_execveat,  { AT_DIRFD, AT_STR, AT_STRARRAY, AT_STRARRAY, AT_ATFLAGS }, 0 },
    { G_NR_exit,      { AT_INT }, 0 },
    { G_NR_exit_group,{ AT_INT }, 0 },
    { G_NR_clone,     { AT_HEX, AT_PTR, AT_PTR, AT_PTR, AT_PTR }, 0 },
    { G_NR_ptrace,    { AT_INT, AT_INT, AT_HEX, AT_HEX }, 0 },
    { G_NR_wait4,     { AT_INT, AT_PTR, AT_HEX, AT_PTR }, 0 },
    { G_NR_kill,      { AT_INT, AT_SIG }, 0 },
    { G_NR_tkill,     { AT_INT, AT_SIG }, 0 },
    { G_NR_tgkill,    { AT_INT, AT_INT, AT_SIG }, 0 },
    { G_NR_set_tid_address, { AT_PTR }, 0 },
    { G_NR_futex,     { AT_PTR, AT_INT, AT_INT, AT_PTR, AT_PTR, AT_HEX }, 0 },
    { G_NR_getpid,    { AT_NONE }, 0 },
    { G_NR_getppid,   { AT_NONE }, 0 },
    { G_NR_gettid,    { AT_NONE }, 0 },
    { G_NR_getuid,    { AT_NONE }, 0 },
    { G_NR_geteuid,   { AT_NONE }, 0 },
    { G_NR_getgid,    { AT_NONE }, 0 },
    { G_NR_getegid,   { AT_NONE }, 0 },
    { G_NR_setuid,    { AT_INT }, 0 },
    { G_NR_setgid,    { AT_INT }, 0 },
    { G_NR_sched_yield, { AT_NONE }, 0 },
    { G_NR_setsid,    { AT_NONE }, 0 },
    /* signals */
    { G_NR_rt_sigaction,   { AT_SIG, AT_PTR, AT_PTR, AT_UINT }, 0 },
    { G_NR_rt_sigprocmask, { AT_SIGHOW, AT_PTR, AT_PTR, AT_UINT }, 0 },
    { G_NR_rt_sigreturn,   { AT_NONE }, 0 },
    /* time */
    { G_NR_clock_gettime,  { AT_INT, AT_TIMESPEC_O }, 0 },
    { G_NR_clock_getres,   { AT_INT, AT_TIMESPEC_O }, 0 },
    { G_NR_gettimeofday,   { AT_TIMEVAL_O, AT_PTR }, 0 },
    { G_NR_nanosleep,      { AT_TIMESPEC, AT_PTR }, 0 },
    { G_NR_clock_nanosleep,{ AT_INT, AT_HEX, AT_TIMESPEC, AT_PTR }, 0 },
    { G_NR_timer_create,   { AT_INT, AT_PTR, AT_PTR }, 0 },
    { G_NR_timer_settime,  { AT_INT, AT_HEX, AT_PTR, AT_PTR }, 0 },
    { G_NR_timer_gettime,  { AT_INT, AT_PTR }, 0 },
    { G_NR_timer_getoverrun, { AT_INT }, 0 },
    { G_NR_timer_delete,   { AT_INT }, 0 },
    /* resource / misc */
    { G_NR_prlimit64, { AT_INT, AT_INT, AT_RLIMIT, AT_RLIMIT_O }, 0 },
    { G_NR_getrlimit, { AT_INT, AT_RLIMIT_O }, 0 },
    { G_NR_setrlimit, { AT_INT, AT_RLIMIT }, 0 },
    { G_NR_uname,     { AT_UTSNAME }, 0 },
    { G_NR_getrandom, { AT_PTR, AT_UINT, AT_HEX }, 0 },
    { G_NR_prctl,     { AT_INT, AT_HEX, AT_HEX, AT_HEX, AT_HEX }, 0 },
    { G_NR_fadvise64, { AT_FD, AT_INT, AT_INT, AT_INT }, 0 },
    { G_NR_memfd_create, { AT_STR, AT_HEX }, 0 },
    /* sockets */
    { G_NR_socket,    { AT_SODOMAIN, AT_SOTYPE, AT_INT }, 0 },
    { G_NR_socketpair,{ AT_SODOMAIN, AT_SOTYPE, AT_INT, AT_PTR }, 0 },
    { G_NR_connect,   { AT_FD, AT_SOCKADDR, AT_UINT }, 0 },
    { G_NR_bind,      { AT_FD, AT_SOCKADDR, AT_UINT }, 0 },
    { G_NR_accept,    { AT_FD, AT_SOCKADDR_O, AT_PTR }, 0 },
    { G_NR_accept4,   { AT_FD, AT_SOCKADDR_O, AT_PTR, AT_SOTYPE }, 0 },
    { G_NR_getsockname,{ AT_FD, AT_SOCKADDR_O, AT_PTR }, 0 },
    { G_NR_getpeername,{ AT_FD, AT_SOCKADDR_O, AT_PTR }, 0 },
    { G_NR_sendto,    { AT_FD, AT_BUF_IN, AT_UINT, AT_HEX, AT_SOCKADDR, AT_UINT }, 0 },
    { G_NR_recvfrom,  { AT_FD, AT_BUF_OUT, AT_UINT, AT_HEX, AT_SOCKADDR_O, AT_PTR }, 0 },
    { G_NR_listen,    { AT_FD, AT_INT }, 0 },
    { G_NR_shutdown,  { AT_FD, AT_INT }, 0 },
};

static u8 g_argtab[G_NR_MAX][6];  /* per-syscall arg types (0 => AT_NONE) */
static u8 g_rettab[G_NR_MAX];     /* per-syscall return render */
static u8 g_described[G_NR_MAX];  /* 1 => syscall has a descriptor row */

static void strace_init(void) {
    for (size_t i = 0; i < sizeof argdefs / sizeof argdefs[0]; i++) {
        u16 nr = argdefs[i].nr;
        memcpy(g_argtab[nr], argdefs[i].t, 6);
        g_rettab[nr] = argdefs[i].rt;
        g_described[nr] = 1;
    }
}

/* ---- name tables ---------------------------------------------------------- */
struct flagname { u64 mask; const char *name; };

/* open flags minus the O_ACCMODE bits (rendered separately). Composite flags
 * (O_SYNC includes O_DSYNC, O_TMPFILE includes O_DIRECTORY) list their full bit
 * pattern first so the matched-and-cleared walk never double-reports them. */
static const struct flagname oflag_tab[] = {
    { 020040000, "O_TMPFILE" }, { 04010000, "O_SYNC" },
    { 0100,   "O_CREAT" },   { 0200,   "O_EXCL" },     { 0400,   "O_NOCTTY" },
    { 01000,  "O_TRUNC" },   { 02000,  "O_APPEND" },   { 04000,  "O_NONBLOCK" },
    { 010000, "O_DSYNC" },   { 020000, "O_ASYNC" },    { 040000, "O_DIRECTORY" },
    { 0100000, "O_NOFOLLOW" },{ 0200000, "O_DIRECT" }, { 0400000, "O_LARGEFILE" },
    { 01000000, "O_NOATIME" },{ 02000000, "O_CLOEXEC" },{ 010000000, "O_PATH" },
    { 0, NULL }
};
static const struct flagname prot_tab[] = {
    { 0x1, "PROT_READ" }, { 0x2, "PROT_WRITE" }, { 0x4, "PROT_EXEC" },
    { 0x01000000, "PROT_GROWSDOWN" }, { 0x02000000, "PROT_GROWSUP" },
    { 0, NULL }
};
static const struct flagname map_tab[] = {
    { 0x03, "MAP_SHARED_VALIDATE" },       /* == SHARED|PRIVATE, list first */
    { 0x01, "MAP_SHARED" },  { 0x02, "MAP_PRIVATE" },
    { 0x10, "MAP_FIXED" },   { 0x20, "MAP_ANONYMOUS" },
    { 0x100, "MAP_GROWSDOWN" }, { 0x800, "MAP_DENYWRITE" },
    { 0x1000, "MAP_EXECUTABLE" }, { 0x2000, "MAP_LOCKED" },
    { 0x4000, "MAP_NORESERVE" }, { 0x8000, "MAP_POPULATE" },
    { 0x10000, "MAP_NONBLOCK" }, { 0x20000, "MAP_STACK" },
    { 0x40000, "MAP_HUGETLB" }, { 0x80000, "MAP_SYNC" },
    { 0x100000, "MAP_FIXED_NOREPLACE" },
    { 0, NULL }
};
static const struct flagname at_tab[] = {
    { 0x100, "AT_SYMLINK_NOFOLLOW" }, { 0x200, "AT_REMOVEDIR" },
    { 0x400, "AT_SYMLINK_FOLLOW" }, { 0x800, "AT_NO_AUTOMOUNT" },
    { 0x1000, "AT_EMPTY_PATH" }, { 0x4000, "AT_STATX_FORCE_SYNC" },
    { 0, NULL }
};
static const struct flagname ms_tab[] = {
    { 0x0001, "MS_RDONLY" }, { 0x0002, "MS_NOSUID" }, { 0x0004, "MS_NODEV" },
    { 0x0008, "MS_NOEXEC" }, { 0x0020, "MS_REMOUNT" }, { 0x1000, "MS_BIND" },
    { 0x2000, "MS_MOVE" }, { 0x4000, "MS_REC" }, { 0x20000, "MS_UNBINDABLE" },
    { 0x40000, "MS_PRIVATE" }, { 0x80000, "MS_SLAVE" }, { 0x100000, "MS_SHARED" },
    { 0, NULL }
};
static const struct flagname umount_tab[] = {
    { 0x1, "MNT_FORCE" }, { 0x2, "MNT_DETACH" }, { 0x4, "MNT_EXPIRE" },
    { 0x8, "UMOUNT_NOFOLLOW" }, { 0, NULL }
};
static const struct flagname socktype_flag_tab[] = {
    { 04000, "SOCK_NONBLOCK" }, { 02000000, "SOCK_CLOEXEC" }, { 0, NULL }
};

struct enumname { u64 val; const char *name; };
static const struct enumname sig_tab[] = {
    { 1, "SIGHUP" }, { 2, "SIGINT" }, { 3, "SIGQUIT" }, { 4, "SIGILL" },
    { 5, "SIGTRAP" }, { 6, "SIGABRT" }, { 7, "SIGBUS" }, { 8, "SIGFPE" },
    { 9, "SIGKILL" }, { 10, "SIGUSR1" }, { 11, "SIGSEGV" }, { 12, "SIGUSR2" },
    { 13, "SIGPIPE" }, { 14, "SIGALRM" }, { 15, "SIGTERM" }, { 16, "SIGSTKFLT" },
    { 17, "SIGCHLD" }, { 18, "SIGCONT" }, { 19, "SIGSTOP" }, { 20, "SIGTSTP" },
    { 21, "SIGTTIN" }, { 22, "SIGTTOU" }, { 23, "SIGURG" }, { 24, "SIGXCPU" },
    { 25, "SIGXFSZ" }, { 26, "SIGVTALRM" }, { 27, "SIGPROF" }, { 28, "SIGWINCH" },
    { 29, "SIGIO" }, { 30, "SIGPWR" }, { 31, "SIGSYS" }, { 0, NULL }
};
static const struct enumname whence_tab[] = {
    { 0, "SEEK_SET" }, { 1, "SEEK_CUR" }, { 2, "SEEK_END" },
    { 3, "SEEK_DATA" }, { 4, "SEEK_HOLE" }, { 0, NULL }
};
static const struct enumname sighow_tab[] = {
    { 0, "SIG_BLOCK" }, { 1, "SIG_UNBLOCK" }, { 2, "SIG_SETMASK" }, { 0, NULL }
};
static const struct enumname af_tab[] = {
    { 0, "AF_UNSPEC" }, { 1, "AF_UNIX" }, { 2, "AF_INET" }, { 10, "AF_INET6" },
    { 16, "AF_NETLINK" }, { 17, "AF_PACKET" }, { 0, NULL }
};
static const struct enumname socktype_tab[] = {
    { 1, "SOCK_STREAM" }, { 2, "SOCK_DGRAM" }, { 3, "SOCK_RAW" },
    { 4, "SOCK_RDM" }, { 5, "SOCK_SEQPACKET" }, { 0, NULL }
};

/* asm-generic errno names, indexed by number. Message text comes from the host
 * strerror(): the host is Linux and shares these numbers, so it stays correct. */
static const char *const errno_tab[] = {
    [1]="EPERM",[2]="ENOENT",[3]="ESRCH",[4]="EINTR",[5]="EIO",[6]="ENXIO",
    [7]="E2BIG",[8]="ENOEXEC",[9]="EBADF",[10]="ECHILD",[11]="EAGAIN",
    [12]="ENOMEM",[13]="EACCES",[14]="EFAULT",[15]="ENOTBLK",[16]="EBUSY",
    [17]="EEXIST",[18]="EXDEV",[19]="ENODEV",[20]="ENOTDIR",[21]="EISDIR",
    [22]="EINVAL",[23]="ENFILE",[24]="EMFILE",[25]="ENOTTY",[26]="ETXTBSY",
    [27]="EFBIG",[28]="ENOSPC",[29]="ESPIPE",[30]="EROFS",[31]="EMLINK",
    [32]="EPIPE",[33]="EDOM",[34]="ERANGE",[35]="EDEADLK",[36]="ENAMETOOLONG",
    [37]="ENOLCK",[38]="ENOSYS",[39]="ENOTEMPTY",[40]="ELOOP",[42]="ENOMSG",
    [43]="EIDRM",[44]="ECHRNG",[45]="EL2NSYNC",[46]="EL3HLT",[47]="EL3RST",
    [48]="ELNRNG",[49]="EUNATCH",[50]="ENOCSI",[51]="EL2HLT",[52]="EBADE",
    [53]="EBADR",[54]="EXFULL",[55]="ENOANO",[56]="EBADRQC",[57]="EBADSLT",
    [59]="EBFONT",[60]="ENOSTR",[61]="ENODATA",[62]="ETIME",[63]="ENOSR",
    [64]="ENONET",[65]="ENOPKG",[66]="EREMOTE",[67]="ENOLINK",[68]="EADV",
    [69]="ESRMNT",[70]="ECOMM",[71]="EPROTO",[72]="EMULTIHOP",[73]="EDOTDOT",
    [74]="EBADMSG",[75]="EOVERFLOW",[76]="ENOTUNIQ",[77]="EBADFD",[78]="EREMCHG",
    [79]="ELIBACC",[80]="ELIBBAD",[81]="ELIBSCN",[82]="ELIBMAX",[83]="ELIBEXEC",
    [84]="EILSEQ",[85]="ERESTART",[86]="ESTRPIPE",[87]="EUSERS",[88]="ENOTSOCK",
    [89]="EDESTADDRREQ",[90]="EMSGSIZE",[91]="EPROTOTYPE",[92]="ENOPROTOOPT",
    [93]="EPROTONOSUPPORT",[94]="ESOCKTNOSUPPORT",[95]="EOPNOTSUPP",
    [96]="EPFNOSUPPORT",[97]="EAFNOSUPPORT",[98]="EADDRINUSE",
    [99]="EADDRNOTAVAIL",[100]="ENETDOWN",[101]="ENETUNREACH",[102]="ENETRESET",
    [103]="ECONNABORTED",[104]="ECONNRESET",[105]="ENOBUFS",[106]="EISCONN",
    [107]="ENOTCONN",[108]="ESHUTDOWN",[109]="ETOOMANYREFS",[110]="ETIMEDOUT",
    [111]="ECONNREFUSED",[112]="EHOSTDOWN",[113]="EHOSTUNREACH",[114]="EALREADY",
    [115]="EINPROGRESS",[116]="ESTALE",[117]="EUCLEAN",[118]="ENOTNAM",
    [119]="ENAVAIL",[120]="EISNAM",[121]="EREMOTEIO",[122]="EDQUOT",
    [123]="ENOMEDIUM",[124]="EMEDIUMTYPE",[125]="ECANCELED",[126]="ENOKEY",
    [127]="EKEYEXPIRED",[128]="EKEYREVOKED",[129]="EKEYREJECTED",
    [130]="EOWNERDEAD",[131]="ENOTRECOVERABLE",[132]="ERFKILL",[133]="EHWPOISON",
};

/* ---- bounded string builder ----------------------------------------------- */
typedef struct { char *buf; size_t cap; size_t off; } SB;

static void sb_puts(SB *s, const char *str) {
    while (*str && s->off + 1 < s->cap) s->buf[s->off++] = *str++;
    s->buf[s->off < s->cap ? s->off : s->cap - 1] = '\0';
}
static void sb_printf(SB *s, const char *fmt, ...) {
    if (s->off + 1 >= s->cap) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(s->buf + s->off, s->cap - s->off, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    s->off += (size_t)n;
    if (s->off >= s->cap) s->off = s->cap - 1;  /* vsnprintf truncated */
}

/* Longest byte-buffer content shown for read/write-style data args (strace -s). */
#define STRACE_BUF_MAX 32

/* Append len bytes as a C-style quoted literal, escaping ", \\, the common
 * control chars, and other non-printables as \xHH. NUL bytes are kept (buffers
 * may embed them), so this is length- rather than NUL-terminated. */
static void sb_quote_bytes(SB *s, const unsigned char *data, size_t len) {
    sb_puts(s, "\"");
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = data[i];
        if (ch == '"' || ch == '\\') sb_printf(s, "\\%c", ch);
        else if (ch == '\n') sb_puts(s, "\\n");
        else if (ch == '\t') sb_puts(s, "\\t");
        else if (ch == '\r') sb_puts(s, "\\r");
        else if (ch >= 0x20 && ch < 0x7f) sb_printf(s, "%c", ch);
        else sb_printf(s, "\\x%02x", ch);
    }
    sb_puts(s, "\"");
}
/* Append a NUL-terminated C string as a quoted literal. */
static void sb_quote(SB *s, const char *src) {
    sb_quote_bytes(s, (const unsigned char *)src, strlen(src));
}

/* Render a guest byte range [va, va+len) as a quoted, capped literal, appending
 * "..." after the closing quote when the buffer is longer than what we show.
 * A NULL pointer prints NULL; an unreadable one falls back to its hex address. */
static void fmt_buf(SB *s, struct CPU *c, u64 va, u64 len) {
    if (va == 0) { sb_puts(s, "NULL"); return; }
    u64 show = len < STRACE_BUF_MAX ? len : STRACE_BUF_MAX;
    if (show == 0) { sb_puts(s, "\"\""); return; }
    unsigned char tmp[STRACE_BUF_MAX];
    if (copy_from_guest(c, tmp, va, (size_t)show) < 0) {
        sb_printf(s, "0x%llx", (unsigned long long)va);
        return;
    }
    sb_quote_bytes(s, tmp, (size_t)show);
    if (len > show) sb_puts(s, "...");
}

/* ---- formatters ----------------------------------------------------------- */
static void fmt_flag_body(SB *s, u64 rem, const struct flagname *tab, int *first) {
    for (; tab->name; tab++)
        if (tab->mask && (rem & tab->mask) == tab->mask) {
            sb_printf(s, "%s%s", *first ? "" : "|", tab->name);
            rem &= ~tab->mask; *first = 0;
        }
    if (rem) { sb_printf(s, "%s0x%llx", *first ? "" : "|", (unsigned long long)rem); *first = 0; }
}
static void fmt_flags(SB *s, u64 v, const struct flagname *tab, const char *zero) {
    if (v == 0) { sb_puts(s, zero ? zero : "0"); return; }
    int first = 1;
    fmt_flag_body(s, v, tab, &first);
}
static void fmt_oflags(SB *s, u64 v) {
    u64 acc = v & 3;
    sb_puts(s, acc == 0 ? "O_RDONLY" : acc == 1 ? "O_WRONLY" :
               acc == 2 ? "O_RDWR" : "O_ACCMODE");
    int first = 0;
    fmt_flag_body(s, v & ~3ull, oflag_tab, &first);
}
static void fmt_enum(SB *s, u64 v, const struct enumname *tab) {
    for (; tab->name; tab++)
        if (tab->val == v) { sb_puts(s, tab->name); return; }
    sb_printf(s, "%llu", (unsigned long long)v);
}
static void fmt_sotype(SB *s, u64 v) {
    fmt_enum(s, v & 0xff, socktype_tab);
    int first = 0;
    fmt_flag_body(s, v & ~0xffull, socktype_flag_tab, &first);
}
static void fmt_stmode(SB *s, u32 m) {
    u32 t = m & 0170000;
    const char *tn = t == 0100000 ? "S_IFREG" : t == 0040000 ? "S_IFDIR" :
                     t == 0120000 ? "S_IFLNK" : t == 0020000 ? "S_IFCHR" :
                     t == 0060000 ? "S_IFBLK" : t == 0010000 ? "S_IFIFO" :
                     t == 0140000 ? "S_IFSOCK" : NULL;
    if (tn) sb_printf(s, "%s|0%llo", tn, (unsigned long long)(m & 07777));
    else    sb_printf(s, "0%llo", (unsigned long long)m);
}

/* Decode a sockaddr into {sa_family=…, …}. Reads only what each family needs so
 * a short mapping past the family word still decodes the family. */
static void fmt_sockaddr(SB *s, struct CPU *c, u64 va) {
    u16 fam;
    if (copy_from_guest(c, &fam, va, sizeof fam) < 0) { sb_printf(s, "0x%llx", (unsigned long long)va); return; }
    if (fam == 1) {                         /* AF_UNIX */
        char path[109];
        long n = copy_str_from_guest(c, path, va + 2, sizeof path - 1);
        sb_puts(s, "{sa_family=AF_UNIX, sun_path=");
        if (n > 0) sb_quote(s, path);
        else if (n == 0) sb_puts(s, "@\"\"");   /* abstract or empty */
        else sb_puts(s, "?");
        sb_puts(s, "}");
    } else if (fam == 2) {                   /* AF_INET */
        u8 b[6];                             /* port(2, net order) + addr(4) */
        if (copy_from_guest(c, b, va + 2, sizeof b) < 0) { sb_puts(s, "{sa_family=AF_INET, ...}"); return; }
        sb_printf(s, "{sa_family=AF_INET, sin_port=htons(%u), sin_addr=%u.%u.%u.%u}",
                  (unsigned)((b[0] << 8) | b[1]), b[2], b[3], b[4], b[5]);
    } else {
        sb_puts(s, "{sa_family=");
        fmt_enum(s, fam, af_tab);
        sb_puts(s, ", ...}");
    }
}

static int type_is_output(u8 ty) {
    return ty == AT_STAT || ty == AT_UTSNAME || ty == AT_TIMESPEC_O ||
           ty == AT_TIMEVAL_O || ty == AT_RLIMIT_O || ty == AT_SOCKADDR_O;
}

/* Pretty-print a struct pointer. ok = the syscall succeeded (output structs are
 * only valid then). Always emits exactly one argument. */
static void fmt_struct(SB *s, struct CPU *c, u8 ty, u64 va, int ok) {
    if (va == 0) { sb_puts(s, "NULL"); return; }
    if (type_is_output(ty) && !ok) { sb_printf(s, "0x%llx", (unsigned long long)va); return; }

    switch (ty) {
    case AT_STAT: {
        GStat g;
        if (copy_from_guest(c, &g, va, sizeof g) < 0) { sb_printf(s, "0x%llx", (unsigned long long)va); return; }
        sb_puts(s, "{st_mode=");
        fmt_stmode(s, g.st_mode);
        sb_printf(s, ", st_size=%lld, ...}", (long long)g.st_size);
        return;
    }
    case AT_TIMESPEC:
    case AT_TIMESPEC_O: {
        GTimespec g;
        if (copy_from_guest(c, &g, va, sizeof g) < 0) { sb_printf(s, "0x%llx", (unsigned long long)va); return; }
        sb_printf(s, "{tv_sec=%lld, tv_nsec=%lld}", (long long)g.tv_sec, (long long)g.tv_nsec);
        return;
    }
    case AT_TIMEVAL_O: {
        GTimeval g;
        if (copy_from_guest(c, &g, va, sizeof g) < 0) { sb_printf(s, "0x%llx", (unsigned long long)va); return; }
        sb_printf(s, "{tv_sec=%lld, tv_usec=%lld}", (long long)g.tv_sec, (long long)g.tv_usec);
        return;
    }
    case AT_RLIMIT:
    case AT_RLIMIT_O: {
        GRlimit g;
        if (copy_from_guest(c, &g, va, sizeof g) < 0) { sb_printf(s, "0x%llx", (unsigned long long)va); return; }
        sb_puts(s, "{rlim_cur=");
        if (g.rlim_cur == ~0ull) sb_puts(s, "RLIM_INFINITY"); else sb_printf(s, "%llu", (unsigned long long)g.rlim_cur);
        sb_puts(s, ", rlim_max=");
        if (g.rlim_max == ~0ull) sb_puts(s, "RLIM_INFINITY"); else sb_printf(s, "%llu", (unsigned long long)g.rlim_max);
        sb_puts(s, "}");
        return;
    }
    case AT_UTSNAME: {
        GUtsname g;
        if (copy_from_guest(c, &g, va, sizeof g) < 0) { sb_printf(s, "0x%llx", (unsigned long long)va); return; }
        g.sysname[64] = g.nodename[64] = g.release[64] = g.machine[64] = '\0';
        sb_puts(s, "{sysname=");   sb_quote(s, g.sysname);
        sb_puts(s, ", nodename="); sb_quote(s, g.nodename);
        sb_puts(s, ", release=");  sb_quote(s, g.release);
        sb_puts(s, ", machine=");  sb_quote(s, g.machine);
        sb_puts(s, ", ...}");
        return;
    }
    case AT_SOCKADDR:
    case AT_SOCKADDR_O:
        fmt_sockaddr(s, c, va);
        return;
    default:
        sb_printf(s, "0x%llx", (unsigned long long)va);
        return;
    }
}

/* Format one argument of the given type. args/idx/ret give the buffer types
 * access to a sibling length arg and the return value. */
static void fmt_arg(SB *s, struct CPU *c, u8 ty, const u64 *args, int idx,
                    const StraceSnap *snap, int ok, u64 ret) {
    u64 v = args[idx];
    switch (ty) {
    case AT_INT:   sb_printf(s, "%lld", (long long)(s64)v); break;
    case AT_UINT:  sb_printf(s, "%llu", (unsigned long long)v); break;
    case AT_HEX:   sb_printf(s, "0x%llx", (unsigned long long)v); break;
    case AT_PTR:   if (v == 0) sb_puts(s, "NULL"); else sb_printf(s, "0x%llx", (unsigned long long)v); break;
    case AT_FD:    sb_printf(s, "%d", (int)(s32)v); break;
    case AT_DIRFD:
        if ((s32)v == G_AT_FDCWD) sb_puts(s, "AT_FDCWD");
        else sb_printf(s, "%d", (int)(s32)v);
        break;
    case AT_STR:
        if (snap && snap->has_str[idx]) sb_quote(s, snap->str[idx]);
        else if (v == 0) sb_puts(s, "NULL");
        else sb_printf(s, "0x%llx", (unsigned long long)v);
        break;
    case AT_STRARRAY:
        if (snap && snap->arr[idx]) sb_puts(s, snap->arr[idx]);
        else if (v == 0) sb_puts(s, "NULL");
        else sb_printf(s, "0x%llx", (unsigned long long)v);
        break;
    case AT_STR_OUT:
        /* NUL-terminated string the call wrote (getcwd), valid on success. */
        if (v == 0) sb_puts(s, "NULL");
        else if (!ok) sb_printf(s, "0x%llx", (unsigned long long)v);
        else {
            char tmp[STRACE_STR_MAX];
            if (copy_str_from_guest(c, tmp, v, sizeof tmp) < 0)
                sb_printf(s, "0x%llx", (unsigned long long)v);
            else sb_quote(s, tmp);
        }
        break;
    case AT_BUF_IN:
        /* Input data: valid regardless of success; length is the next arg. */
        fmt_buf(s, c, v, (idx + 1 < 6) ? args[idx + 1] : 0);
        break;
    case AT_BUF_OUT:
        /* Output data: only the returned byte count was written, on success. */
        if (v == 0) sb_puts(s, "NULL");
        else if (!ok) sb_printf(s, "0x%llx", (unsigned long long)v);
        else fmt_buf(s, c, v, ret);
        break;
    case AT_OFLAGS:      fmt_oflags(s, v); break;
    case AT_MODE:        sb_printf(s, "0%llo", (unsigned long long)v); break;
    case AT_PROT:        fmt_flags(s, v, prot_tab, "PROT_NONE"); break;
    case AT_MAPFLAGS:    fmt_flags(s, v, map_tab, NULL); break;
    case AT_MSFLAGS:     fmt_flags(s, v, ms_tab, NULL); break;
    case AT_ATFLAGS:     fmt_flags(s, v, at_tab, NULL); break;
    case AT_UMOUNTFLAGS: fmt_flags(s, v, umount_tab, NULL); break;
    case AT_SIG:         fmt_enum(s, v, sig_tab); break;
    case AT_WHENCE:      fmt_enum(s, v, whence_tab); break;
    case AT_SIGHOW:      fmt_enum(s, v, sighow_tab); break;
    case AT_SODOMAIN:    fmt_enum(s, v, af_tab); break;
    case AT_SOTYPE:      fmt_sotype(s, v); break;
    default:             fmt_struct(s, c, ty, v, ok); break;
    }
}

/* ---- public API ----------------------------------------------------------- */
void strace_pre(struct CPU *c, u64 nr, const u64 *args, StraceSnap *snap) {
    static int inited;
    if (!inited) { strace_init(); inited = 1; }

    /* Initialize the bookkeeping the caller left uninitialized (str[][] itself
     * is only read when has_str[] marks it valid). */
    memset(snap->has_str, 0, sizeof snap->has_str);
    for (int i = 0; i < 6; i++) snap->arr[i] = NULL;
    if (nr >= G_NR_MAX) return;

    const u8 *t = g_argtab[nr];
    for (int i = 0; i < 6; i++) {
        if (t[i] == AT_STR) {
            if (copy_str_from_guest(c, snap->str[i], args[i], STRACE_STR_MAX) >= 0)
                snap->has_str[i] = 1;
        } else if (t[i] == AT_STRARRAY && args[i]) {
            /* Format the whole "[...]" now — execve frees the pages on success. */
            size_t cap = 8192;
            char *out = malloc(cap);
            if (!out) continue;
            SB s = { out, cap, 0 };
            sb_puts(&s, "[");
            int first = 1, ok = 1;
            u64 p;
            int j = 0;
            for (; j < 32; j++) {
                if (copy_from_guest(c, &p, args[i] + (u64)j * 8, sizeof p) < 0) { ok = 0; break; }
                if (p == 0) break;
                char tmp[STRACE_STR_MAX];
                if (copy_str_from_guest(c, tmp, p, sizeof tmp) < 0) strcpy(tmp, "???");
                sb_printf(&s, "%s", first ? "" : ", ");
                sb_quote(&s, tmp);
                first = 0;
            }
            if (j == 32) sb_puts(&s, ", ...");   /* array longer than we show */
            sb_puts(&s, "]");
            if (ok || !first) snap->arr[i] = out;  /* keep if we read anything */
            else free(out);
        }
    }
}

void strace_log(struct CPU *c, u64 nr, const char *name, const u64 *args,
                u64 ret, StraceSnap *snap) {
    char buf[8192];
    SB s = { buf, sizeof buf, 0 };
    s64 r = (s64)ret;
    int ok = !(r < 0 && r >= -4095);

    sb_printf(&s, "%d %s(", getpid(), name);

    if (nr < G_NR_MAX && g_described[nr]) {
        const u8 *t = g_argtab[nr];
        int printed = 0;
        for (int i = 0; i < 6; i++) {
            if (t[i] == AT_NONE) break;      /* arity: no more args */
            /* openat's mode is meaningful only with O_CREAT/O_TMPFILE (bit
             * 0100 / __O_TMPFILE 020000000); omit it otherwise, like strace. */
            if (nr == G_NR_openat && i == 3 && !(args[2] & (0100 | 020000000)))
                break;
            if (printed) sb_puts(&s, ", ");
            fmt_arg(&s, c, t[i], args, i, snap, ok, ret);
            printed = 1;
        }
    } else {
        /* Undescribed syscall: fall back to six hex args (as plain --strace). */
        for (int i = 0; i < 6; i++)
            sb_printf(&s, "%s0x%llx", i ? ", " : "", (unsigned long long)args[i]);
    }

    sb_puts(&s, ") = ");
    if (r < 0 && r >= -4095) {
        int e = (int)-r;
        const char *nm = ((size_t)e < sizeof errno_tab / sizeof errno_tab[0]) ? errno_tab[e] : NULL;
        if (nm) sb_printf(&s, "-1 %s (%s)", nm, strerror(e));
        else    sb_printf(&s, "-1 errno %d (%s)", e, strerror(e));
    } else if (nr < G_NR_MAX && g_rettab[nr] == AT_HEX) {
        sb_printf(&s, "0x%llx", (unsigned long long)ret);
    } else {
        sb_printf(&s, "%lld", (long long)r);
    }
    sb_puts(&s, "\n");

    /* One write keeps the line intact under multi-process/-thread interleaving. */
    fwrite(buf, 1, s.off, stderr);

    for (int i = 0; i < 6; i++)
        if (snap->arr[i]) { free(snap->arr[i]); snap->arr[i] = NULL; }
}
