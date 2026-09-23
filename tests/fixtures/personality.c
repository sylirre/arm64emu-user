/* personality(2) as an arm64 kernel with no AArch32 at EL0 answers it, and
 * what its flags do to what such a kernel presents:
 *   - PER_LINUX32 is refused with EINVAL (arm64_personality), whatever else
 *     rides with it, and leaves the value as it was;
 *   - UNAME26 makes uname's release 2.6.<60 + patchlevel><rest>
 *     (override_release), here "2.6.61-arm64chroot";
 *   - READ_IMPLIES_EXEC makes a readable mapping executable: mmap, mprotect,
 *     the heap brk grows and shmat alike -- code written into a read-write
 *     page runs;
 *   - an execve clears READ_IMPLIES_EXEC (arm64's SET_PERSONALITY) and keeps
 *     the rest, and MMAP_PAGE_ZERO then maps page zero read+exec -- where
 *     vm.mmap_min_addr lets anything be mapped there, which the row judges
 *     against the host's own limit.
 *
 * Self-checking: qemu-user hands the value to its host kernel, which knows
 * nothing of AArch32 here and applies none of it to the guest's mappings.
 * The expectations are the kernel's (arch/arm64/kernel/sys.c, kernel/sys.c,
 * mm/mmap.c, mm/mprotect.c, ipc/shm.c, fs/binfmt_elf.c), the mapping rows
 * also measured on a native kernel. */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/shm.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned now(void) { return (unsigned)personality(0xffffffff); }

/* The permission string /proc/self/maps shows for the mapping holding p. */
static const char *perms(const void *p, char *out) {
    FILE *f = fopen("/proc/self/maps", "r");
    strcpy(out, "none");
    if (!f) return out;
    char line[512];
    unsigned long lo, hi;
    char pr[8];
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, pr) == 3 &&
            (unsigned long)p >= lo && (unsigned long)p < hi) {
            strcpy(out, pr);
            break;
        }
    fclose(f);
    return out;
}

static sigjmp_buf jb;
static void onsegv(int s) { (void)s; siglongjmp(jb, 1); }

/* Write `mov w0, #42; ret` into a fresh read-write page and call it. */
static const char *run_rw(void) {
    static char res[16];
    unsigned *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) return "mmap-failed";
    code[0] = 0x52800540;   /* mov w0, #42 */
    code[1] = 0xd65f03c0;   /* ret */
    __builtin___clear_cache((char *)code, (char *)(code + 2));
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = onsegv;
    sigaction(SIGSEGV, &sa, &old);
    if (sigsetjmp(jb, 1) == 0) {
        int v = ((int (*)(void))(void *)code)();
        snprintf(res, sizeof res, "%d", v);
    } else {
        strcpy(res, "SIGSEGV");
    }
    sigaction(SIGSEGV, &old, NULL);
    munmap(code, 4096);
    return res;
}

static void page0(void) {
    char buf[32] = "";
    FILE *f = fopen("/proc/sys/vm/mmap_min_addr", "r");
    unsigned long lim = 1;
    if (f) { if (fgets(buf, sizeof buf, f)) lim = strtoul(buf, NULL, 10); fclose(f); }
    char pr[8];
    perms((void *)0, pr);
    int mapped = strcmp(pr, "none") != 0;
    if (lim == 0 ? (mapped && !strcmp(pr, "r-xp")) : !mapped)
        printf("page0 follows the limit\n");
    else
        printf("page0 limit=%lu perms=%s\n", lim, pr);
}

int main(int argc, char **argv) {
    char pr[8];
    if (argc > 1 && !strcmp(argv[1], "exec")) {
        void *r = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("exec %08x mmap(r) %s rw-page %s\n", now(), perms(r, pr), run_rw());
        page0();
        return 0;
    }
    setvbuf(stdout, NULL, _IONBF, 0);

    static const unsigned refuse[] = { 0x0008, 0x0008 | UNAME26, 0x8000008,
                                       0x0108 };
    personality(ADDR_NO_RANDOMIZE);
    for (unsigned i = 0; i < sizeof refuse / sizeof *refuse; i++) {
        errno = 0;
        int r = personality(refuse[i]);
        printf("refuse %#x: r=%d errno=%d now=%08x\n", refuse[i], r, errno, now());
    }
    personality(0x0018);   /* a type byte that is not PER_LINUX32 */
    printf("type 0x18 kept: %08x\n", now());

    struct utsname u;
    personality(UNAME26);
    uname(&u);
    printf("uname26 %s\n", u.release);
    personality(0);
    uname(&u);
    printf("uname %s\n", u.release);

    printf("rw-page before %s\n", run_rw());
    personality(READ_IMPLIES_EXEC);
    char *r = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *w = mmap(NULL, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *n = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("mmap r %s", perms(r, pr));
    printf(" w %s", perms(w, pr));
    printf(" none %s\n", perms(n, pr));
    mprotect(n, 4096, PROT_READ | PROT_WRITE);
    printf("mprotect rw %s", perms(n, pr));
    mprotect(n, 4096, PROT_WRITE);
    printf(" w %s\n", perms(n, pr));
    char *b0 = sbrk(0);
    if (sbrk(8192) == (void *)-1) printf("brk failed\n");
    else printf("brk %s\n", perms(b0 + 4096, pr));
    int id = shmget(IPC_PRIVATE, 4096, 0600);
    void *sa = id < 0 ? (void *)-1 : shmat(id, NULL, SHM_RDONLY);
    if (sa == (void *)-1) printf("shmat failed %d\n", errno);
    else { printf("shmat ro %s\n", perms(sa, pr)); shmdt(sa); }
    if (id >= 0) shmctl(id, IPC_RMID, NULL);
    printf("rw-page under it %s\n", run_rw());

    personality(READ_IMPLIES_EXEC | MMAP_PAGE_ZERO | UNAME26);
    pid_t kid = fork();
    if (kid == 0) {
        execl("/proc/self/exe", "personality", "exec", (char *)NULL);
        _exit(8);
    }
    int st;
    waitpid(kid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) printf("exec child status %#x\n", st);
    printf("done\n");
    return 0;
}
