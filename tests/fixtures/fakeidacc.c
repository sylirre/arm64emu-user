/* access(2) under --fake-id (self-checking; no oracle can answer this -- qemu
 * models no fake identity, and a native run has none either).
 *
 * With --fake-id the guest's credentials are the fake ones and a rootfs file's
 * owner, as every stat reports it, is the REMAPPED owner. The host cannot
 * answer "may I read this" about that pair: its own identity is the
 * emulator's, and it owns the whole rootfs. So the answer used to be the
 * host's, with a bypass bolted on for fake root -- which meant a guest that
 * dropped to a non-root fake uid was still told it could write files its own
 * model says belong to fake root.
 *
 * The rows below are the kernel's generic_permission over the fake identity:
 * root's bypass (read/write always, execute only where an execute bit is set),
 * the owner/group/other triads once the guest has dropped, and the one place
 * access(2) and faccessat2(AT_EACCESS) part company -- the first asks about
 * the real uid, the second about the effective one. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#define G_AT_EACCESS 0x200

static const char *F600 = "/tmp/ci_fa600";
static const char *F640 = "/tmp/ci_fa640";
static const char *F644 = "/tmp/ci_fa644";
static const char *F755 = "/tmp/ci_fa755";

static int acc(const char *p, int m) { return access(p, m) == 0; }
static int acc_eff(const char *p, int m) {
    return syscall(SYS_faccessat2, AT_FDCWD, p, m, G_AT_EACCESS) == 0;
}

static int make(const char *p, mode_t m) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    close(fd);
    return chmod(p, m);
}

int main(void) {
    if (make(F600, 0600) || make(F640, 0640) || make(F644, 0644) || make(F755, 0755)) {
        perror("setup");
        return 1;
    }
    /* Fake root: CAP_DAC_OVERRIDE reads and writes a 0600 file it owns and one
     * it does not, but will not execute a file with no execute bit anywhere. */
    printf("root r600=%d w600=%d x644=%d x755=%d\n",
           acc(F600, R_OK), acc(F600, W_OK), acc(F644, X_OK), acc(F755, X_OK));

    /* Real uid 0, effective 1000: access(2) asks about the real one and still
     * has root's bypass; AT_EACCESS asks about the effective one and does not. */
    if (setresuid(0, 1000, 0) != 0) { perror("setresuid"); return 1; }
    printf("euid1000 real_r600=%d eff_r600=%d\n", acc(F600, R_OK), acc_eff(F600, R_OK));

    /* Fully dropped, but still in fake root's group: the files' owner is fake
     * root, so this is the GROUP triad. */
    if (setresuid(1000, 1000, 1000) != 0) { perror("setresuid2"); return 1; }
    printf("uid1000 r600=%d r640=%d w640=%d x755=%d\n",
           acc(F600, R_OK), acc(F640, R_OK), acc(F640, W_OK), acc(F755, X_OK));
    return 0;
}
