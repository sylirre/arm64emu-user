/* What a faked user namespace accepts as its uid_map / gid_map / setgroups,
 * line for line the kernel's own parsers (kernel/user_namespace.c map_write and
 * proc_setgroups_write).
 *
 * Self-checking: the emulator's namespace is a fiction, so no oracle can run
 * the same writes -- an unprivileged qemu-aarch64 has the initial namespace,
 * whose map is fixed, and on an AppArmor-restricted host even a namespace of
 * its own refuses every well-formed write at the capability check before the
 * parse. The verdicts below are read off the kernel source:
 *
 *  - a write of PAGE_SIZE or more is EINVAL before anything else is looked at;
 *  - the buffer is a string (a NUL ends it) of lines; a line with nothing on
 *    it is an error, not a blank to skip, except that a newline ending the
 *    buffer opens no line;
 *  - a field is simple_strtoul(): decimal digits, no sign, no radix prefix,
 *    and no overflow -- the value lands in a u32, so it is taken modulo 2^32;
 *    whitespace (isspace) must follow the first two fields and nothing but
 *    whitespace the third;
 *  - a first or lower_first of 4294967295 is refused, a count of zero, a
 *    count that carries either range past 2^32, and an extent whose upper or
 *    lower range meets an earlier extent's; 340 extents are the most a map
 *    holds; an empty map is no map;
 *  - a map is written once (EPERM afterwards, tested before the parse);
 *  - setgroups takes fewer than 8 bytes, "allow" or "deny" followed by
 *    whitespace alone; "deny" is refused once gid_map is written, "allow" once
 *    "deny" stands, and "allow" is otherwise a no-op that succeeds -- after
 *    gid_map too.
 *
 * Each case runs in a fresh child that unshares CLONE_NEWUSER, so every write
 * is the first to its file. Output: one line per case, then "done". */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static long wr(const char *file, const void *s, size_t n) {
    int fd = open(file, O_WRONLY);
    if (fd < 0) return -errno;
    ssize_t r = write(fd, s, n);
    long e = r < 0 ? -errno : (long)r;
    close(fd);
    return e;
}

/* The read-back, folded to one line: each extent as "first:lower:count". */
static void rd(const char *file, char *out, size_t outsz) {
    static char b[16384];
    int fd = open(file, O_RDONLY);
    long n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
    if (fd >= 0) close(fd);
    if (n < 0) { snprintf(out, outsz, "read=%d", errno); return; }
    b[n] = 0;
    size_t o = 0;
    unsigned ext = 0;
    for (char *p = strtok(b, "\n"); p; p = strtok(NULL, "\n")) {
        unsigned long f, l, c;
        if (sscanf(p, "%lu %lu %lu", &f, &l, &c) != 3) { snprintf(out, outsz, "bad line [%s]", p); return; }
        if (ext < 4) o += (size_t)snprintf(out + o, outsz - o, "%s%lu:%lu:%lu", o ? "," : "", f, l, c);
        ext++;
    }
    if (ext > 4) snprintf(out + o, outsz - o, ",...(%u extents)", ext);
    if (!ext) snprintf(out, outsz, "(empty)");
}

/* One uid_map write in a fresh namespace: the result, and the map read back
 * when it took. */
static void map_case(const char *name, const void *s, size_t n) {
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        if (unshare(CLONE_NEWUSER) != 0) { printf("%s: unshare=%d\n", name, errno); _exit(0); }
        long r = wr("/proc/self/uid_map", s, n);
        if (r < 0) printf("%s: %ld\n", name, r);
        else {
            char back[256];
            rd("/proc/self/uid_map", back, sizeof back);
            printf("%s: %ld back=%s\n", name, r, back);
        }
        fflush(stdout);
        _exit(0);
    }
    waitpid(k, NULL, 0);
}
#define MAP(name, s) map_case(name, s, strlen(s))

static void sg_case(const char *name, const char *s) {
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        if (unshare(CLONE_NEWUSER) != 0) { printf("%s: unshare=%d\n", name, errno); _exit(0); }
        printf("%s: %ld\n", name, wr("/proc/self/setgroups", s, strlen(s)));
        fflush(stdout);
        _exit(0);
    }
    waitpid(k, NULL, 0);
}

int main(void) {
    /* ---- syntax ---- */
    MAP("simple", "0 1000 1\n");
    MAP("no_newline", "0 1000 1");
    MAP("two_lines", "0 1000 1\n1 1001 1\n");
    MAP("tabs", "0\t1000\t1\n");
    MAP("cr", "0 1000 1\r\n");
    MAP("leading_space", "  0 1000 1\n");
    MAP("trailing_space", "0 1000 1 \n");
    MAP("blank_between", "0 1000 1\n\n1 1001 1\n");
    MAP("blank_trailing", "0 1000 1\n\n");
    MAP("blank_leading", "\n0 1000 1\n");
    MAP("space_only_line", "0 1000 1\n \n");
    MAP("junk", "0 1000 1 x\n");
    MAP("two_fields", "0 1000\n");
    MAP("one_field", "0\n");
    MAP("empty", "");
    MAP("newline_only", "\n");
    MAP("plus", "+0 1000 1\n");
    MAP("minus", "-0 1000 1\n");
    MAP("hex", "0x10 1000 1\n");
    MAP("glued", "0 1000 1x\n");
    map_case("nul_ends", "0 1000 1\0garbage garbage", 23);
    map_case("nul_after_newline", "0 1000 1\n\0x", 11);
    /* ---- values ---- */
    MAP("wrap_first", "4294967296 1000 1\n");          /* 2^32 -> 0 */
    MAP("wrap_lower", "0 4294968296 1\n");             /* 2^32+1000 -> 1000 */
    MAP("wrap_huge", "18446744073709551621 1000 1\n"); /* 2^64+5 -> 5 */
    MAP("first_minus1", "4294967295 1000 1\n");
    MAP("lower_minus1", "0 4294967295 1\n");
    MAP("count_zero", "0 1000 0\n");
    MAP("first_wraps", "4294967294 1000 2\n");
    MAP("lower_wraps", "0 4294967294 2\n");
    MAP("first_to_end", "4294967294 1000 1\n");
    MAP("lower_to_end", "0 4294967294 1\n");
    MAP("overlap_upper", "0 1000 10\n5 2000 1\n");
    MAP("overlap_lower", "0 1000 10\n100 1005 1\n");
    MAP("overlap_touch", "0 1000 10\n9 5000 1\n");
    MAP("adjacent", "0 1000 10\n10 1010 10\n");
    MAP("duplicate", "0 1000 1\n0 1000 1\n");
    /* ---- size: 340 extents (3630 bytes at these ids, under the page) ---- */
    char *big = malloc(65536);
    size_t bn = 0;
    for (int i = 0; i < 340; i++) bn += (size_t)sprintf(big + bn, "%d %d 1\n", i, 1000 + i);
    map_case("extents_340", big, bn);
    bn = 0;
    for (int i = 0; i < 341; i++) bn += (size_t)sprintf(big + bn, "%d %d 1\n", i, 1000 + i);
    map_case("extents_341", big, bn);
    /* the 341st line empty: no extent, but a line all the same */
    bn = 0;
    for (int i = 0; i < 340; i++) bn += (size_t)sprintf(big + bn, "%d %d 1\n", i, 1000 + i);
    big[bn++] = '\n';
    map_case("extents_340_blank", big, bn);
    /* ---- size: the page. Lines up to near it, the last one padded with
     * trailing whitespace to exactly 4095 bytes; one more byte is EINVAL
     * before the text is looked at, so junk on the first line is not even
     * seen. ---- */
    bn = 0;
    while (bn + 24 < 4095) bn += (size_t)sprintf(big + bn, "%d %d 1\n", (int)bn, 100000 + (int)bn);
    bn--;                                   /* the last newline: after the padding */
    while (bn < 4094) big[bn++] = ' ';
    big[bn++] = '\n';
    map_case("bytes_4095", big, bn);
    big[bn - 1] = ' ';
    big[bn++] = '\n';
    map_case("bytes_4096", big, bn);
    memcpy(big, "junk", 4);
    map_case("bytes_4096_junk", big, bn);
    free(big);
    /* ---- setgroups ---- */
    sg_case("sg_deny", "deny");
    sg_case("sg_allow", "allow");
    sg_case("sg_deny_nl", "deny\n");
    sg_case("sg_allow_nl", "allow\n");
    sg_case("sg_denyx", "denyx");
    sg_case("sg_allowx", "allowx");
    sg_case("sg_deny_ws", "deny \n ");
    sg_case("sg_allow_ws", "allow  ");
    sg_case("sg_deny_junk", "deny  x");
    sg_case("sg_den", "den");
    sg_case("sg_empty", "");
    sg_case("sg_8bytes", "allow\n\n\n");
    sg_case("sg_Deny", "Deny");
    /* ---- order ---- */
    fflush(stdout);
    if (fork() == 0) {
        if (unshare(CLONE_NEWUSER) != 0) _exit(0);
        printf("gid_map: %ld\n", wr("/proc/self/gid_map", "0 1000 1\n", 9));
        printf("allow_after_gid_map: %ld\n", wr("/proc/self/setgroups", "allow", 5));
        printf("deny_after_gid_map: %ld\n", wr("/proc/self/setgroups", "deny", 4));
        printf("gid_map_again: %ld\n", wr("/proc/self/gid_map", "0 1000 1\n", 9));
        printf("gid_map_again_junk: %ld\n", wr("/proc/self/gid_map", "junk", 4));
        char page[4096];
        memset(page, ' ', sizeof page);
        printf("gid_map_again_page: %ld\n", wr("/proc/self/gid_map", page, sizeof page));
        fflush(stdout);
        _exit(0);
    }
    wait(NULL);
    fflush(stdout);
    if (fork() == 0) {
        if (unshare(CLONE_NEWUSER) != 0) _exit(0);
        printf("deny: %ld\n", wr("/proc/self/setgroups", "deny", 4));
        printf("deny_again: %ld\n", wr("/proc/self/setgroups", "deny", 4));
        printf("allow_after_deny: %ld\n", wr("/proc/self/setgroups", "allow", 5));
        printf("allowx_after_deny: %ld\n", wr("/proc/self/setgroups", "allowx", 6));
        char b[64];
        int fd = open("/proc/self/setgroups", O_RDONLY);
        long n = read(fd, b, sizeof b - 1);
        close(fd);
        b[n > 0 ? n : 0] = 0;
        printf("setgroups_back: %s", b);
        printf("gid_map_after_deny: %ld\n", wr("/proc/self/gid_map", "0 1000 1\n", 9));
        fflush(stdout);
        _exit(0);
    }
    wait(NULL);
    /* ---- the registry: a parent writing its child's map, all 340 extents of
     * it, and the child (then a grandchild, which inherits the namespace)
     * reading every one back. The record used to hold 256 bytes of text --
     * seven extents -- and silently kept that many. ---- */
    int up[2], down[2];
    if (pipe(up) || pipe(down)) { printf("pipe failed\n"); return 1; }
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        close(up[0]); close(down[1]);
        if (unshare(CLONE_NEWUSER) != 0) _exit(2);
        char c = 'x';
        if (write(up[1], &c, 1) != 1) _exit(3);
        if (read(down[0], &c, 1) != 1) _exit(4);
        char back[256];
        rd("/proc/self/uid_map", back, sizeof back);
        printf("child_back: %s\n", back);
        fflush(stdout);
        pid_t g = fork();
        if (g == 0) {
            rd("/proc/self/uid_map", back, sizeof back);
            printf("grandchild_back: %s\n", back);
            fflush(stdout);
            _exit(0);
        }
        waitpid(g, NULL, 0);
        _exit(0);
    }
    close(up[1]); close(down[0]);
    char c;
    if (read(up[0], &c, 1) != 1) { printf("handshake failed\n"); return 1; }
    big = malloc(65536);
    bn = 0;
    for (int i = 0; i < 340; i++) bn += (size_t)sprintf(big + bn, "%d %d 1\n", i, 1000 + i);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/uid_map", (int)kid);
    printf("parent_writes_340: %ld\n", wr(path, big, bn));
    printf("parent_writes_again: %ld\n", wr(path, "0 1000 1\n", 9));
    char back[256];
    rd(path, back, sizeof back);
    printf("parent_back: %s\n", back);
    free(big);
    fflush(stdout);
    if (write(down[1], &c, 1) != 1) { printf("handshake failed\n"); return 1; }
    int st = 0;
    waitpid(kid, &st, 0);
    printf("child_status: %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    printf("done\n");
    return 0;
}
