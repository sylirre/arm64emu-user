/* /proc/self synthesis, differential half: qemu-user also fakes cmdline (guest
 * argv) and maps (guest view with [stack]), so these properties must match the
 * oracle exactly. The rootfs-dependent /proc files (mounts, magic links) are
 * covered by the self-checking fixture instead. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    char buf[4096];
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) { puts("no cmdline"); return 1; }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) { puts("empty cmdline"); return 1; }
    buf[n] = 0;
    int args = 0;
    for (ssize_t off = 0; off < n; off += (ssize_t)strlen(buf + off) + 1) {
        printf("arg%d=%s\n", args, buf + off);
        args++;
    }
    printf("args=%d trailing_nul=%d\n", args, buf[n - 1] == 0);

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { puts("no maps"); return 1; }
    int have_stack = 0, have_rx = 0;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "[stack]")) have_stack = 1;
        if (strstr(line, " r-xp ")) have_rx = 1;
    }
    fclose(f);
    printf("stack=%d rx=%d\n", have_stack, have_rx);
    return 0;
}
