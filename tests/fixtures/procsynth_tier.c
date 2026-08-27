/* The synthesized /proc must fail CLOSED (self-checking; qemu-user has no
 * synthesized /proc at all, so it cannot be the oracle).
 *
 * Every per-process file under /proc that the emulator synthesizes is served
 * from an anonymous fd (a memfd, or an unlinked temp file where the host has no
 * memfd_create). A host with neither -- forced here with
 * A64_PROCSYNTH_FORCE_FAIL -- used to make each of those opens fall through to
 * the HOST file, which describes the emulator: /proc/self/environ handed the
 * guest the emulator's whole environment, cmdline its command line, mounts the
 * host mount table, maps its address space. They are denied instead.
 *
 * The host-global views (version, uptime) are the exception on purpose: they
 * carry no guest state, so the host's own answer is the truthful one and still
 * passes through. The run stamps SECRET into the emulator's environment, so a
 * leak of it through any file that IS served is unmistakable. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int leaked;

static const char *probe(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? "ENOENT" : "err";
    static char b[65536];
    size_t n = 0;
    ssize_t r;
    while (n < sizeof b - 1 && (r = read(fd, b + n, sizeof b - 1 - n)) > 0)
        n += (size_t)r;
    close(fd);
    b[n] = 0;
    for (size_t i = 0; i + 1 < n; i++)      /* NUL-joined files too */
        if (!b[i]) b[i] = '\n';
    if (strstr(b, "emulator-only")) leaked = 1;
    return "served";
}

int main(void) {
    static const char *self[] = {
        "/proc/self/environ", "/proc/self/cmdline", "/proc/self/auxv",
        "/proc/self/maps", "/proc/self/mounts", "/proc/self/mountinfo",
        "/proc/self/limits", "/proc/self/status",
    };
    for (unsigned i = 0; i < sizeof self / sizeof self[0]; i++)
        printf("%s=%s\n", strrchr(self[i], '/') + 1, probe(self[i]));
    printf("version=%s\n", probe("/proc/version"));
    printf("uptime=%s\n", probe("/proc/uptime"));
    printf("leak=%d\n", leaked);
    printf("done\n");
    return 0;
}
