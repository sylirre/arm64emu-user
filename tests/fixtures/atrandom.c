/* AT_RANDOM: the sixteen bytes the kernel puts on the initial stack for the
 * guest libc to build its stack canary and pointer guard from. They have to be
 * unpredictable -- the emulator used to fall back to a fixed pattern whenever
 * the host's getrandom(2) was missing or filtered, which handed every guest on
 * such a host the same canary.
 *
 * This prints them; run_tests.sh runs the program several times and requires
 * every run to differ (and none of them to be the old constant). Also prints
 * whether the pointer is where a kernel puts it -- inside the initial stack,
 * above the current SP -- since a canary read from somewhere else is not a
 * canary either. */
#include <stdio.h>
#include <elf.h>
#include <link.h>

extern char **environ;

int main(int argc, char **argv) {
    (void)argc;
    /* Walk past argv[] and envp[] to the auxv the loader left above them. */
    char **e = environ;
    while (*e) e++;
    Elf64_auxv_t *av = (Elf64_auxv_t *)(e + 1);
    unsigned char *rnd = 0;
    for (; av->a_type != AT_NULL; av++)
        if (av->a_type == AT_RANDOM) rnd = (unsigned char *)av->a_un.a_val;
    if (!rnd) { printf("no AT_RANDOM\n"); return 1; }
    for (int i = 0; i < 16; i++) printf("%02x", rnd[i]);
    printf("\n");
    /* The block belongs to the process stack: above this frame, and within a
     * megabyte of it (the kernel places it just under the argv strings). */
    unsigned long here = (unsigned long)&av;
    unsigned long at = (unsigned long)rnd;
    printf("onstack=%d\n", at > here && at - here < (1UL << 20));
    (void)argv;
    return 0;
}
