/* /proc/cpuinfo is an arm64 kernel's for the CPU this emulator is, not the
 * host's file: one block per online host CPU, a Features line spelled from
 * the same HWCAP words the auxv carries (so a program that reads the one
 * never runs an instruction the other did not promise), the MIDR fields the
 * MIDR_EL1 register reads as, and no "model name" line (an arm64 kernel
 * prints none). The host's file used to pass through -- "GenuineIntel" and
 * x86 flags on an x86 host. Self-checking: every row is a relation between
 * the file, getauxval and the machine; qemu-user synthesizes a file of its
 * own with a model name line and its own feature list. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

static const char *const hw1[] = {
    "fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32",
    "atomics", "fphp", "asimdhp", "cpuid", "asimdrdm", "jscvt", "fcma", "lrcpc",
    "dcpop", "sha3", "sm3", "sm4", "asimddp", "sha512", "sve", "asimdfhm",
    "dit", "uscat", "ilrcpc", "flagm", "ssbs", "sb", "paca", "pacg",
};
static const char *const hw2[] = {
    "dcpodp", "sve2", "sveaes", "svepmull", "svebitperm", "svesha3", "svesm4",
    "flagm2", "frint", "svei8mm", "svef32mm", "svef64mm", "svebf16", "i8mm",
    "bf16", "dgh", "rng", "bti", "mte", "ecv", "afp", "rpres", "mte3", "sme",
    "smei16i64", "smef64f64", "smei8i32", "smef16f32", "smeb16f32",
    "smef32f32", "smefa64", "wfxt", "ebf16", "sveebf16", "cssc", "rprfm",
    "sve2p1", "sme2", "sme2p1", "smei16i32", "smebi32i32", "smeb16b16",
    "smef16f16", "mops", "hbc",
};

int main(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) { printf("SKIP: no /proc/cpuinfo\n"); return 0; }
    unsigned long hwcap = getauxval(AT_HWCAP), hwcap2 = getauxval(AT_HWCAP2);
    char line[4096];
    int blocks = 0, model_name = 0, features_lines = 0, features_ok = 1;
    int impl_ok = 1, arch_ok = 1, part_ok = 1, seq_ok = 1, last = -1;
    char *feat = NULL;
    while (fgets(line, sizeof line, f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        if (!strncmp(line, "processor", 9)) {
            int id = atoi(strchr(line, ':') + 1);
            if (id <= last) seq_ok = 0;
            last = id;
            blocks++;
        } else if (!strncmp(line, "model name", 10)) model_name = 1;
        else if (!strncmp(line, "Features", 8)) {
            features_lines++;
            if (!feat) feat = strdup(strchr(line, ':') + 1);
            /* Every name listed is a bit set; every bit set is a name listed. */
            char *copy = strdup(strchr(line, ':') + 1);
            unsigned long seen1 = 0, seen2 = 0;
            for (char *tok = strtok(copy, " "); tok; tok = strtok(NULL, " ")) {
                int found = 0;
                for (unsigned b = 0; b < sizeof hw1 / sizeof *hw1; b++)
                    if (!strcmp(tok, hw1[b])) { found = 1; seen1 |= 1UL << b; if (!(hwcap & (1UL << b))) features_ok = 0; }
                for (unsigned b = 0; b < sizeof hw2 / sizeof *hw2; b++)
                    if (!strcmp(tok, hw2[b])) { found = 1; seen2 |= 1UL << b; if (!(hwcap2 & (1UL << b))) features_ok = 0; }
                if (!found) features_ok = 0;
            }
            if ((hwcap & ((1UL << (sizeof hw1 / sizeof *hw1)) - 1)) != seen1) features_ok = 0;
            if ((hwcap2 & ((1UL << (sizeof hw2 / sizeof *hw2)) - 1)) != seen2) features_ok = 0;
            free(copy);
        } else if (!strncmp(line, "CPU implementer", 15)) {
            if (strtoul(strchr(line, ':') + 1, NULL, 16) != 0x41) impl_ok = 0;
        } else if (!strncmp(line, "CPU architecture", 16)) {
            if (atoi(strchr(line, ':') + 1) != 8) arch_ok = 0;
        } else if (!strncmp(line, "CPU part", 8)) {
            if (strtoul(strchr(line, ':') + 1, NULL, 16) != 0xd07) part_ok = 0;
        }
    }
    fclose(f);
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    printf("blocks_eq_online=%d\n", blocks == online);
    printf("one_features_per_block=%d\n", features_lines == blocks);
    printf("features_are_hwcap=%d\n", features_ok);
    printf("has_atomics=%d has_fphp=%d has_mops=%d\n",
           feat && strstr(feat, " atomics") != NULL, feat && strstr(feat, " fphp") != NULL,
           feat && strstr(feat, " mops") != NULL);
    printf("no_x86=%d\n", !(feat && (strstr(feat, "sse") || strstr(feat, "avx"))));
    printf("no_model_name=%d\n", !model_name);
    printf("midr_ok=%d\n", impl_ok && arch_ok && part_ok);
    printf("ids_ascending=%d\n", seq_ok);
    printf("done\n");
    return 0;
}
