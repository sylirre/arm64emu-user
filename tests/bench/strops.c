/* Benchmark kernel: glibc string/memory routines over a 1 MiB working set.
 * strlen/memchr/strcmp run the CMEQ-#0 / SHRN / UMINV vector idioms and LD1
 * block loads; memset >256B goes through DC ZVA; memcpy is LDP/STP Q pairs.
 * Deterministic output for the runner's cross-engine check. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    enum { N = 1 << 20 };
    char *buf = malloc(N + 64), *dst = malloc(N + 64);
    if (!buf || !dst) return 1;
    unsigned long long s = 88172645463325252ULL, h = 1234567;
    for (int i = 0; i < N; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        buf[i] = (char)(s | 1);                  /* non-zero bytes */
    }
    for (int i = 1; i < N; i += 4096) buf[i + (i % 63)] = 0;
    buf[N] = 0;

    for (int it = 0; it < 200; it++) {
        size_t off = (size_t)(it * 977) & 0xfff;
        const char *p = buf + off;
        while (p < buf + N) {                    /* strlen sweep */
            size_t l = strlen(p);
            h += l;
            p += l + 1;
        }
        const char *q = memchr(buf, 0x5a, N);
        h ^= (unsigned long long)(q ? (size_t)(q - buf) : 0);
        h += (unsigned)strcmp(buf + off, buf + off + 4096);
        memset(dst, it & 0xff, N);               /* DC ZVA path */
        memcpy(dst, buf, N >> 1);                /* LDP/STP Q pairs */
        h ^= (unsigned char)dst[(size_t)(it * 131071) & (N - 1)];
    }
    printf("strops h=%llx\n", h);
    return 0;
}
