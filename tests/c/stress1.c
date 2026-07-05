#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
static int cmp(const void *a, const void *b) { return *(const int*)a - *(const int*)b; }
int main(void) {
    // malloc/qsort stress
    int n = 50000;
    int *v = malloc(n * sizeof 0[v]);
    unsigned seed = 12345;
    for (int i = 0; i < n; i++) { seed = seed * 1103515245 + 12345; v[i] = (int)(seed >> 16) % 1000; }
    qsort(v, n, sizeof *v, cmp);
    long sum = 0; for (int i = 0; i < n; i++) sum += v[i] * (long)(i % 7);
    printf("qsort sum=%ld first=%d last=%d\n", sum, v[0], v[n-1]);
    // FP
    double x = 0;
    for (int i = 1; i <= 1000; i++) x += sqrt((double)i) * sin(i * 0.01);
    printf("fp=%.6f\n", x);
    printf("fmt=%g %e %.3f\n", 3.14159, 12345.6789, 2.0/3.0);
    // string ops (SIMD memcpy/strlen paths)
    char buf[8192]; memset(buf, 'a', sizeof buf - 1); buf[sizeof buf - 1] = 0;
    printf("strlen=%zu\n", strlen(buf));
    char *dup = strdup(buf); printf("memcmp=%d\n", memcmp(dup, buf, sizeof buf));
    free(dup); free(v);
    return 0;
}
