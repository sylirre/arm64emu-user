/* Scalar (D-form) SLI / SRI shift-insert. These 64-bit scalar encodings used to
 * UNDEF/SIGILL in simd_scalar_shift() (the D-form switch had SHL/SSHR/USHR/…
 * but no U=1 opcode 0x0a SLI or 0x08 SRI); the vector forms already existed.
 * Covers the shift extremes: SLI #0 (result = Vn) and #63, SRI #1 and #64
 * (result = Vd). qemu is the oracle; result bits must be byte-identical. */
#include <stdio.h>
#include <stdint.h>
#include <arm_neon.h>

static volatile uint64_t nn[4] = { 0xfedcba9876543210ULL, 0x0000000000000001ULL,
                                   0xffffffffffffffffULL, 0x8000000000000001ULL };
static volatile uint64_t dd[4] = { 0x1111111111111111ULL, 0xaaaaaaaaaaaaaaaaULL,
                                   0x0123456789abcdefULL, 0xdeadbeefcafebabeULL };

#define SLI(i, sh) do {                                                       \
    uint64_t nb = nn[i], db = dd[i], o;                                       \
    int64x1_t rn = vreinterpret_s64_u64(vld1_u64(&nb));                       \
    int64x1_t rd = vreinterpret_s64_u64(vld1_u64(&db));                       \
    vst1_u64(&o, vreinterpret_u64_s64(vsli_n_s64(rd, rn, sh)));               \
    printf("sli  #%-2d %016llx\n", sh, (unsigned long long)o);                \
} while (0)

#define SRI(i, sh) do {                                                       \
    uint64_t nb = nn[i], db = dd[i], o;                                       \
    int64x1_t rn = vreinterpret_s64_u64(vld1_u64(&nb));                       \
    int64x1_t rd = vreinterpret_s64_u64(vld1_u64(&db));                       \
    vst1_u64(&o, vreinterpret_u64_s64(vsri_n_s64(rd, rn, sh)));               \
    printf("sri  #%-2d %016llx\n", sh, (unsigned long long)o);                \
} while (0)

int main(void) {
    SLI(0, 0); SLI(1, 1); SLI(2, 32); SLI(3, 63);
    SRI(0, 1); SRI(1, 32); SRI(2, 63); SRI(3, 64);
    return 0;
}
