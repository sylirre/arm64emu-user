/* Scalar (D-form) SLI / SRI shift-insert. These 64-bit scalar encodings used to
 * UNDEF/SIGILL in simd_scalar_shift() (the D-form switch had SHL/SSHR/USHR/…
 * but no U=1 opcode 0x0a SLI or 0x08 SRI); the vector forms already existed.
 * Covers the shift extremes: SLI #0 (result = Vn) and #63, SRI #1 and #64
 * (result = Vd). qemu is the oracle; result bits must be byte-identical.
 *
 * The vector block below covers the same extremes per lane width. SRI by the
 * full element width was wrong there for .2d: the kernel shifted a 64-bit lane
 * right by 64 (undefined in C, and on the host a no-op shift), so the source
 * lane was copied where the architecture preserves the destination whole. The
 * narrower widths never showed it — an 8/16/32-bit lane still shifts inside a
 * u64 — which is why only the .2d rows caught it. */
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

/* Vector forms: print both 64-bit halves of the Q register (or the single half
 * of a D-form result) so a wrong lane cannot hide in the other one. */
#define VSRI_Q(fn, ty, ld, st, sh) do {                                       \
    uint64_t nb[2] = { nn[0], nn[1] }, db[2] = { dd[2], dd[3] }, o[2];        \
    ty rn = ld((void *)nb), rd = ld((void *)db);                              \
    st((void *)o, fn(rd, rn, sh));                                            \
    printf(#fn " #%-2d %016llx %016llx\n", sh,                                \
           (unsigned long long)o[0], (unsigned long long)o[1]);               \
} while (0)

#define VSRI_D(fn, ty, ld, st, sh) do {                                       \
    uint64_t nb = nn[0], db = dd[2], o;                                       \
    ty rn = ld((void *)&nb), rd = ld((void *)&db);                            \
    st((void *)&o, fn(rd, rn, sh));                                           \
    printf(#fn " #%-2d %016llx\n", sh, (unsigned long long)o);                \
} while (0)

int main(void) {
    SLI(0, 0); SLI(1, 1); SLI(2, 32); SLI(3, 63);
    SRI(0, 1); SRI(1, 32); SRI(2, 63); SRI(3, 64);

    /* SRI by the element width — the whole destination survives — and by 1,
     * for every lane width in both the 64- and 128-bit forms. */
    VSRI_Q(vsriq_n_u64, uint64x2_t, vld1q_u64, vst1q_u64, 64);
    VSRI_Q(vsriq_n_u64, uint64x2_t, vld1q_u64, vst1q_u64, 1);
    VSRI_Q(vsriq_n_u32, uint32x4_t, vld1q_u32, vst1q_u32, 32);
    VSRI_Q(vsriq_n_u32, uint32x4_t, vld1q_u32, vst1q_u32, 1);
    VSRI_Q(vsriq_n_u16, uint16x8_t, vld1q_u16, vst1q_u16, 16);
    VSRI_Q(vsriq_n_u16, uint16x8_t, vld1q_u16, vst1q_u16, 1);
    VSRI_Q(vsriq_n_u8,  uint8x16_t, vld1q_u8,  vst1q_u8,  8);
    VSRI_Q(vsriq_n_u8,  uint8x16_t, vld1q_u8,  vst1q_u8,  1);
    VSRI_D(vsri_n_u32, uint32x2_t, vld1_u32, vst1_u32, 32);
    VSRI_D(vsri_n_u16, uint16x4_t, vld1_u16, vst1_u16, 16);
    VSRI_D(vsri_n_u8,  uint8x8_t,  vld1_u8,  vst1_u8,  8);

    /* SLI by 0 (result = Vn) and by width-1, the mirror extremes. */
    VSRI_Q(vsliq_n_u64, uint64x2_t, vld1q_u64, vst1q_u64, 0);
    VSRI_Q(vsliq_n_u64, uint64x2_t, vld1q_u64, vst1q_u64, 63);
    VSRI_Q(vsliq_n_u32, uint32x4_t, vld1q_u32, vst1q_u32, 31);
    VSRI_Q(vsliq_n_u16, uint16x8_t, vld1q_u16, vst1q_u16, 15);
    VSRI_Q(vsliq_n_u8,  uint8x16_t, vld1q_u8,  vst1q_u8,  7);
    VSRI_D(vsli_n_u8,   uint8x8_t,  vld1_u8,   vst1_u8,   0);
    return 0;
}
