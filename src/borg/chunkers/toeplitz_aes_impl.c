/* toeplitz-aes chunker scan kernel, see toeplitz_aes_impl.h and
 * toeplitz_aes.pyx. Mirrors rabin_aes_impl.c / goldilocks_aes_impl.c; only
 * the rolling arithmetic differs (tabulated LFSR/Toeplitz hash over
 * GF(2)[x] mod a fixed public P). */

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "toeplitz_aes_impl.h"

/* low 64 bits of the fixed public irreducible P = x^64 + x^4 + x^3 + x + 1
 * (the x^64 coefficient is implicit). Public: the secrecy lives in T. */
#define TP_PLO 0x1BULL

struct TP_CTX {
    /* rolling tables; in0_tbl is the secret random table T itself, the other
     * three are algebraic combinations of T and P (see toeplitz_aes_impl.h).
     * All indices used in the scan are plaintext bytes, so no load ever sits
     * on the serial digest dependency chain (unlike rabin-aes, whose
     * reduction lookup is indexed by digest bits). */
    uint64_t in0_tbl[256];   /* T[b] (incoming byte, newest) */
    uint64_t in1_tbl[256];   /* x    * T[b] mod P (stride-2, older incoming) */
    uint64_t out64_tbl[256]; /* x^64 * T[b] mod P (single-step removal) */
    uint64_t out65_tbl[256]; /* x^65 * T[b] mod P (stride-2 removal, older) */
    uint8_t rk[11][16];      /* AES-128 round keys, for the hardware paths */
    EVP_CIPHER_CTX *evp;
    int use_hw;
};

/* --- portable helpers ------------------------------------------------- */

static inline void store_le64(uint8_t *b, uint64_t v)
{
    for (int j = 0; j < 8; j++)
        b[j] = (uint8_t)(v >> (8 * j));
}

static inline uint64_t load_le64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int j = 0; j < 8; j++)
        v |= ((uint64_t)b[j]) << (8 * j);
    return v;
}

/* --- GF(2)[x] mod P rolling ------------------------------------------- */

/* d * x mod P: shift out the degree-63 coefficient and, if it was set, add
 * back x^64 = P_LO. Branchless: the arithmetic right shift smears the top
 * bit into a full mask. */
static inline uint64_t tp_mulx(uint64_t d)
{
    return (d << 1) ^ (((uint64_t)((int64_t)d >> 63)) & TP_PLO);
}

/* d * x^2 mod P: same for the top two coefficients (x^65 = x * P_LO, which
 * has degree 5, so no second-order reduction is needed). */
static inline uint64_t tp_mulx2(uint64_t d)
{
    return (d << 2) ^ (((uint64_t)((int64_t)d >> 63)) & (TP_PLO << 1)) ^
           (((uint64_t)((int64_t)(d << 1) >> 63)) & TP_PLO);
}

/* Advance the digest by one byte. The digest is the window's Toeplitz hash
 * d = sum_j x^(63-j) * T[b_j] (oldest byte at x^63, newest at x^0), so
 *   d' = d*x ^ x^64*T[byte_out] ^ T[byte_in]   (mod P).
 * Both table terms are plaintext-indexed and combine off the critical path;
 * the serial chain is just tp_mulx (shift + masked XOR). */
static inline uint64_t tp_roll(const TP_CTX *c, uint64_t d, uint8_t byte_out, uint8_t byte_in)
{
    return tp_mulx(d) ^ c->out64_tbl[byte_out] ^ c->in0_tbl[byte_in];
}

/* Advance the digest by TWO bytes in one step (exact composition of two
 * tp_roll steps, expanded using linearity over GF(2)):
 *   d' = d*x^2 ^ o0*x^65*T ^ o1*x^64*T ^ i0*x*T ^ i1*T   (mod P)
 * where (o0, i0) belong to the first composed step and (o1, i1) to the second.
 * Used to run two independent even/odd lanes; bit-identical to tp_roll twice. */
static inline uint64_t tp_roll2(const TP_CTX *c, uint64_t d,
                                uint8_t o0, uint8_t o1, uint8_t i0, uint8_t i1)
{
    uint64_t delta = c->out65_tbl[o0] ^ c->out64_tbl[o1] ^ c->in1_tbl[i0] ^ c->in0_tbl[i1];
    return tp_mulx2(d) ^ delta;
}

uint64_t tp_digest64(const TP_CTX *c, const uint8_t *q)
{
    uint64_t d = 0;
    for (int j = 0; j < 64; j++)
        d = tp_mulx(d) ^ c->in0_tbl[q[j]];
    return d;
}

/* --- AES-128 key expansion (encryption-only, standard FIPS-197) -------- */

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static void aes128_expand(const uint8_t key[16], uint8_t rk[11][16])
{
    uint8_t rcon = 1;
    memcpy(rk[0], key, 16);
    for (int i = 1; i <= 10; i++) {
        rk[i][0] = (uint8_t)(rk[i - 1][0] ^ sbox[rk[i - 1][13]] ^ rcon);
        rk[i][1] = (uint8_t)(rk[i - 1][1] ^ sbox[rk[i - 1][14]]);
        rk[i][2] = (uint8_t)(rk[i - 1][2] ^ sbox[rk[i - 1][15]]);
        rk[i][3] = (uint8_t)(rk[i - 1][3] ^ sbox[rk[i - 1][12]]);
        for (int j = 4; j < 16; j++)
            rk[i][j] = (uint8_t)(rk[i - 1][j] ^ rk[i][j - 4]);
        rcon = (uint8_t)((rcon << 1) ^ ((rcon >> 7) * 0x1b));
    }
}

/* --- two-lane digest fill (shared by the portable path) ----------------- */

/* Compute the digests for positions [0, m), writing each as an AES input
 * block (digest LE in bytes 0..7; bytes 8..15 must already be zero) into inb.
 * On entry *d_io is the digest at position -1; on return, at position m-1.
 * Uses two independent even/odd lanes advancing with stride 2 so the two
 * dependency chains overlap; bit-identical to m single tp_roll steps. */
static inline void tp_fill2(const TP_CTX *c, const uint8_t *q, const uint8_t *qo,
                            size_t m, uint64_t *d_io, uint8_t *inb)
{
    uint64_t d = *d_io, da, db;
    size_t i;

    if (m == 1) {
        d = tp_roll(c, d, qo[0], q[0]);
        store_le64(inb, d);
        *d_io = d;
        return;
    }
    db = tp_roll(c, d, qo[0], q[0]);                /* even lane: d_0 */
    da = tp_roll2(c, d, qo[0], qo[1], q[0], q[1]);  /* odd lane:  d_1 */
    store_le64(inb, db);
    store_le64(inb + 16, da);
    for (i = 2; i + 1 < m; i += 2) {
        db = tp_roll2(c, db, qo[i - 1], qo[i], q[i - 1], q[i]);
        da = tp_roll2(c, da, qo[i], qo[i + 1], q[i], q[i + 1]);
        store_le64(inb + i * 16, db);
        store_le64(inb + (i + 1) * 16, da);
    }
    if (i < m) { /* odd m: one even-lane step left for position m-1 */
        db = tp_roll2(c, db, qo[i - 1], qo[i], q[i - 1], q[i]);
        store_le64(inb + i * 16, db);
        *d_io = db;
    } else {
        *d_io = da;
    }
}

/* --- portable path: batched AES via OpenSSL EVP ------------------------ */

/* sub-batch size (blocks); 512 * 16 B = 8 KiB in/out buffers on the stack */
#define TP_SB 512

static int64_t tp_scan_evp(TP_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint8_t inb[TP_SB * 16];
    uint8_t outb[TP_SB * 16];
    uint64_t d = *digest;
    size_t base = 0;
    int outlen;

    memset(inb, 0, sizeof(inb)); /* bytes 8..15 of each block stay zero */
    while (base < n) {
        const uint8_t *q = p + base;
        size_t m = n - base;
        if (m > TP_SB)
            m = TP_SB;
        tp_fill2(c, q, q - 64, m, &d, inb);
        outlen = 0;
        if (!EVP_EncryptUpdate(c->evp, outb, &outlen, inb, (int)(m * 16)) || outlen != (int)(m * 16))
            return -2; /* OpenSSL failure; caller raises */
        for (size_t i = 0; i < m; i++) {
            if ((load_le64(outb + i * 16) & mask) == 0) {
                /* recompute the digest at the cut position (cheaper than
                 * storing all digests: one 64-byte warm-up per chunk) */
                *digest = tp_digest64(c, q + i - 63);
                return (int64_t)(base + i);
            }
        }
        base += m;
    }
    *digest = d;
    return -1;
}

/* --- hardware paths ----------------------------------------------------
 *
 * Both hardware paths process groups of 8 positions: the two rolling lanes
 * advance 4 stride-2 steps each (two independent shift/xor chains), then the
 * 8 digests are encrypted with interleaved AES instructions, which execute
 * on different ports than the table loads and thus overlap with the next
 * group's rolling work.
 *
 * Loop invariant: entering a group at position i, db = digest at i and
 * da = digest at i+1 (both already computed); the group emits digests for
 * i..i+7 and prepares db/da for i+8/i+9 (reading bytes up to q[i+9], hence
 * the i + 10 <= n loop bound). */

#if defined(__aarch64__) && defined(__ARM_FEATURE_AES)
#define TP_HAVE_HW 1
#define TP_KIND_HW "aes-arm64"

#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#endif

static int tp_hw_available(void)
{
#if defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
    return 1; /* compiler targeted +aes; on Apple Silicon it is always there */
#endif
}

static inline uint8x16_t tp_aes1_neon(const uint8x16_t k[11], uint8x16_t b)
{
    for (int r = 0; r < 9; r++)
        b = vaesmcq_u8(vaeseq_u8(b, k[r]));
    return veorq_u8(vaeseq_u8(b, k[9]), k[10]);
}

static int64_t tp_scan_hw(TP_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint8x16_t k[11];
    uint64_t d = *digest, da, db;
    const uint8_t *qo = p - 64;
    size_t i = 0;
    int lanes_live = 0;

    for (int j = 0; j < 11; j++)
        k[j] = vld1q_u8(c->rk[j]);

    if (n >= 10) {
        db = tp_roll(c, d, qo[0], p[0]);               /* d_0 */
        da = tp_roll2(c, d, qo[0], qo[1], p[0], p[1]); /* d_1 */
        lanes_live = 1;
    }

    while (lanes_live && i + 10 <= n) {
        uint64_t dg[8];
        uint8x16_t b0, b1, b2, b3, b4, b5, b6, b7;

        dg[0] = db;
        dg[1] = da;
        db = tp_roll2(c, db, qo[i + 1], qo[i + 2], p[i + 1], p[i + 2]); dg[2] = db;
        da = tp_roll2(c, da, qo[i + 2], qo[i + 3], p[i + 2], p[i + 3]); dg[3] = da;
        db = tp_roll2(c, db, qo[i + 3], qo[i + 4], p[i + 3], p[i + 4]); dg[4] = db;
        da = tp_roll2(c, da, qo[i + 4], qo[i + 5], p[i + 4], p[i + 5]); dg[5] = da;
        db = tp_roll2(c, db, qo[i + 5], qo[i + 6], p[i + 5], p[i + 6]); dg[6] = db;
        da = tp_roll2(c, da, qo[i + 6], qo[i + 7], p[i + 6], p[i + 7]); dg[7] = da;
        /* prepare the next group's invariant (digests at i+8, i+9) */
        db = tp_roll2(c, db, qo[i + 7], qo[i + 8], p[i + 7], p[i + 8]);
        da = tp_roll2(c, da, qo[i + 8], qo[i + 9], p[i + 8], p[i + 9]);

        b0 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[0]), vcreate_u64(0)));
        b1 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[1]), vcreate_u64(0)));
        b2 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[2]), vcreate_u64(0)));
        b3 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[3]), vcreate_u64(0)));
        b4 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[4]), vcreate_u64(0)));
        b5 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[5]), vcreate_u64(0)));
        b6 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[6]), vcreate_u64(0)));
        b7 = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(dg[7]), vcreate_u64(0)));
        for (int r = 0; r < 9; r++) {
            b0 = vaesmcq_u8(vaeseq_u8(b0, k[r]));
            b1 = vaesmcq_u8(vaeseq_u8(b1, k[r]));
            b2 = vaesmcq_u8(vaeseq_u8(b2, k[r]));
            b3 = vaesmcq_u8(vaeseq_u8(b3, k[r]));
            b4 = vaesmcq_u8(vaeseq_u8(b4, k[r]));
            b5 = vaesmcq_u8(vaeseq_u8(b5, k[r]));
            b6 = vaesmcq_u8(vaeseq_u8(b6, k[r]));
            b7 = vaesmcq_u8(vaeseq_u8(b7, k[r]));
        }
        b0 = veorq_u8(vaeseq_u8(b0, k[9]), k[10]);
        b1 = veorq_u8(vaeseq_u8(b1, k[9]), k[10]);
        b2 = veorq_u8(vaeseq_u8(b2, k[9]), k[10]);
        b3 = veorq_u8(vaeseq_u8(b3, k[9]), k[10]);
        b4 = veorq_u8(vaeseq_u8(b4, k[9]), k[10]);
        b5 = veorq_u8(vaeseq_u8(b5, k[9]), k[10]);
        b6 = veorq_u8(vaeseq_u8(b6, k[9]), k[10]);
        b7 = veorq_u8(vaeseq_u8(b7, k[9]), k[10]);

        {
            uint64_t c0 = vgetq_lane_u64(vreinterpretq_u64_u8(b0), 0);
            uint64_t c1 = vgetq_lane_u64(vreinterpretq_u64_u8(b1), 0);
            uint64_t c2 = vgetq_lane_u64(vreinterpretq_u64_u8(b2), 0);
            uint64_t c3 = vgetq_lane_u64(vreinterpretq_u64_u8(b3), 0);
            uint64_t c4 = vgetq_lane_u64(vreinterpretq_u64_u8(b4), 0);
            uint64_t c5 = vgetq_lane_u64(vreinterpretq_u64_u8(b5), 0);
            uint64_t c6 = vgetq_lane_u64(vreinterpretq_u64_u8(b6), 0);
            uint64_t c7 = vgetq_lane_u64(vreinterpretq_u64_u8(b7), 0);
            if ((((c0 & mask) == 0) | ((c1 & mask) == 0) | ((c2 & mask) == 0) | ((c3 & mask) == 0) |
                 ((c4 & mask) == 0) | ((c5 & mask) == 0) | ((c6 & mask) == 0) | ((c7 & mask) == 0))) {
                uint64_t cs[8] = {c0, c1, c2, c3, c4, c5, c6, c7};
                for (int j = 0; j < 8; j++) {
                    if ((cs[j] & mask) == 0) {
                        *digest = dg[j];
                        return (int64_t)(i + j);
                    }
                }
            }
        }
        i += 8;
    }
    /* tail: single positions. If the lanes ran, db already is the digest at
     * position i; check it first, then continue with single-step rolls. */
    if (lanes_live && i < n) {
        uint8x16_t b = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(db), vcreate_u64(0)));
        b = tp_aes1_neon(k, b);
        if ((vgetq_lane_u64(vreinterpretq_u64_u8(b), 0) & mask) == 0) {
            *digest = db;
            return (int64_t)i;
        }
        d = db;
        i++;
    }
    while (i < n) {
        uint8x16_t b;
        d = tp_roll(c, d, qo[i], p[i]);
        b = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(d), vcreate_u64(0)));
        b = tp_aes1_neon(k, b);
        if ((vgetq_lane_u64(vreinterpretq_u64_u8(b), 0) & mask) == 0) {
            *digest = d;
            return (int64_t)i;
        }
        i++;
    }
    *digest = d;
    return -1;
}

#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#define TP_HAVE_HW 1
#define TP_KIND_HW "aes-ni"

#include <immintrin.h>

static int tp_hw_available(void)
{
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse2");
}

__attribute__((target("aes,sse2"))) static inline __m128i
tp_aes1_ni(const uint8_t rk[11][16], __m128i b)
{
    b = _mm_xor_si128(b, _mm_loadu_si128((const __m128i *)rk[0]));
    for (int r = 1; r < 10; r++)
        b = _mm_aesenc_si128(b, _mm_loadu_si128((const __m128i *)rk[r]));
    return _mm_aesenclast_si128(b, _mm_loadu_si128((const __m128i *)rk[10]));
}

__attribute__((target("aes,sse2"))) static int64_t
tp_scan_hw(TP_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint64_t d = *digest, da, db;
    const uint8_t *qo = p - 64;
    size_t i = 0;
    int lanes_live = 0;

    if (n >= 10) {
        db = tp_roll(c, d, qo[0], p[0]);               /* d_0 */
        da = tp_roll2(c, d, qo[0], qo[1], p[0], p[1]); /* d_1 */
        lanes_live = 1;
    }

    while (lanes_live && i + 10 <= n) {
        uint64_t dg[8];
        __m128i b0, b1, b2, b3, b4, b5, b6, b7, kr;

        dg[0] = db;
        dg[1] = da;
        db = tp_roll2(c, db, qo[i + 1], qo[i + 2], p[i + 1], p[i + 2]); dg[2] = db;
        da = tp_roll2(c, da, qo[i + 2], qo[i + 3], p[i + 2], p[i + 3]); dg[3] = da;
        db = tp_roll2(c, db, qo[i + 3], qo[i + 4], p[i + 3], p[i + 4]); dg[4] = db;
        da = tp_roll2(c, da, qo[i + 4], qo[i + 5], p[i + 4], p[i + 5]); dg[5] = da;
        db = tp_roll2(c, db, qo[i + 5], qo[i + 6], p[i + 5], p[i + 6]); dg[6] = db;
        da = tp_roll2(c, da, qo[i + 6], qo[i + 7], p[i + 6], p[i + 7]); dg[7] = da;
        db = tp_roll2(c, db, qo[i + 7], qo[i + 8], p[i + 7], p[i + 8]);
        da = tp_roll2(c, da, qo[i + 8], qo[i + 9], p[i + 8], p[i + 9]);

        /* 8 blocks in flight; round keys are re-loaded per round (they stay
         * hot in L1) to keep register pressure within the 16 XMM registers */
        kr = _mm_loadu_si128((const __m128i *)c->rk[0]);
        b0 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[0]), kr);
        b1 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[1]), kr);
        b2 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[2]), kr);
        b3 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[3]), kr);
        b4 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[4]), kr);
        b5 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[5]), kr);
        b6 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[6]), kr);
        b7 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[7]), kr);
        for (int r = 1; r < 10; r++) {
            kr = _mm_loadu_si128((const __m128i *)c->rk[r]);
            b0 = _mm_aesenc_si128(b0, kr);
            b1 = _mm_aesenc_si128(b1, kr);
            b2 = _mm_aesenc_si128(b2, kr);
            b3 = _mm_aesenc_si128(b3, kr);
            b4 = _mm_aesenc_si128(b4, kr);
            b5 = _mm_aesenc_si128(b5, kr);
            b6 = _mm_aesenc_si128(b6, kr);
            b7 = _mm_aesenc_si128(b7, kr);
        }
        kr = _mm_loadu_si128((const __m128i *)c->rk[10]);
        b0 = _mm_aesenclast_si128(b0, kr);
        b1 = _mm_aesenclast_si128(b1, kr);
        b2 = _mm_aesenclast_si128(b2, kr);
        b3 = _mm_aesenclast_si128(b3, kr);
        b4 = _mm_aesenclast_si128(b4, kr);
        b5 = _mm_aesenclast_si128(b5, kr);
        b6 = _mm_aesenclast_si128(b6, kr);
        b7 = _mm_aesenclast_si128(b7, kr);

        {
            uint64_t cs[8];
            cs[0] = (uint64_t)_mm_cvtsi128_si64(b0);
            cs[1] = (uint64_t)_mm_cvtsi128_si64(b1);
            cs[2] = (uint64_t)_mm_cvtsi128_si64(b2);
            cs[3] = (uint64_t)_mm_cvtsi128_si64(b3);
            cs[4] = (uint64_t)_mm_cvtsi128_si64(b4);
            cs[5] = (uint64_t)_mm_cvtsi128_si64(b5);
            cs[6] = (uint64_t)_mm_cvtsi128_si64(b6);
            cs[7] = (uint64_t)_mm_cvtsi128_si64(b7);
            for (int j = 0; j < 8; j++) {
                if ((cs[j] & mask) == 0) {
                    *digest = dg[j];
                    return (int64_t)(i + j);
                }
            }
        }
        i += 8;
    }
    if (lanes_live && i < n) {
        __m128i b = tp_aes1_ni(c->rk, _mm_set_epi64x(0, (long long)db));
        if (((uint64_t)_mm_cvtsi128_si64(b) & mask) == 0) {
            *digest = db;
            return (int64_t)i;
        }
        d = db;
        i++;
    }
    while (i < n) {
        __m128i b;
        d = tp_roll(c, d, qo[i], p[i]);
        b = tp_aes1_ni(c->rk, _mm_set_epi64x(0, (long long)d));
        if (((uint64_t)_mm_cvtsi128_si64(b) & mask) == 0) {
            *digest = d;
            return (int64_t)i;
        }
        i++;
    }
    *digest = d;
    return -1;
}

#else
#define TP_HAVE_HW 0
#endif

/* --- context management and dispatch ----------------------------------- */

TP_CTX *tp_new(const uint64_t tables[TP_TABLES * 256], const uint8_t aes_key[16], int force_sw)
{
    TP_CTX *c = calloc(1, sizeof(TP_CTX));
    if (c == NULL)
        return NULL;
    memcpy(c->in0_tbl, tables + 0 * 256, sizeof(c->in0_tbl));
    memcpy(c->in1_tbl, tables + 1 * 256, sizeof(c->in1_tbl));
    memcpy(c->out64_tbl, tables + 2 * 256, sizeof(c->out64_tbl));
    memcpy(c->out65_tbl, tables + 3 * 256, sizeof(c->out65_tbl));
    aes128_expand(aes_key, c->rk);
#if TP_HAVE_HW
    c->use_hw = !force_sw && tp_hw_available();
#else
    (void)force_sw;
    c->use_hw = 0;
#endif
    c->evp = EVP_CIPHER_CTX_new();
    if (c->evp == NULL) {
        free(c);
        return NULL;
    }
    if (!EVP_EncryptInit_ex(c->evp, EVP_aes_128_ecb(), NULL, aes_key, NULL) ||
        !EVP_CIPHER_CTX_set_padding(c->evp, 0)) {
        EVP_CIPHER_CTX_free(c->evp);
        free(c);
        return NULL;
    }
    return c;
}

void tp_free(TP_CTX *c)
{
    if (c != NULL) {
        if (c->evp != NULL)
            EVP_CIPHER_CTX_free(c->evp);
        free(c);
    }
}

const char *tp_kind(const TP_CTX *c)
{
#if TP_HAVE_HW
    if (c->use_hw)
        return TP_KIND_HW;
#endif
    (void)c;
    return "evp";
}

int64_t tp_scan(TP_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
#if TP_HAVE_HW
    if (c->use_hw)
        return tp_scan_hw(c, p, n, digest, mask);
#endif
    return tp_scan_evp(c, p, n, digest, mask);
}
