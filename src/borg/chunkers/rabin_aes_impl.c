/* rabin-aes chunker scan kernel, see rabin_aes_impl.h and rabin_aes.pyx. */

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "rabin_aes_impl.h"

#define M55 ((((uint64_t)1) << 55) - 1)

struct RA_CTX {
    uint64_t out_tbl[256];
    uint64_t red_tbl[256];
    uint8_t rk[11][16]; /* AES-128 round keys, for the hardware paths */
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

/* Advance the digest by one byte: remove the byte leaving the 64-byte window
 * (its coefficient is x^504), multiply by x^8, add the incoming byte, reduce.
 * The digest is the mod-P remainder, so it always fits in 63 bits. */
static inline uint64_t ra_roll(const RA_CTX *c, uint64_t d, uint8_t byte_out, uint8_t byte_in)
{
    d ^= c->out_tbl[byte_out];
    return (((d & M55) << 8) | byte_in) ^ c->red_tbl[d >> 55];
}

uint64_t ra_digest64(const RA_CTX *c, const uint8_t *q)
{
    uint64_t d = 0;
    for (int j = 0; j < 64; j++)
        d = (((d & M55) << 8) | q[j]) ^ c->red_tbl[d >> 55];
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

/* --- portable path: batched AES via OpenSSL EVP ------------------------ */

/* sub-batch size (blocks); 512 * 16 B = 8 KiB in/out buffers on the stack */
#define RA_SB 512

static int64_t ra_scan_evp(RA_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint8_t inb[RA_SB * 16];
    uint8_t outb[RA_SB * 16];
    uint64_t dig[RA_SB];
    uint64_t d = *digest;
    size_t base = 0;
    int outlen;

    memset(inb, 0, sizeof(inb)); /* bytes 8..15 of each block stay zero */
    while (base < n) {
        const uint8_t *q = p + base;
        const uint8_t *q_out = q - 64;
        size_t m = n - base;
        if (m > RA_SB)
            m = RA_SB;
        for (size_t i = 0; i < m; i++) {
            d = ra_roll(c, d, q_out[i], q[i]);
            dig[i] = d;
            store_le64(inb + i * 16, d);
        }
        outlen = 0;
        if (!EVP_EncryptUpdate(c->evp, outb, &outlen, inb, (int)(m * 16)) || outlen != (int)(m * 16))
            return -2; /* OpenSSL failure; caller raises */
        for (size_t i = 0; i < m; i++) {
            if ((load_le64(outb + i * 16) & mask) == 0) {
                *digest = dig[i];
                return (int64_t)(base + i);
            }
        }
        base += m;
    }
    *digest = d;
    return -1;
}

/* --- hardware path: arm64 crypto extension ----------------------------- */

#if defined(__aarch64__) && defined(__ARM_FEATURE_AES)
#define RA_HAVE_HW 1
#define RA_KIND_HW "aes-arm64"

#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#endif

static int ra_hw_available(void)
{
#if defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
    return 1; /* compiler targeted +aes; on Apple Silicon it is always there */
#endif
}

static inline uint8x16_t ra_aes1_neon(const uint8x16_t k[11], uint8x16_t b)
{
    for (int r = 0; r < 9; r++)
        b = vaesmcq_u8(vaeseq_u8(b, k[r]));
    return veorq_u8(vaeseq_u8(b, k[9]), k[10]);
}

static int64_t ra_scan_hw(RA_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    uint8x16_t k[11];
    uint64_t d = *digest;
    const uint8_t *q_out = p - 64;
    size_t i = 0;

    for (int j = 0; j < 11; j++)
        k[j] = vld1q_u8(c->rk[j]);

    while (i + 8 <= n) {
        uint64_t dg[8];
        uint8x16_t b0, b1, b2, b3, b4, b5, b6, b7;

        /* serial Rabin chain for the next 8 positions */
        d = ra_roll(c, d, q_out[i + 0], p[i + 0]); dg[0] = d;
        d = ra_roll(c, d, q_out[i + 1], p[i + 1]); dg[1] = d;
        d = ra_roll(c, d, q_out[i + 2], p[i + 2]); dg[2] = d;
        d = ra_roll(c, d, q_out[i + 3], p[i + 3]); dg[3] = d;
        d = ra_roll(c, d, q_out[i + 4], p[i + 4]); dg[4] = d;
        d = ra_roll(c, d, q_out[i + 5], p[i + 5]); dg[5] = d;
        d = ra_roll(c, d, q_out[i + 6], p[i + 6]); dg[6] = d;
        d = ra_roll(c, d, q_out[i + 7], p[i + 7]); dg[7] = d;

        /* 8 independent AES-128 encryptions, interleaved to fill the AES pipes */
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
    /* tail: single blocks */
    while (i < n) {
        uint8x16_t b;
        d = ra_roll(c, d, q_out[i], p[i]);
        b = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(d), vcreate_u64(0)));
        b = ra_aes1_neon(k, b);
        if ((vgetq_lane_u64(vreinterpretq_u64_u8(b), 0) & mask) == 0) {
            *digest = d;
            return (int64_t)i;
        }
        i++;
    }
    *digest = d;
    return -1;
}

/* --- hardware path: x86-64 AES-NI -------------------------------------- */

#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#define RA_HAVE_HW 1
#define RA_KIND_HW "aes-ni"

#include <immintrin.h>

static int ra_hw_available(void)
{
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse2");
}

__attribute__((target("aes,sse2"))) static int64_t
ra_scan_hw(RA_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
    __m128i k[11];
    uint64_t d = *digest;
    const uint8_t *q_out = p - 64;
    size_t i = 0;

    for (int j = 0; j < 11; j++)
        k[j] = _mm_loadu_si128((const __m128i *)c->rk[j]);

    while (i + 4 <= n) {
        uint64_t dg[4];
        __m128i b0, b1, b2, b3;

        d = ra_roll(c, d, q_out[i + 0], p[i + 0]); dg[0] = d;
        d = ra_roll(c, d, q_out[i + 1], p[i + 1]); dg[1] = d;
        d = ra_roll(c, d, q_out[i + 2], p[i + 2]); dg[2] = d;
        d = ra_roll(c, d, q_out[i + 3], p[i + 3]); dg[3] = d;

        b0 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[0]), k[0]);
        b1 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[1]), k[0]);
        b2 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[2]), k[0]);
        b3 = _mm_xor_si128(_mm_set_epi64x(0, (long long)dg[3]), k[0]);
        for (int r = 1; r < 10; r++) {
            b0 = _mm_aesenc_si128(b0, k[r]);
            b1 = _mm_aesenc_si128(b1, k[r]);
            b2 = _mm_aesenc_si128(b2, k[r]);
            b3 = _mm_aesenc_si128(b3, k[r]);
        }
        b0 = _mm_aesenclast_si128(b0, k[10]);
        b1 = _mm_aesenclast_si128(b1, k[10]);
        b2 = _mm_aesenclast_si128(b2, k[10]);
        b3 = _mm_aesenclast_si128(b3, k[10]);

        {
            uint64_t cs[4];
            cs[0] = (uint64_t)_mm_cvtsi128_si64(b0);
            cs[1] = (uint64_t)_mm_cvtsi128_si64(b1);
            cs[2] = (uint64_t)_mm_cvtsi128_si64(b2);
            cs[3] = (uint64_t)_mm_cvtsi128_si64(b3);
            for (int j = 0; j < 4; j++) {
                if ((cs[j] & mask) == 0) {
                    *digest = dg[j];
                    return (int64_t)(i + j);
                }
            }
        }
        i += 4;
    }
    while (i < n) {
        __m128i b;
        d = ra_roll(c, d, q_out[i], p[i]);
        b = _mm_xor_si128(_mm_set_epi64x(0, (long long)d), k[0]);
        for (int r = 1; r < 10; r++)
            b = _mm_aesenc_si128(b, k[r]);
        b = _mm_aesenclast_si128(b, k[10]);
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
#define RA_HAVE_HW 0
#endif

/* --- context management and dispatch ----------------------------------- */

RA_CTX *ra_new(const uint64_t out_tbl[256], const uint64_t red_tbl[256],
               const uint8_t aes_key[16], int force_sw)
{
    RA_CTX *c = calloc(1, sizeof(RA_CTX));
    if (c == NULL)
        return NULL;
    memcpy(c->out_tbl, out_tbl, sizeof(c->out_tbl));
    memcpy(c->red_tbl, red_tbl, sizeof(c->red_tbl));
    aes128_expand(aes_key, c->rk);
#if RA_HAVE_HW
    c->use_hw = !force_sw && ra_hw_available();
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

void ra_free(RA_CTX *c)
{
    if (c != NULL) {
        if (c->evp != NULL)
            EVP_CIPHER_CTX_free(c->evp);
        free(c);
    }
}

const char *ra_kind(const RA_CTX *c)
{
#if RA_HAVE_HW
    if (c->use_hw)
        return RA_KIND_HW;
#endif
    (void)c;
    return "evp";
}

int64_t ra_scan(RA_CTX *c, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)
{
#if RA_HAVE_HW
    if (c->use_hw)
        return ra_scan_hw(c, p, n, digest, mask);
#endif
    return ra_scan_evp(c, p, n, digest, mask);
}
