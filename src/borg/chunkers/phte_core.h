/* Shared parts of the UHF-then-PRF ("Chk-PHTE") chunker scan kernels.
 *
 * rabin-aes, goldilocks-aes and toeplitz-aes differ only in their rolling
 * universal hash; the AES-128 PRF layer, the two-lane scan structure and the
 * context plumbing are identical. This header holds everything that does not
 * depend on the rolling hash; phte_scan.h holds the scan template that does.
 *
 * Everything here is static (or static inline): each kernel is a separate
 * extension module and gets its own copy, so there is no cross-kernel call,
 * no indirection and no code-generation difference versus hand-copied code.
 */

#ifndef BORG_PHTE_CORE_H
#define BORG_PHTE_CORE_H

#include "phte_kernel.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

/* Fields every kernel context needs. Each kernel's context struct embeds this
 * as its first member `base`, followed by its own rolling tables. */
typedef struct {
    uint8_t rk[11][16];  /* AES-128 round keys, for the hardware paths */
    EVP_CIPHER_CTX *evp; /* portable path */
    int use_hw;
    int use_hw512; /* VAES/AVX-512 variant of the hardware path (x86-64) */
} PHTE_BASE;

/* --- endianness-explicit helpers (byte loops, so cut points do not depend
 *     on the host byte order) ------------------------------------------- */

static inline void phte_store_le64(uint8_t *b, uint64_t v)
{
    for (int j = 0; j < 8; j++)
        b[j] = (uint8_t)(v >> (8 * j));
}

static inline uint64_t phte_load_le64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int j = 0; j < 8; j++)
        v |= ((uint64_t)b[j]) << (8 * j);
    return v;
}

/* --- AES-128 key expansion (encryption-only, standard FIPS-197) -------- */

static const uint8_t phte_sbox[256] = {
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

static void phte_aes128_expand(const uint8_t key[16], uint8_t rk[11][16])
{
    uint8_t rcon = 1;
    memcpy(rk[0], key, 16);
    for (int i = 1; i <= 10; i++) {
        rk[i][0] = (uint8_t)(rk[i - 1][0] ^ phte_sbox[rk[i - 1][13]] ^ rcon);
        rk[i][1] = (uint8_t)(rk[i - 1][1] ^ phte_sbox[rk[i - 1][14]]);
        rk[i][2] = (uint8_t)(rk[i - 1][2] ^ phte_sbox[rk[i - 1][15]]);
        rk[i][3] = (uint8_t)(rk[i - 1][3] ^ phte_sbox[rk[i - 1][12]]);
        for (int j = 4; j < 16; j++)
            rk[i][j] = (uint8_t)(rk[i - 1][j] ^ rk[i][j - 4]);
        rcon = (uint8_t)((rcon << 1) ^ ((rcon >> 7) * 0x1b));
    }
}

/* --- hardware AES availability and single-block helpers ---------------- */

/* aarch64: the AES intrinsics are only usable in a function compiled with the
 * crypto extension enabled. Python extension builds get no -march flags, so on
 * Linux and the BSDs they target the armv8-a baseline, which does not include
 * it (__ARM_FEATURE_AES is undefined there); only Apple's default target has
 * it. So the extension is enabled per function via a target attribute (gcc >=
 * 6 / clang >= 14), the same way the x86-64 path uses target("aes,sse2"), and
 * whether this CPU actually has the instructions is decided at run time by
 * phte_hw_available(). A build that targets +crypto as a whole needs neither. */
#if defined(__aarch64__) && \
    (defined(__ARM_FEATURE_AES) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 6) || \
     (defined(__clang__) && __clang_major__ >= 14))
#define PHTE_HAVE_HW 1
#define PHTE_KIND_HW "aes-arm64"

#include <arm_neon.h>
#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/auxv.h> /* getauxval resp. elf_aux_info; FreeBSD's also brings HWCAP_AES */
#endif
#if (defined(__linux__) || defined(__FreeBSD__)) && !defined(HWCAP_AES)
#define HWCAP_AES (1 << 3)
#endif

#if defined(__ARM_FEATURE_AES)
#define PHTE_HW_TARGET /* the whole build targets +crypto already */
#else
#define PHTE_HW_TARGET __attribute__((target("+crypto")))
#endif

/* Whether this CPU has the AES instructions. Where the OS cannot be asked,
 * only a build that targets +crypto as a whole may assume so (it would not
 * run on a lesser CPU anyway); everything else stays on the portable path.
 * TODO: NetBSD (machdep.cpuN.cpu_id sysctl) and OpenBSD (elf_aux_info since
 * 7.6) could be asked too. */
static int phte_hw_available(void)
{
#if defined(__APPLE__)
    return 1; /* every Apple Silicon CPU has the crypto extension */
#elif defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#elif defined(__FreeBSD__)
    unsigned long hwcap = 0;
    return elf_aux_info(AT_HWCAP, &hwcap, sizeof(hwcap)) == 0 && (hwcap & HWCAP_AES) != 0;
#elif defined(__ARM_FEATURE_AES)
    return 1;
#else
    return 0;
#endif
}

PHTE_HW_TARGET static inline uint8x16_t phte_aes1_neon(const uint8x16_t k[11], uint8x16_t b)
{
    for (int r = 0; r < 9; r++)
        b = vaesmcq_u8(vaeseq_u8(b, k[r]));
    return veorq_u8(vaeseq_u8(b, k[9]), k[10]);
}

#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#define PHTE_HAVE_HW 1
#define PHTE_KIND_HW "aes-ni"

#include <immintrin.h>

static int phte_hw_available(void)
{
    /* SSE4.1 for the scan's pcmpeqq; every CPU with AES-NI has it */
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse4.1");
}

__attribute__((target("aes,sse2"))) static inline __m128i
phte_aes1_ni(const uint8_t rk[11][16], __m128i b)
{
    b = _mm_xor_si128(b, _mm_loadu_si128((const __m128i *)rk[0]));
    for (int r = 1; r < 10; r++)
        b = _mm_aesenc_si128(b, _mm_loadu_si128((const __m128i *)rk[r]));
    return _mm_aesenclast_si128(b, _mm_loadu_si128((const __m128i *)rk[10]));
}

/* VAES/AVX-512 variant of the hardware path (4 AES blocks per instruction).
 * __builtin_cpu_supports("vaes") needs GCC >= 11 / clang >= 14; older
 * compilers simply keep the 128-bit AES-NI path. */
#if (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 11) || (defined(__clang__) && __clang_major__ >= 14)
#define PHTE_HAVE_HW512 1
#define PHTE_KIND_HW512 "vaes"

static int phte_hw512_available(void)
{
    return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("vaes");
}
#endif

#else
#define PHTE_HAVE_HW 0
#endif

#ifndef PHTE_HAVE_HW512
#define PHTE_HAVE_HW512 0
#endif

/* --- kernel selection ---------------------------------------------------
 *
 * Shared by all three AES chunkers: the scan path lives in phte_scan.h and
 * only the rolling hash differs between them, so there is no machine on which
 * one of them has a hardware path and another does not. Hence one selector
 * (BORG_AES_CHUNKER_KERNEL) rather than one per chunker. */

const char *phte_kernel_names(void)
{
#if defined(__aarch64__)
    return "aes-arm64,evp";
#elif (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
    return "vaes,aes-ni,evp";
#else
    return "evp";
#endif
}

int phte_kernel_select(const char *name, int *out_id)
{
    if (strcmp(name, "evp") == 0) {
        *out_id = PHTE_K_EVP;
        return PHTE_KSEL_OK;
    }
#if PHTE_HAVE_HW
    if (strcmp(name, PHTE_KIND_HW) == 0) {
        if (!phte_hw_available())
            return PHTE_KSEL_NOCPU;
        *out_id = PHTE_K_HW;
        return PHTE_KSEL_OK;
    }
#elif defined(__aarch64__)
    if (strcmp(name, "aes-arm64") == 0)
        return PHTE_KSEL_NOTBUILT; /* compiler too old for the target attribute */
#endif
#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
    if (strcmp(name, "vaes") == 0) {
#if !PHTE_HAVE_HW512
        return PHTE_KSEL_NOTBUILT; /* compiler too old for the VAES intrinsics */
#else
        if (!phte_hw512_available())
            return PHTE_KSEL_NOCPU;
        *out_id = PHTE_K_HW512;
        return PHTE_KSEL_OK;
#endif
    }
#endif
    return PHTE_KSEL_UNKNOWN;
}

int phte_kernel_default(void)
{
    int kid;
    (void)kid;
#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
    if (phte_kernel_select("vaes", &kid) == PHTE_KSEL_OK)
        return kid;
#endif
#if PHTE_HAVE_HW
    if (phte_kernel_select(PHTE_KIND_HW, &kid) == PHTE_KSEL_OK)
        return kid;
#endif
    return PHTE_K_EVP;
}

/* --- context base management ------------------------------------------- */

/* Expand the AES key, select the scan path and set up the OpenSSL context.
 * kernel is one of PHTE_K_*.
 * Returns 0 on failure (caller frees its context). */
static int phte_base_init(PHTE_BASE *b, const uint8_t aes_key[16], int kernel)
{
    phte_aes128_expand(aes_key, b->rk);
#if PHTE_HAVE_HW
    b->use_hw = (kernel == PHTE_K_HW || kernel == PHTE_K_HW512) && phte_hw_available();
#else
    b->use_hw = 0;
#endif
#if PHTE_HAVE_HW512
    b->use_hw512 = b->use_hw && kernel == PHTE_K_HW512 && phte_hw512_available();
#else
    b->use_hw512 = 0;
#endif
    (void)kernel;
    b->evp = EVP_CIPHER_CTX_new();
    if (b->evp == NULL)
        return 0;
    if (!EVP_EncryptInit_ex(b->evp, EVP_aes_128_ecb(), NULL, aes_key, NULL) ||
        !EVP_CIPHER_CTX_set_padding(b->evp, 0)) {
        EVP_CIPHER_CTX_free(b->evp);
        b->evp = NULL;
        return 0;
    }
    return 1;
}

static void phte_base_free(PHTE_BASE *b)
{
    if (b->evp != NULL) {
        EVP_CIPHER_CTX_free(b->evp);
        b->evp = NULL;
    }
}

static const char *phte_base_kind(const PHTE_BASE *b)
{
#if PHTE_HAVE_HW512
    if (b->use_hw512)
        return PHTE_KIND_HW512;
#endif
#if PHTE_HAVE_HW
    if (b->use_hw)
        return PHTE_KIND_HW;
#endif
    (void)b;
    return "evp";
}

#endif /* BORG_PHTE_CORE_H */
