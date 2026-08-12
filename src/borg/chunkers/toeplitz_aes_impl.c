/* toeplitz-aes chunker scan kernel, see toeplitz_aes_impl.h and
 * toeplitz_aes.pyx.
 *
 * Only the rolling tabulated LFSR/Toeplitz hash lives here; the AES layer,
 * the two-lane scan structure and the context plumbing are shared with the
 * other UHF-then-PRF chunkers (phte_core.h, phte_scan.h). */

#include <stdlib.h>
#include <string.h>

#include "phte_core.h"
#include "toeplitz_aes_impl.h"

/* low 64 bits of the fixed public irreducible P = x^64 + x^4 + x^3 + x + 1
 * (the x^64 coefficient is implicit). Public: the secrecy lives in T. */
#define TP_PLO 0x1BULL

struct TP_CTX {
    PHTE_BASE base;
    /* rolling tables; in0_tbl is the secret random table T itself, the other
     * three are algebraic combinations of T and P (see toeplitz_aes_impl.h).
     * All indices used in the scan are plaintext bytes, so no load ever sits
     * on the serial digest dependency chain (unlike rabin-aes, whose
     * reduction lookup is indexed by digest bits). */
    uint64_t in0_tbl[256];   /* T[b] (incoming byte, newest) */
    uint64_t in1_tbl[256];   /* x    * T[b] mod P (stride-2, older incoming) */
    uint64_t out64_tbl[256]; /* x^64 * T[b] mod P (single-step removal) */
    uint64_t out65_tbl[256]; /* x^65 * T[b] mod P (stride-2 removal, older) */
};

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

/* the shared scan template: defines tp_scan, tp_kind and tp_free */
#define PH_PREFIX tp_
#define PH_CTX TP_CTX
#define PH_ROLL tp_roll
#define PH_ROLL2 tp_roll2
#define PH_DIGEST64 tp_digest64
#include "phte_scan.h"

TP_CTX *tp_new(const uint64_t tables[TP_TABLES * 256], const uint8_t aes_key[16], int kernel)
{
    TP_CTX *c = calloc(1, sizeof(TP_CTX));
    if (c == NULL)
        return NULL;
    memcpy(c->in0_tbl, tables + 0 * 256, sizeof(c->in0_tbl));
    memcpy(c->in1_tbl, tables + 1 * 256, sizeof(c->in1_tbl));
    memcpy(c->out64_tbl, tables + 2 * 256, sizeof(c->out64_tbl));
    memcpy(c->out65_tbl, tables + 3 * 256, sizeof(c->out65_tbl));
    if (!phte_base_init(&c->base, aes_key, kernel)) {
        free(c);
        return NULL;
    }
    return c;
}
