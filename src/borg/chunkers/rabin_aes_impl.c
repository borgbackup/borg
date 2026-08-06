/* rabin-aes chunker scan kernel, see rabin_aes_impl.h and rabin_aes.pyx.
 *
 * Only the rolling Rabin fingerprint lives here; the AES layer, the two-lane
 * scan structure and the context plumbing are shared with the other
 * UHF-then-PRF chunkers (phte_core.h, phte_scan.h). */

#include <stdlib.h>
#include <string.h>

#include "phte_core.h"
#include "rabin_aes_impl.h"

struct RA_CTX {
    PHTE_BASE base;
    /* rolling tables; all entries are mod-P remainders. P has degree 64 with
     * the x^64 coefficient implicit, so remainders fill a uint64 exactly and
     * the left shifts below naturally discard the bits being reduced.
     * The single-step tables define the digest; the double-step tables are
     * algebraically derived from them (see ra_roll2) and exist only so that
     * two independent "lanes" (even/odd positions) can advance with stride 2,
     * halving the load-use latency chain that limits single-step rolling. */
    uint64_t out_tbl[256];   /* b * x^504 mod P (single-step removal) */
    uint64_t red_tbl[256];   /* t * x^64  mod P (reduce 8 bits above bit 63) */
    uint64_t w1_tbl[256];    /* t * x^72  mod P (reduce bits 72..79, stride-2 step) */
    uint64_t out8_tbl[256];  /* b * x^512 mod P (stride-2 removal, newer byte) */
    uint64_t out16_tbl[256]; /* b * x^520 mod P (stride-2 removal, older byte) */
};

/* Advance the digest by one byte: remove the byte leaving the 64-byte window
 * (its coefficient is x^504), multiply by x^8, add the incoming byte, reduce.
 * The digest is the mod-P remainder (deg P = 64), a full uint64; the shift
 * naturally discards the 8 bits that red_tbl reduces back in. */
static inline uint64_t ra_roll(const RA_CTX *c, uint64_t d, uint8_t byte_out, uint8_t byte_in)
{
    d ^= c->out_tbl[byte_out];
    return ((d << 8) | byte_in) ^ c->red_tbl[d >> 56];
}

/* Advance the digest by TWO bytes in one step (exact composition of two
 * ra_roll steps, expanded using linearity over GF(2)):
 *   d' = d*x^16 ^ o0*x^520 ^ o1*x^512 ^ i0*x^8 ^ i1   (mod P)
 * where (o0, i0) belong to the first composed step and (o1, i1) to the second.
 * d*x^16 mod P reduces the top 16 bits of d via two independent lookups
 * (the shift discards them; the tables add the reduced equivalents back).
 * Used to run two independent even/odd lanes; bit-identical to ra_roll twice. */
static inline uint64_t ra_roll2(const RA_CTX *c, uint64_t d,
                                uint8_t o0, uint8_t o1, uint8_t i0, uint8_t i1)
{
    uint64_t delta = c->out16_tbl[o0] ^ c->out8_tbl[o1] ^ (((uint64_t)i0) << 8) ^ i1;
    return (d << 16) ^ c->red_tbl[(d >> 48) & 0xFF] ^ c->w1_tbl[d >> 56] ^ delta;
}

uint64_t ra_digest64(const RA_CTX *c, const uint8_t *q)
{
    uint64_t d = 0;
    for (int j = 0; j < 64; j++)
        d = ((d << 8) | q[j]) ^ c->red_tbl[d >> 56];
    return d;
}

/* the shared scan template: defines ra_scan, ra_kind and ra_free */
#define PH_PREFIX ra_
#define PH_CTX RA_CTX
#define PH_ROLL ra_roll
#define PH_ROLL2 ra_roll2
#define PH_DIGEST64 ra_digest64
#include "phte_scan.h"

RA_CTX *ra_new(const uint64_t tables[RA_TABLES * 256], const uint8_t aes_key[16], int kernel)
{
    RA_CTX *c = calloc(1, sizeof(RA_CTX));
    if (c == NULL)
        return NULL;
    memcpy(c->out_tbl, tables + 0 * 256, sizeof(c->out_tbl));
    memcpy(c->red_tbl, tables + 1 * 256, sizeof(c->red_tbl));
    memcpy(c->w1_tbl, tables + 2 * 256, sizeof(c->w1_tbl));
    memcpy(c->out8_tbl, tables + 3 * 256, sizeof(c->out8_tbl));
    memcpy(c->out16_tbl, tables + 4 * 256, sizeof(c->out16_tbl));
    if (!phte_base_init(&c->base, aes_key, kernel)) {
        free(c);
        return NULL;
    }
    return c;
}
