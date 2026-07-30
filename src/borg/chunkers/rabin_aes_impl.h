/* rabin-aes chunker scan kernel: rolling Rabin fingerprint (UHF) + AES-128 (PRF).
 *
 * See rabin_aes.pyx for the scheme description. This C layer only implements the
 * performance-critical inner scan: roll the Rabin digest one byte at a time,
 * encrypt each digest with AES-128, and cut where the ciphertext's low bits
 * (little-endian uint64 of the first 8 ciphertext bytes) are all zero under mask.
 *
 * Two code paths produce bit-identical results:
 *  - a portable path batching digests through OpenSSL EVP AES-128-ECB,
 *  - a hardware path using AES instructions directly (arm64 with the crypto
 *    extension, e.g. Apple Silicon; x86-64 with AES-NI), which interleaves the
 *    serial Rabin chain with pipelined AES so the AES work is (mostly) hidden
 *    behind the Rabin table-lookup latency chain.
 */

#ifndef BORG_RABIN_AES_IMPL_H
#define BORG_RABIN_AES_IMPL_H

#include <stdint.h>
#include <stddef.h>

typedef struct RA_CTX RA_CTX;

/* Create a kernel context.
 * out_tbl[b] = poly(b) * x^504 mod P  (removal of the byte leaving the 64-byte window)
 * red_tbl[t] = poly(t) * x^63  mod P  (reduction of the 8 bits shifted above bit 62)
 * aes_key: 16 bytes (AES-128).
 * force_sw: nonzero forces the portable OpenSSL path (for tests/benchmarks).
 * Returns NULL on allocation/OpenSSL failure. */
RA_CTX *ra_new(const uint64_t out_tbl[256], const uint64_t red_tbl[256],
               const uint8_t aes_key[16], int force_sw);

void ra_free(RA_CTX *ctx);

/* Which path this context uses: "aes-arm64", "aes-ni" or "evp". */
const char *ra_kind(const RA_CTX *ctx);

/* Full (non-rolling) Rabin digest of the 64 bytes at q: the window warm-up at
 * the start of each chunk scan. */
uint64_t ra_digest64(const RA_CTX *ctx, const uint8_t *q);

/* Scan up to n positions. For position i (0 <= i < n), the rolling digest is
 * advanced to cover the 64-byte window p[i-63..i] (reading the outgoing byte
 * at p[i-64], which the caller must guarantee to be accessible) and the cut
 * condition is evaluated on AES(digest).
 * Returns the first i whose cut condition matched (digest is left at position i),
 * or -1 if none matched (digest is left at position n-1). */
int64_t ra_scan(RA_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask);

#endif
