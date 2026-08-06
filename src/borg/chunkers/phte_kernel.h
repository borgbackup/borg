/* Scan-path selection shared by the three UHF-then-PRF ("Chk-PHTE") chunkers
 * (toeplitz-aes, rabin-aes, goldilocks-aes).
 *
 * They share phte_scan.h and differ only in their rolling hash, so the
 * available scan paths are a property of the build and the CPU, never of the
 * individual chunker: there is no machine where one of them has a hardware
 * path and another does not. Hence one selector for all three. */

#ifndef BORG_PHTE_KERNEL_H
#define BORG_PHTE_KERNEL_H

/* Scan path ids. Which names map onto them depends on the build: "vaes" only
 * on x86-64, and the 128-bit hardware path is spelled "aes-ni" on x86-64 and
 * "aes-arm64" on aarch64.
 *
 * There is no automatic selection: the caller says which path to run.
 * PHTE_K_EVP, the portable OpenSSL batch path, is id 0 and the default - it
 * is the simplest implementation and the one the others are checked
 * against. */
#define PHTE_K_EVP 0   /* portable OpenSSL EVP batch path */
#define PHTE_K_HW 1    /* 128-bit AES instructions: aes-ni / aes-arm64 */
#define PHTE_K_HW512 2 /* VAES/AVX-512, 4 AES blocks per instruction */

/* Results of phte_kernel_select(). */
#define PHTE_KSEL_OK 0
#define PHTE_KSEL_UNKNOWN 1  /* not a scan path name on this platform */
#define PHTE_KSEL_NOTBUILT 2 /* known, but not compiled into this binary */
#define PHTE_KSEL_NOCPU 3    /* known and built, but this CPU cannot run it */

/* Resolve a scan path name for this build. On PHTE_KSEL_OK the id is stored
 * in *out_id, otherwise *out_id is left alone. The three failures are kept
 * apart because they need different fixes: a typo, too old a compiler, or the
 * wrong CPU. */
int phte_kernel_select(const char *name, int *out_id);

/* Comma-separated list of the scan path names this build accepts, for error
 * messages. Names a CPU cannot run are still listed. */
const char *phte_kernel_names(void);

#endif /* BORG_PHTE_KERNEL_H */
