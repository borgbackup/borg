
/* always compile slice by 8 as a runtime fallback */
#include "crc32_slice_by_8.c"

#ifdef __GNUC__
/*
 * GCC 4.4(.7) has a bug that causes it to recurse infinitely if an unknown option
 * is pushed onto the options stack. GCC 4.5 was not tested, so is excluded as well.
 * GCC 4.6 is known good.
 */
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
/*
 * clang also has or had GCC bug #56298 explained below, but doesn't support
 * target attributes or the options stack. So we disable this faster code path for clang.
 */
#ifndef __clang__
/*
 * While OpenBSD uses GCC, they don't have Intel intrinsics, so we can't compile this code
 * on OpenBSD.
 */
#ifndef __OpenBSD__
#if __x86_64__
/*
 * Because we don't want a configure script we need compiler-dependent pre-defined macros for detecting this,
 * also some compiler-dependent stuff to invoke SSE modes and align things.
 */

#define FOLDING_CRC

/*
 * SSE2 misses _mm_shuffle_epi32, and _mm_extract_epi32
 * SSSE3 added _mm_shuffle_epi32
 * SSE4.1 added _mm_extract_epi32
 * Also requires CLMUL of course (all AES-NI CPUs have it)
 * Note that there are no CPUs with AES-NI/CLMUL but without SSE4.1
 */
#define CLMUL __attribute__ ((target ("pclmul,sse4.1")))

#define ALIGNED_(n) __attribute__ ((aligned(n)))

/*
 * Work around https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56298
 * These are taken from GCC 6.x, so apparently the above bug has been resolved in that version,
 * but it still affects widely used GCC 4.x.
 * Part 2 of 2 follows below.
 */

#ifndef __PCLMUL__
#pragma GCC push_options
#pragma GCC target("pclmul")
#define __BORG_DISABLE_PCLMUL__
#endif

#ifndef __SSE3__
#pragma GCC push_options
#pragma GCC target("sse3")
#define __BORG_DISABLE_SSE3__
#endif

#ifndef __SSSE3__
#pragma GCC push_options
#pragma GCC target("ssse3")
#define __BORG_DISABLE_SSSE3__
#endif

#ifndef __SSE4_1__
#pragma GCC push_options
#pragma GCC target("sse4.1")
#define __BORG_DISABLE_SSE4_1__
#endif

#endif /* if __x86_64__ */
#endif /* ifndef __OpenBSD__ */
#endif /* ifndef __clang__ */
#endif /* __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6) */
#endif /* ifdef __GNUC__ */

#ifdef FOLDING_CRC
#include "crc32_clmul.c"
#else

static uint32_t
crc32_clmul(const uint8_t *src, long len, uint32_t initial_crc)
{
    (void)src; (void)len; (void)initial_crc;
    assert(0);
    return 0;
}

static int
have_clmul(void)
{
    return 0;
}
#endif

/*
 * Part 2 of 2 of the GCC workaround.
 */
#ifdef __BORG_DISABLE_PCLMUL__
#undef __BORG_DISABLE_PCLMUL__
#pragma GCC pop_options
#endif

#ifdef __BORG_DISABLE_SSE3__
#undef __BORG_DISABLE_SSE3__
#pragma GCC pop_options
#endif

#ifdef __BORG_DISABLE_SSSE3__
#undef __BORG_DISABLE_SSSE3__
#pragma GCC pop_options
#endif

#ifdef __BORG_DISABLE_SSE4_1__
#undef __BORG_DISABLE_SSE4_1__
#pragma GCC pop_options
#endif
