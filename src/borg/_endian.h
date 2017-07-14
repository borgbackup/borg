#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#if defined (__SVR4) && defined (__sun)
#include <sys/isa_defs.h>
#endif

#if (defined(BYTE_ORDER) && defined(BIG_ENDIAN) && (BYTE_ORDER == BIG_ENDIAN)) ||  \
    (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)) || \
    (defined(_BIG_ENDIAN) && defined(__SVR4) && defined(__sun))
#define BORG_BIG_ENDIAN 1
#elif (defined(BYTE_ORDER) && defined(LITTLE_ENDIAN) && (BYTE_ORDER == LITTLE_ENDIAN)) || \
      (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
      (defined(_LITTLE_ENDIAN) && defined(__SVR4) && defined(__sun))
#define BORG_BIG_ENDIAN 0
#else
#error Unknown byte order
#endif

#if BORG_BIG_ENDIAN
#define _le32toh(x) __builtin_bswap32(x)
#define _htole32(x) __builtin_bswap32(x)
#else
#define _le32toh(x) (x)
#define _htole32(x) (x)
#endif
