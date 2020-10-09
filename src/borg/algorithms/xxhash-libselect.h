#ifdef BORG_USE_LIBXXHASH
#include <xxhash.h>
#else
#include "xxh64/xxhash.c"
#endif
