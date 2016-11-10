#ifdef BORG_USE_LIBB2
#include <blake2.h>
#else
#include "blake2/blake2b-ref.c"
#endif
