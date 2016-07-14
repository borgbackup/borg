/* add missing HMAC functions, so OpenSSL 1.0.x can be used like 1.1 */

#include <openssl/opensslv.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);

#endif
