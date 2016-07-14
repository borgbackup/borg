/* add missing HMAC functions, so OpenSSL 1.0.x can be used like 1.1 */

#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

HMAC_CTX *HMAC_CTX_new(void)
{
   HMAC_CTX *ctx = OPENSSL_malloc(sizeof(*ctx));
   if (ctx != NULL) {
       memset(ctx, 0, sizeof *ctx);
       HMAC_CTX_cleanup(ctx);
   }
   return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
   if (ctx != NULL) {
       HMAC_CTX_cleanup(ctx);
       OPENSSL_free(ctx);
   }
}

#endif
