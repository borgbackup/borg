/* some helpers, so our code also works with OpenSSL 1.0.x */

#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

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

const EVP_CIPHER *EVP_aes_256_ocb(void){  /* dummy, so that code compiles */
    return NULL;
}

const EVP_CIPHER *EVP_chacha20_poly1305(void){  /* dummy, so that code compiles */
    return NULL;
}

#endif
