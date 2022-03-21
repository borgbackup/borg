/* some helpers, so our code also works with OpenSSL 1.0.x */

#include <openssl/opensslv.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
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
