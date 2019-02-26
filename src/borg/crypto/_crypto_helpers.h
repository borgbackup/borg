/* some helpers, so our code also works with OpenSSL 1.0.x */

#include <openssl/opensslv.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);

const EVP_CIPHER *EVP_aes_256_ocb(void);  /* dummy, so that code compiles */
const EVP_CIPHER *EVP_chacha20_poly1305(void);  /* dummy, so that code compiles */

#endif


#if !defined(LIBRESSL_VERSION_NUMBER)
#define LIBRESSL_VERSION_NUMBER 0
#endif
