/* some helpers, so our code also works with LibreSSL */

#include <openssl/opensslv.h>
#include <openssl/evp.h>

#if defined(LIBRESSL_VERSION_NUMBER)
const EVP_CIPHER *EVP_aes_256_ocb(void);  /* dummy, so that code compiles */
const EVP_CIPHER *EVP_chacha20_poly1305(void);  /* dummy, so that code compiles */
#endif

#if !defined(LIBRESSL_VERSION_NUMBER)
#define LIBRESSL_VERSION_NUMBER 0
#endif
