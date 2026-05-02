// Stand-in for <mbedtls/base64.h> just for host tests.
#ifndef MBEDTLS_BASE64_H_STUB
#define MBEDTLS_BASE64_H_STUB

#include <stddef.h>

#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL    -0x002A
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER   -0x002C

int mbedtls_base64_decode(unsigned char* dst,
                          size_t         dlen,
                          size_t*        olen,
                          const unsigned char* src,
                          size_t         slen);

int mbedtls_base64_encode(unsigned char* dst,
                          size_t         dlen,
                          size_t*        olen,
                          const unsigned char* src,
                          size_t         slen);

#endif
