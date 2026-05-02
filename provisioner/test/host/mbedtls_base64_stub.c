// Minimal RFC 4648 base64 implementation that satisfies the subset of
// mbedtls that provisioner_proto.c actually calls. The signatures mirror
// mbedtls/base64.h verbatim so the unit under test can be compiled
// unchanged. NOT for production use.

#include <stddef.h>

#include "mbedtls/base64.h"

static const signed char b64_decode_tab[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
    ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
    ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25,
    ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
    ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
    ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
    ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
    ['y'] = 50, ['z'] = 51,
    ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57,
    ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61,
    ['+'] = 62, ['/'] = 63,
};

static const char b64_encode_tab[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int mbedtls_base64_decode(unsigned char* dst,
                          size_t         dlen,
                          size_t*        olen,
                          const unsigned char* src,
                          size_t         slen)
{
    // Trim trailing '=' padding and validate alphabet.
    size_t in_pad = 0;
    while (in_pad < 2 && slen > 0 && src[slen - 1] == '=')
    {
        slen--;
        in_pad++;
    }
    if (slen % 4 == 1)
    {
        return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
    }
    size_t produced = (slen * 3) / 4;
    if (olen)
    {
        *olen = produced;
    }
    if (dst == NULL || dlen < produced)
    {
        if (olen)
        {
            *olen = produced;
        }
        return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
    }

    unsigned bits = 0;
    int      have = 0;
    size_t   wpos = 0;
    for (size_t i = 0; i < slen; i++)
    {
        unsigned char c = src[i];
        signed char   v = b64_decode_tab[c];
        if (v == 0 && c != 'A')
        {
            return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
        }
        bits = (bits << 6) | (unsigned)v;
        have += 6;
        if (have >= 8)
        {
            have -= 8;
            dst[wpos++] = (unsigned char)((bits >> have) & 0xFF);
        }
    }
    if (olen)
    {
        *olen = wpos;
    }
    return 0;
}

int mbedtls_base64_encode(unsigned char* dst,
                          size_t         dlen,
                          size_t*        olen,
                          const unsigned char* src,
                          size_t         slen)
{
    size_t out_len = 4 * ((slen + 2) / 3);
    if (olen)
    {
        *olen = out_len;
    }
    if (dst == NULL || dlen < out_len + 1) // +1 for trailing NUL like real mbedtls
    {
        return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
    }
    size_t i = 0;
    size_t j = 0;
    while (i + 3 <= slen)
    {
        unsigned v   = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8) | src[i + 2];
        dst[j++]     = (unsigned char)b64_encode_tab[(v >> 18) & 0x3F];
        dst[j++]     = (unsigned char)b64_encode_tab[(v >> 12) & 0x3F];
        dst[j++]     = (unsigned char)b64_encode_tab[(v >> 6) & 0x3F];
        dst[j++]     = (unsigned char)b64_encode_tab[v & 0x3F];
        i += 3;
    }
    if (i < slen)
    {
        unsigned v = (unsigned)src[i] << 16;
        if (i + 1 < slen)
        {
            v |= (unsigned)src[i + 1] << 8;
        }
        dst[j++] = (unsigned char)b64_encode_tab[(v >> 18) & 0x3F];
        dst[j++] = (unsigned char)b64_encode_tab[(v >> 12) & 0x3F];
        if (i + 1 < slen)
        {
            dst[j++] = (unsigned char)b64_encode_tab[(v >> 6) & 0x3F];
        }
        else
        {
            dst[j++] = '=';
        }
        dst[j++] = '=';
    }
    dst[j] = '\0';
    if (olen)
    {
        *olen = j;
    }
    return 0;
}
