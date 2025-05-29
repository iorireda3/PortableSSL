/**
 * @file util.c
 * @brief Implementation of utility functions
 */

#include "util/util.h"
#include "platform/platform.h"
#include <string.h>

/* Securely zero memory */
void util_secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    size_t i;
    
    if (ptr == NULL) {
        return;
    }
    
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

/* Constant-time memory comparison */
int util_constant_time_eq(const void* a, const void* b, size_t len) {
    const uint8_t* a_ptr = (const uint8_t*)a;
    const uint8_t* b_ptr = (const uint8_t*)b;
    uint8_t result = 0;
    size_t i;
    
    for (i = 0; i < len; i++) {
        result |= a_ptr[i] ^ b_ptr[i];
    }
    
    return result == 0 ? 1 : 0;
}

/* Host to network byte order (16-bit) */
uint16_t util_htons(uint16_t val) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((val & 0xff) << 8) | ((val & 0xff00) >> 8);
#else
    return val;
#endif
}

/* Network to host byte order (16-bit) */
uint16_t util_ntohs(uint16_t val) {
    return util_htons(val);  /* Same operation */
}

/* Host to network byte order (32-bit) */
uint32_t util_htonl(uint32_t val) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((val & 0xff) << 24) |
           ((val & 0xff00) << 8) |
           ((val & 0xff0000) >> 8) |
           ((val & 0xff000000) >> 24);
#else
    return val;
#endif
}

/* Network to host byte order (32-bit) */
uint32_t util_ntohl(uint32_t val) {
    return util_htonl(val);  /* Same operation */
}

/* Base64 encoding/decoding */

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t util_base64_encode_len(size_t in_len) {
    /* Base64 encoding expands to 4 bytes for every 3 bytes of input */
    return ((in_len + 2) / 3) * 4;
}

int util_base64_encode(const uint8_t* in, size_t in_len, char* out, size_t* out_len) {
    size_t i, j;
    size_t output_size = util_base64_encode_len(in_len);
    
    if (!in || !out || !out_len || *out_len < output_size) {
        if (out_len) {
            *out_len = output_size;
        }
        return -1;
    }
    
    for (i = 0, j = 0; i < in_len; i += 3, j += 4) {
        uint32_t val = in[i] << 16;
        
        if (i + 1 < in_len) {
            val |= in[i + 1] << 8;
        }
        
        if (i + 2 < in_len) {
            val |= in[i + 2];
        }
        
        out[j] = b64_table[(val >> 18) & 0x3F];
        out[j + 1] = b64_table[(val >> 12) & 0x3F];
        out[j + 2] = (i + 1 < in_len) ? b64_table[(val >> 6) & 0x3F] : '=';
        out[j + 3] = (i + 2 < in_len) ? b64_table[val & 0x3F] : '=';
    }
    
    *out_len = j;
    return 0;
}

/* Helper for base64 decoding */
static int b64_decode_value(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    } else if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    } else if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    } else if (c == '+') {
        return 62;
    } else if (c == '/') {
        return 63;
    } else if (c == '=') {
        return 0;  /* Padding */
    }
    return -1;  /* Invalid character */
}

size_t util_base64_decode_len(const char* in, size_t in_len) {
    size_t padding = 0;
    
    if (in_len == 0) {
        return 0;
    }
    
    /* Check for padding characters at the end */
    if (in[in_len - 1] == '=') padding++;
    if (in_len > 1 && in[in_len - 2] == '=') padding++;
    
    /* Each 4 characters of input produces 3 bytes of output (minus padding) */
    return (in_len / 4) * 3 - padding;
}

int util_base64_decode(const char* in, size_t in_len, uint8_t* out, size_t* out_len) {
    size_t i, j;
    size_t output_size = util_base64_decode_len(in, in_len);
    
    if (!in || !out || !out_len || *out_len < output_size) {
        if (out_len) {
            *out_len = output_size;
        }
        return -1;
    }
    
    /* Base64 input must be a multiple of 4 characters */
    if (in_len % 4 != 0) {
        return -1;
    }
    
    for (i = 0, j = 0; i < in_len; i += 4) {
        int v1 = b64_decode_value(in[i]);
        int v2 = b64_decode_value(in[i + 1]);
        int v3 = b64_decode_value(in[i + 2]);
        int v4 = b64_decode_value(in[i + 3]);
        
        if (v1 < 0 || v2 < 0 || v3 < 0 || v4 < 0) {
            return -1;  /* Invalid character */
        }
        
        uint32_t val = (v1 << 18) | (v2 << 12) | (v3 << 6) | v4;
        
        if (j < *out_len) out[j++] = (val >> 16) & 0xFF;
        if (in[i + 2] != '=' && j < *out_len) out[j++] = (val >> 8) & 0xFF;
        if (in[i + 3] != '=' && j < *out_len) out[j++] = val & 0xFF;
    }
    
    *out_len = j;
    return 0;
}

/* Hex encoding/decoding */

size_t util_hex_encode_len(size_t in_len) {
    return in_len * 2;  /* Each byte becomes two hex characters */
}

int util_hex_encode(const uint8_t* in, size_t in_len, char* out, size_t* out_len) {
    static const char hex_table[] = "0123456789abcdef";
    size_t i, j;
    size_t output_size = util_hex_encode_len(in_len);
    
    if (!in || !out || !out_len || *out_len < output_size) {
        if (out_len) {
            *out_len = output_size;
        }
        return -1;
    }
    
    for (i = 0, j = 0; i < in_len; i++, j += 2) {
        out[j] = hex_table[(in[i] >> 4) & 0xF];
        out[j + 1] = hex_table[in[i] & 0xF];
    }
    
    *out_len = j;
    return 0;
}

/* Helper for hex decoding */
static int hex_decode_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;  /* Invalid character */
}

size_t util_hex_decode_len(const char* in, size_t in_len) {
    return in_len / 2;  /* Two hex characters become one byte */
}

int util_hex_decode(const char* in, size_t in_len, uint8_t* out, size_t* out_len) {
    size_t i, j;
    size_t output_size = util_hex_decode_len(in, in_len);
    
    if (!in || !out || !out_len || *out_len < output_size) {
        if (out_len) {
            *out_len = output_size;
        }
        return -1;
    }
    
    /* Hex input must have an even number of characters */
    if (in_len % 2 != 0) {
        return -1;
    }
    
    for (i = 0, j = 0; i < in_len; i += 2, j++) {
        int high = hex_decode_value(in[i]);
        int low = hex_decode_value(in[i + 1]);
        
        if (high < 0 || low < 0) {
            return -1;  /* Invalid character */
        }
        
        out[j] = (high << 4) | low;
    }
    
    *out_len = j;
    return 0;
}

/* String operations */
char* util_strdup(const char* str) {
    size_t len;
    char* dup;
    
    if (!str) {
        return NULL;
    }
    
    len = strlen(str) + 1;
    dup = (char*)platform_malloc(len);
    if (dup) {
        memcpy(dup, str, len);
    }
    
    return dup;
}

int util_strcasecmp(const char* s1, const char* s2) {
    unsigned char c1, c2;
    
    while (*s1 && *s2) {
        c1 = *s1++;
        c2 = *s2++;
        
        /* Convert to lowercase */
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 += 'a' - 'A';
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 += 'a' - 'A';
        }
        
        if (c1 != c2) {
            return c1 - c2;
        }
    }
    
    return *s1 - *s2;
}

size_t util_strlcpy(char* dst, const char* src, size_t size) {
    size_t src_len = strlen(src);
    
    if (size > 0) {
        size_t copy_len = (src_len < size - 1) ? src_len : size - 1;
        memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }
    
    return src_len;
}