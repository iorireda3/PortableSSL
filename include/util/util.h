/**
 * @file util.h
 * @brief Utility functions
 */

#ifndef PORTABLE_SSL_UTIL_H
#define PORTABLE_SSL_UTIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Memory operations */
void util_secure_zero(void* ptr, size_t len);
int util_constant_time_eq(const void* a, const void* b, size_t len);

/* Byte order conversion */
uint16_t util_htons(uint16_t val);
uint16_t util_ntohs(uint16_t val);
uint32_t util_htonl(uint32_t val);
uint32_t util_ntohl(uint32_t val);

/* Base64 encoding/decoding */
size_t util_base64_encode_len(size_t in_len);
int util_base64_encode(const uint8_t* in, size_t in_len, char* out, size_t* out_len);
size_t util_base64_decode_len(const char* in, size_t in_len);
int util_base64_decode(const char* in, size_t in_len, uint8_t* out, size_t* out_len);

/* Hex encoding/decoding */
size_t util_hex_encode_len(size_t in_len);
int util_hex_encode(const uint8_t* in, size_t in_len, char* out, size_t* out_len);
size_t util_hex_decode_len(const char* in, size_t in_len);
int util_hex_decode(const char* in, size_t in_len, uint8_t* out, size_t* out_len);

/* String operations */
char* util_strdup(const char* str);
int util_strcasecmp(const char* s1, const char* s2);
size_t util_strlcpy(char* dst, const char* src, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_SSL_UTIL_H */