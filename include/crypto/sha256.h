/**
 * @file sha256.h
 * @brief SHA-256 hash function
 */

#ifndef PORTABLE_SSL_SHA256_H
#define PORTABLE_SSL_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

typedef struct sha256_ctx_st {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_ctx_t;

/* Initialize SHA-256 context */
void sha256_init(sha256_ctx_t* ctx);

/* Update SHA-256 context with data */
void sha256_update(sha256_ctx_t* ctx, const uint8_t* data, size_t len);

/* Finalize SHA-256 hash computation */
void sha256_final(sha256_ctx_t* ctx, uint8_t digest[SHA256_DIGEST_LENGTH]);

/* All-in-one function */
void sha256(const uint8_t* data, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]);

/* HMAC-SHA256 */
void hmac_sha256(const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len,
                uint8_t digest[SHA256_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_SSL_SHA256_H */