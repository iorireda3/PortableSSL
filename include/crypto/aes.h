/**
 * @file aes.h
 * @brief AES encryption/decryption functionality
 */

#ifndef PORTABLE_SSL_AES_H
#define PORTABLE_SSL_AES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AES key sizes */
#define AES_128_KEY_SIZE 16
#define AES_192_KEY_SIZE 24
#define AES_256_KEY_SIZE 32

/* AES block size */
#define AES_BLOCK_SIZE 16

/* AES context structure */
typedef struct aes_ctx_st {
    uint32_t round_keys[60];
    int rounds;
} aes_ctx_t;

/* AES modes of operation */
typedef enum {
    AES_MODE_ECB,
    AES_MODE_CBC,
    AES_MODE_CTR,
    AES_MODE_GCM
} aes_mode_t;

/* AES context for modes of operation */
typedef struct aes_mode_ctx_st {
    aes_ctx_t aes;
    aes_mode_t mode;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t counter[AES_BLOCK_SIZE];
    /* GCM specific fields */
    uint8_t auth_tag[16];
    size_t auth_tag_len;
    uint64_t aad_len;
    uint64_t pt_len;
    uint8_t H[16]; /* GCM subkey */
    uint8_t J0[16]; /* Initial counter block */
} aes_mode_ctx_t;

/* AES key setup */
int aes_set_encrypt_key(aes_ctx_t* ctx, const uint8_t* key, size_t key_len);
int aes_set_decrypt_key(aes_ctx_t* ctx, const uint8_t* key, size_t key_len);

/* AES ECB mode (single block) */
void aes_encrypt_block(const aes_ctx_t* ctx, const uint8_t* in, uint8_t* out);
void aes_decrypt_block(const aes_ctx_t* ctx, const uint8_t* in, uint8_t* out);

/* AES mode operations */
int aes_mode_init(aes_mode_ctx_t* ctx, aes_mode_t mode, const uint8_t* key, size_t key_len, const uint8_t* iv);
int aes_encrypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len);
int aes_decrypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len);

/* AES-GCM specific operations */
int aes_gcm_update_aad(aes_mode_ctx_t* ctx, const uint8_t* aad, size_t aad_len);
int aes_gcm_get_tag(aes_mode_ctx_t* ctx, uint8_t* tag, size_t tag_len);
int aes_gcm_verify_tag(aes_mode_ctx_t* ctx, const uint8_t* tag, size_t tag_len);

/* Clean up contexts */
void aes_ctx_cleanup(aes_ctx_t* ctx);
void aes_mode_ctx_cleanup(aes_mode_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_SSL_AES_H */