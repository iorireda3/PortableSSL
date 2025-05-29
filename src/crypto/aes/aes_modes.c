/**
 * @file aes_modes.c
 * @brief AES modes of operation implementation
 */

#include "crypto/aes.h"
#include "util/util.h"
#include <string.h>

/* Increment counter (big-endian) */
static void increment_counter(uint8_t* counter) {
    int i;
    
    for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

/* AES-ECB encryption */
static int aes_ecb_encrypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, 
                          uint8_t* out, size_t* out_len) {
    size_t i;
    
    /* ECB mode requires input length to be a multiple of block size */
    if (in_len % AES_BLOCK_SIZE != 0) {
        return -1;
    }
    
    if (*out_len < in_len) {
        *out_len = in_len;
        return -1;
    }
    
    for (i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        aes_encrypt_block(&ctx->aes, &in[i], &out[i]);
    }
    
    *out_len = in_len;
    return 0;
}

/* AES-ECB decryption */
static int aes_ecb_decrypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, 
                          uint8_t* out, size_t* out_len) {
    size_t i;
    
    /* ECB mode requires input length to be a multiple of block size */
    if (in_len % AES_BLOCK_SIZE != 0) {
        return -1;
    }
    
    if (*out_len < in_len) {
        *out_len = in_len;
        return -1;
    }
    
    for (i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        aes_decrypt_block(&ctx->aes, &in[i], &out[i]);
    }
    
    *out_len = in_len;
    return 0;
}

/* AES-CBC encryption */
static int aes_cbc_encrypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, 
                          uint8_t* out, size_t* out_len) {
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    size_t i, j;
    
    /* CBC mode requires input length to be a multiple of block size */
    if (in_len % AES_BLOCK_SIZE != 0) {
        return -1;
    }
    
    if (*out_len < in_len) {
        *out_len = in_len;
        return -1;
    }
    
    /* Use current IV */
    memcpy(iv, ctx->iv, AES_BLOCK_SIZE);
    
    for (i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        /* XOR input with IV/previous ciphertext block */
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] = in[i + j] ^ iv[j];
        }
        
        /* Encrypt */
        aes_encrypt_block(&ctx->aes, block, &out[i]);
        
        /* Update IV for next block */
        memcpy(iv, &out[i], AES_BLOCK_SIZE);
    }
    
    /* Save final IV for next call */
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    
    *out_len = in_len;
    return 0;
}

/* AES-CBC decryption */
static int aes_cbc_decrypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, 
                          uint8_t* out, size_t* out_len) {
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t next_iv[AES_BLOCK_SIZE];
    size_t i, j;
    
    /* CBC mode requires input length to be a multiple of block size */
    if (in_len % AES_BLOCK_SIZE != 0) {
        return -1;
    }
    
    if (*out_len < in_len) {
        *out_len = in_len;
        return -1;
    }
    
    /* Use current IV */
    memcpy(iv, ctx->iv, AES_BLOCK_SIZE);
    
    for (i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        /* Save current ciphertext block as next IV */
        memcpy(next_iv, &in[i], AES_BLOCK_SIZE);
        
        /* Decrypt */
        aes_decrypt_block(&ctx->aes, &in[i], &out[i]);
        
        /* XOR with IV/previous ciphertext block */
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            out[i + j] ^= iv[j];
        }
        
        /* Update IV for next block */
        memcpy(iv, next_iv, AES_BLOCK_SIZE);
    }
    
    /* Save final IV for next call */
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    
    *out_len = in_len;
    return 0;
}

/* AES-CTR encryption/decryption (same operation) */
static int aes_ctr_crypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, 
                         uint8_t* out, size_t* out_len) {
    uint8_t counter_block[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    size_t i, j, blocks, remainder;
    
    if (*out_len < in_len) {
        *out_len = in_len;
        return -1;
    }
    
    blocks = in_len / AES_BLOCK_SIZE;
    remainder = in_len % AES_BLOCK_SIZE;
    
    /* Process complete blocks */
    for (i = 0; i < blocks; i++) {
        /* Encrypt counter to create keystream */
        memcpy(counter_block, ctx->counter, AES_BLOCK_SIZE);
        aes_encrypt_block(&ctx->aes, counter_block, keystream);
        
        /* XOR input with keystream */
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            out[i * AES_BLOCK_SIZE + j] = in[i * AES_BLOCK_SIZE + j] ^ keystream[j];
        }
        
        /* Increment counter */
        increment_counter(ctx->counter);
    }
    
    /* Process remaining bytes */
    if (remainder > 0) {
        /* Encrypt counter to create keystream */
        memcpy(counter_block, ctx->counter, AES_BLOCK_SIZE);
        aes_encrypt_block(&ctx->aes, counter_block, keystream);
        
        /* XOR remaining bytes */
        for (j = 0; j < remainder; j++) {
            out[blocks * AES_BLOCK_SIZE + j] = in[blocks * AES_BLOCK_SIZE + j] ^ keystream[j];
        }
        
        /* Increment counter */
        increment_counter(ctx->counter);
    }
    
    *out_len = in_len;
    return 0;
}

/* AES encryption using the configured mode */
int aes_encrypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len) {
    if (!ctx || !in || !out || !out_len) {
        return -1;
    }
    
    switch (ctx->mode) {
        case AES_MODE_ECB:
            return aes_ecb_encrypt(ctx, in, in_len, out, out_len);
        case AES_MODE_CBC:
            return aes_cbc_encrypt(ctx, in, in_len, out, out_len);
        case AES_MODE_CTR:
            return aes_ctr_crypt(ctx, in, in_len, out, out_len);
        case AES_MODE_GCM:
            /* GCM would be implemented separately due to its complexity */
            return -1;
        default:
            return -1;
    }
}

/* AES decryption using the configured mode */
int aes_decrypt(aes_mode_ctx_t* ctx, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len) {
    if (!ctx || !in || !out || !out_len) {
        return -1;
    }
    
    switch (ctx->mode) {
        case AES_MODE_ECB:
            return aes_ecb_decrypt(ctx, in, in_len, out, out_len);
        case AES_MODE_CBC:
            return aes_cbc_decrypt(ctx, in, in_len, out, out_len);
        case AES_MODE_CTR:
            return aes_ctr_crypt(ctx, in, in_len, out, out_len);
        case AES_MODE_GCM:
            /* GCM would be implemented separately due to its complexity */
            return -1;
        default:
            return -1;
    }
}

/* Update AAD data for GCM mode */
int aes_gcm_update_aad(aes_mode_ctx_t* ctx, const uint8_t* aad, size_t aad_len) {
    if (!ctx || (aad_len > 0 && !aad)) {
        return -1;
    }
    
    if (ctx->mode != AES_MODE_GCM) {
        return -1;
    }
    
    /* GCM-specific AAD processing would go here */
    ctx->aad_len += aad_len;
    
    return 0;
}

/* Get authentication tag for GCM mode */
int aes_gcm_get_tag(aes_mode_ctx_t* ctx, uint8_t* tag, size_t tag_len) {
    if (!ctx || !tag || tag_len == 0 || tag_len > 16) {
        return -1;
    }
    
    if (ctx->mode != AES_MODE_GCM) {
        return -1;
    }
    
    /* Copy tag to output */
    memcpy(tag, ctx->auth_tag, tag_len);
    ctx->auth_tag_len = tag_len;
    
    return 0;
}

/* Verify authentication tag for GCM mode */
int aes_gcm_verify_tag(aes_mode_ctx_t* ctx, const uint8_t* tag, size_t tag_len) {
    if (!ctx || !tag || tag_len == 0 || tag_len > 16 || ctx->auth_tag_len == 0) {
        return -1;
    }
    
    if (ctx->mode != AES_MODE_GCM) {
        return -1;
    }
    
    /* Compare tags in constant time */
    if (!util_constant_time_eq(ctx->auth_tag, tag, tag_len)) {
        return -1;
    }
    
    return 0;
}