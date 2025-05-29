/**
 * @file rsa_oaep.c
 * @brief RSA OAEP padding implementation
 */

#include "crypto/rsa.h"
#include "crypto/sha256.h"
#include "platform/platform.h"
#include "util/util.h"
#include <string.h>

/* OAEP parameters */
#define OAEP_LABEL_HASH_SIZE SHA256_DIGEST_LENGTH

/* MGF1 mask generation function */
static int mgf1_sha256(const uint8_t* seed, size_t seed_len,
                      uint8_t* mask, size_t mask_len) {
    uint8_t counter[4];
    uint8_t hash[SHA256_DIGEST_LENGTH];
    size_t remaining = mask_len;
    size_t offset = 0;
    uint32_t counter_num = 0;
    
    while (remaining > 0) {
        /* Convert counter to big-endian bytes */
        counter[0] = (counter_num >> 24) & 0xFF;
        counter[1] = (counter_num >> 16) & 0xFF;
        counter[2] = (counter_num >> 8) & 0xFF;
        counter[3] = counter_num & 0xFF;
        
        /* Calculate hash of seed || counter */
        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, seed, seed_len);
        sha256_update(&ctx, counter, 4);
        sha256_final(&ctx, hash);
        
        /* Copy hash to mask buffer */
        size_t to_copy = (remaining < SHA256_DIGEST_LENGTH) ? 
                        remaining : SHA256_DIGEST_LENGTH;
        memcpy(mask + offset, hash, to_copy);
        
        offset += to_copy;
        remaining -= to_copy;
        counter_num++;
    }
    
    return 0;
}

/* OAEP padding for encryption */
int rsa_oaep_pad(const uint8_t* in, size_t in_len,
                 uint8_t* out, size_t* out_len,
                 size_t modulus_len) {
    uint8_t* db;
    uint8_t* seed;
    uint8_t* db_mask;
    uint8_t* seed_mask;
    size_t db_len;
    int result = -1;
    
    if (!in || !out || !out_len || modulus_len < 2 * SHA256_DIGEST_LENGTH + 2) {
        return -1;
    }
    
    /* Check if message is too long */
    if (in_len > modulus_len - 2 * SHA256_DIGEST_LENGTH - 2) {
        return -1;
    }
    
    /* Allocate temporary buffers */
    db = platform_malloc(modulus_len - SHA256_DIGEST_LENGTH);
    seed = platform_malloc(SHA256_DIGEST_LENGTH);
    db_mask = platform_malloc(modulus_len - SHA256_DIGEST_LENGTH);
    seed_mask = platform_malloc(SHA256_DIGEST_LENGTH);
    
    if (!db || !seed || !db_mask || !seed_mask) {
        goto cleanup;
    }
    
    /* Generate random seed */
    if (crypto_random_bytes(seed, SHA256_DIGEST_LENGTH) != 0) {
        goto cleanup;
    }
    
    /* Construct DB: lHash || PS || 0x01 || M */
    db_len = modulus_len - SHA256_DIGEST_LENGTH;
    memset(db, 0, db_len);
    /* TODO: Add label hash at the beginning */
    /* Add message at the end with 0x01 separator */
    db[db_len - in_len - 1] = 0x01;
    memcpy(db + db_len - in_len, in, in_len);
    
    /* Generate masks */
    if (mgf1_sha256(seed, SHA256_DIGEST_LENGTH, db_mask, db_len) != 0) {
        goto cleanup;
    }
    if (mgf1_sha256(db_mask, db_len, seed_mask, SHA256_DIGEST_LENGTH) != 0) {
        goto cleanup;
    }
    
    /* XOR operations */
    for (size_t i = 0; i < db_len; i++) {
        db[i] ^= db_mask[i];
    }
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        seed[i] ^= seed_mask[i];
    }
    
    /* Construct output: 0x00 || maskedSeed || maskedDB */
    out[0] = 0x00;
    memcpy(out + 1, seed, SHA256_DIGEST_LENGTH);
    memcpy(out + SHA256_DIGEST_LENGTH + 1, db, db_len);
    *out_len = modulus_len;
    
    result = 0;
    
cleanup:
    if (db) platform_free(db);
    if (seed) platform_free(seed);
    if (db_mask) platform_free(db_mask);
    if (seed_mask) platform_free(seed_mask);
    
    return result;
}

/* OAEP unpadding for decryption */
int rsa_oaep_unpad(const uint8_t* in, size_t in_len,
                   uint8_t* out, size_t* out_len) {
    uint8_t* db;
    uint8_t* seed;
    uint8_t* db_mask;
    uint8_t* seed_mask;
    size_t db_len;
    int result = -1;
    size_t i;
    
    if (!in || !out || !out_len || in_len < 2 * SHA256_DIGEST_LENGTH + 2) {
        return -1;
    }
    
    /* Check leading zero */
    if (in[0] != 0x00) {
        return -1;
    }
    
    /* Allocate temporary buffers */
    db_len = in_len - SHA256_DIGEST_LENGTH - 1;
    db = platform_malloc(db_len);
    seed = platform_malloc(SHA256_DIGEST_LENGTH);
    db_mask = platform_malloc(db_len);
    seed_mask = platform_malloc(SHA256_DIGEST_LENGTH);
    
    if (!db || !seed || !db_mask || !seed_mask) {
        goto cleanup;
    }
    
    /* Extract masked seed and DB */
    memcpy(seed, in + 1, SHA256_DIGEST_LENGTH);
    memcpy(db, in + SHA256_DIGEST_LENGTH + 1, db_len);
    
    /* Generate masks */
    if (mgf1_sha256(db, db_len, seed_mask, SHA256_DIGEST_LENGTH) != 0) {
        goto cleanup;
    }
    if (mgf1_sha256(seed, SHA256_DIGEST_LENGTH, db_mask, db_len) != 0) {
        goto cleanup;
    }
    
    /* XOR operations */
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        seed[i] ^= seed_mask[i];
    }
    for (i = 0; i < db_len; i++) {
        db[i] ^= db_mask[i];
    }
    
    /* TODO: Verify label hash */
    
    /* Find message start */
    for (i = 0; i < db_len; i++) {
        if (db[i] == 0x01) {
            break;
        }
        if (db[i] != 0x00) {
            goto cleanup;  /* Invalid padding */
        }
    }
    
    if (i == db_len) {
        goto cleanup;  /* No message separator found */
    }
    
    /* Extract message */
    i++;  /* Skip 0x01 separator */
    *out_len = db_len - i;
    memcpy(out, db + i, *out_len);
    
    result = 0;
    
cleanup:
    if (db) platform_free(db);
    if (seed) platform_free(seed);
    if (db_mask) platform_free(db_mask);
    if (seed_mask) platform_free(seed_mask);
    
    return result;
}