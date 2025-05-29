/**
 * @file test_aes.c
 * @brief Test AES implementation
 */

#include "crypto/aes.h"
#include <stdio.h>
#include <string.h>

/* Test vectors from FIPS-197 */
static const uint8_t aes_test_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const uint8_t aes_test_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const uint8_t aes_test_plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const uint8_t aes_test_ciphertext[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

static int test_aes_ecb(void) {
    aes_ctx_t ctx;
    uint8_t out[16];
    int result = 0;
    
    printf("Testing AES-ECB...\n");
    
    /* Encryption */
    if (aes_set_encrypt_key(&ctx, aes_test_key, sizeof(aes_test_key)) != 0) {
        printf("FAIL: aes_set_encrypt_key\n");
        return 1;
    }
    
    aes_encrypt_block(&ctx, aes_test_plaintext, out);
    
    if (memcmp(out, aes_test_ciphertext, 16) != 0) {
        printf("FAIL: aes_encrypt_block mismatch\n");
        result = 1;
    } else {
        printf("PASS: aes_encrypt_block\n");
    }
    
    /* Decryption */
    if (aes_set_decrypt_key(&ctx, aes_test_key, sizeof(aes_test_key)) != 0) {
        printf("FAIL: aes_set_decrypt_key\n");
        return 1;
    }
    
    aes_decrypt_block(&ctx, aes_test_ciphertext, out);
    
    if (memcmp(out, aes_test_plaintext, 16) != 0) {
        printf("FAIL: aes_decrypt_block mismatch\n");
        result = 1;
    } else {
        printf("PASS: aes_decrypt_block\n");
    }
    
    return result;
}

static int test_aes_cbc(void) {
    aes_mode_ctx_t ctx;
    uint8_t out[32];
    uint8_t dec[32];
    size_t out_len, dec_len;
    int result = 0;
    
    printf("Testing AES-CBC...\n");
    
    /* Initialize context */
    if (aes_mode_init(&ctx, AES_MODE_CBC, aes_test_key, sizeof(aes_test_key), aes_test_iv) != 0) {
        printf("FAIL: aes_mode_init\n");
        return 1;
    }
    
    /* Encrypt */
    out_len = sizeof(out);
    if (aes_encrypt(&ctx, aes_test_plaintext, sizeof(aes_test_plaintext), out, &out_len) != 0) {
        printf("FAIL: aes_encrypt\n");
        return 1;
    }
    
    /* Decrypt */
    aes_mode_ctx_cleanup(&ctx);
    if (aes_mode_init(&ctx, AES_MODE_CBC, aes_test_key, sizeof(aes_test_key), aes_test_iv) != 0) {
        printf("FAIL: aes_mode_init (decrypt)\n");
        return 1;
    }
    
    dec_len = sizeof(dec);
    if (aes_decrypt(&ctx, out, out_len, dec, &dec_len) != 0) {
        printf("FAIL: aes_decrypt\n");
        result = 1;
    }
    
    if (dec_len != sizeof(aes_test_plaintext) || 
        memcmp(dec, aes_test_plaintext, sizeof(aes_test_plaintext)) != 0) {
        printf("FAIL: aes_decrypt mismatch\n");
        result = 1;
    } else {
        printf("PASS: AES-CBC encrypt/decrypt\n");
    }
    
    aes_mode_ctx_cleanup(&ctx);
    return result;
}

int main(void) {
    int result = 0;
    
    printf("=== AES Tests ===\n");
    
    result |= test_aes_ecb();
    result |= test_aes_cbc();
    
    if (result == 0) {
        printf("All AES tests passed!\n");
    } else {
        printf("Some AES tests failed.\n");
    }
    
    return result;
}