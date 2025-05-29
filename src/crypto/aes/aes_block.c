/**
 * @file aes_block.c
 * @brief AES block encryption/decryption implementation
 */

#include "crypto/aes.h"
#include <string.h>

/* AES S-box lookup */
#define SBOX(x) sbox[(x)]
#define INV_SBOX(x) inv_sbox[(x)]

/* External S-boxes defined in aes.c */
extern const uint8_t sbox[256];
extern const uint8_t inv_sbox[256];

/* AES operations */
#define AES_ROUNDS(keysize) ((keysize) == 16 ? 10 : (keysize) == 24 ? 12 : 14)

/* Galois field multiplication */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t high_bit;
    int i;
    
    for (i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        
        high_bit = (a & 0x80);
        a <<= 1;
        if (high_bit) {
            a ^= 0x1b;  /* XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1 */
        }
        
        b >>= 1;
    }
    
    return p;
}

/* AES state operations */
static void sub_bytes(uint8_t state[4][4]) {
    int i, j;
    
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = SBOX(state[i][j]);
        }
    }
}

static void inv_sub_bytes(uint8_t state[4][4]) {
    int i, j;
    
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = INV_SBOX(state[i][j]);
        }
    }
}

static void shift_rows(uint8_t state[4][4]) {
    uint8_t temp;
    
    /* Row 1: shift left by 1 */
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    
    /* Row 2: shift left by 2 */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    /* Row 3: shift left by 3 (or right by 1) */
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

static void inv_shift_rows(uint8_t state[4][4]) {
    uint8_t temp;
    
    /* Row 1: shift right by 1 */
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    
    /* Row 2: shift right by 2 */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    /* Row 3: shift right by 3 (or left by 1) */
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

static void mix_columns(uint8_t state[4][4]) {
    int c;
    uint8_t s[4];
    
    for (c = 0; c < 4; c++) {
        s[0] = state[0][c];
        s[1] = state[1][c];
        s[2] = state[2][c];
        s[3] = state[3][c];
        
        state[0][c] = gf_mul(0x02, s[0]) ^ gf_mul(0x03, s[1]) ^ s[2] ^ s[3];
        state[1][c] = s[0] ^ gf_mul(0x02, s[1]) ^ gf_mul(0x03, s[2]) ^ s[3];
        state[2][c] = s[0] ^ s[1] ^ gf_mul(0x02, s[2]) ^ gf_mul(0x03, s[3]);
        state[3][c] = gf_mul(0x03, s[0]) ^ s[1] ^ s[2] ^ gf_mul(0x02, s[3]);
    }
}

static void inv_mix_columns(uint8_t state[4][4]) {
    int c;
    uint8_t s[4];
    
    for (c = 0; c < 4; c++) {
        s[0] = state[0][c];
        s[1] = state[1][c];
        s[2] = state[2][c];
        s[3] = state[3][c];
        
        state[0][c] = gf_mul(0x0e, s[0]) ^ gf_mul(0x0b, s[1]) ^ gf_mul(0x0d, s[2]) ^ gf_mul(0x09, s[3]);
        state[1][c] = gf_mul(0x09, s[0]) ^ gf_mul(0x0e, s[1]) ^ gf_mul(0x0b, s[2]) ^ gf_mul(0x0d, s[3]);
        state[2][c] = gf_mul(0x0d, s[0]) ^ gf_mul(0x09, s[1]) ^ gf_mul(0x0e, s[2]) ^ gf_mul(0x0b, s[3]);
        state[3][c] = gf_mul(0x0b, s[0]) ^ gf_mul(0x0d, s[1]) ^ gf_mul(0x09, s[2]) ^ gf_mul(0x0e, s[3]);
    }
}

static void add_round_key(uint8_t state[4][4], const uint32_t* key) {
    int i, j;
    
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] ^= (key[i] >> (24 - j * 8)) & 0xFF;
        }
    }
}

/* AES block encryption */
void aes_encrypt_block(const aes_ctx_t* ctx, const uint8_t* in, uint8_t* out) {
    uint8_t state[4][4];
    int i, j, r;
    
    /* Copy input to state array (column-major order) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] = in[i * 4 + j];
        }
    }
    
    /* Initial round key addition */
    add_round_key(state, ctx->round_keys);
    
    /* Main rounds */
    for (r = 1; r < ctx->rounds; r++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->round_keys[r * 4]);
    }
    
    /* Final round (no mix_columns) */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx->round_keys[ctx->rounds * 4]);
    
    /* Copy state to output (column-major order) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            out[i * 4 + j] = state[j][i];
        }
    }
}

/* AES block decryption */
void aes_decrypt_block(const aes_ctx_t* ctx, const uint8_t* in, uint8_t* out) {
    uint8_t state[4][4];
    int i, j, r;
    
    /* Copy input to state array (column-major order) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] = in[i * 4 + j];
        }
    }
    
    /* Initial round key addition */
    add_round_key(state, &ctx->round_keys[ctx->rounds * 4]);
    
    /* Main rounds */
    for (r = ctx->rounds - 1; r > 0; r--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &ctx->round_keys[r * 4]);
        inv_mix_columns(state);
    }
    
    /* Final round */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, ctx->round_keys);
    
    /* Copy state to output (column-major order) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            out[i * 4 + j] = state[j][i];
        }
    }
}