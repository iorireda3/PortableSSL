/**
 * @file sha256.c
 * @brief Implementation of SHA-256 hash function
 */

#include "crypto/sha256.h"
#include "util/util.h"
#include <string.h>

/* SHA-256 implementation constants */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define SHR(x, n) ((x) >> (n))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Initialize SHA-256 context */
void sha256_init(sha256_ctx_t* ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    memset(ctx->buffer, 0, SHA256_BLOCK_SIZE);
}

/* Process a single block of data */
static void sha256_process_block(sha256_ctx_t* ctx, const uint8_t* block) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t W[64];
    uint32_t T1, T2;
    uint32_t i;
    
    /* Prepare the message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }
    
    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    
    /* Main loop */
    for (i = 0; i < 64; i++) {
        T1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        T2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    
    /* Update state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

/* Update SHA-256 context with data */
void sha256_update(sha256_ctx_t* ctx, const uint8_t* data, size_t len) {
    size_t i, index, part_len;
    
    /* Compute number of bytes mod 64 */
    index = (size_t)((ctx->count >> 3) & 0x3F);
    
    /* Update bit count */
    ctx->count += (len << 3);
    
    /* Transform as many times as possible */
    part_len = SHA256_BLOCK_SIZE - index;
    if (len >= part_len) {
        memcpy(&ctx->buffer[index], data, part_len);
        sha256_process_block(ctx, ctx->buffer);
        
        for (i = part_len; i + SHA256_BLOCK_SIZE - 1 < len; i += SHA256_BLOCK_SIZE) {
            sha256_process_block(ctx, &data[i]);
        }
        
        index = 0;
    } else {
        i = 0;
    }
    
    /* Buffer remaining input */
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

/* Finalize SHA-256 hash computation */
void sha256_final(sha256_ctx_t* ctx, uint8_t digest[SHA256_DIGEST_LENGTH]) {
    uint8_t bits[8];
    size_t index, pad_len;
    uint64_t count = ctx->count;
    
    /* Save the bit count */
    for (index = 0; index < 8; index++) {
        bits[index] = (uint8_t)((count >> ((7 - index) * 8)) & 0xFF);
    }
    
    /* Pad out to 56 mod 64 */
    index = (size_t)((ctx->count >> 3) & 0x3F);
    pad_len = (index < 56) ? (56 - index) : (120 - index);
    
    {
        uint8_t padding[64] = { 0x80 };  /* First byte is 0x80, rest are 0 */
        sha256_update(ctx, padding, pad_len);
    }
    
    /* Append length */
    sha256_update(ctx, bits, 8);
    
    /* Store state in digest */
    for (index = 0; index < 8; index++) {
        digest[index * 4] = (uint8_t)((ctx->state[index] >> 24) & 0xFF);
        digest[index * 4 + 1] = (uint8_t)((ctx->state[index] >> 16) & 0xFF);
        digest[index * 4 + 2] = (uint8_t)((ctx->state[index] >> 8) & 0xFF);
        digest[index * 4 + 3] = (uint8_t)(ctx->state[index] & 0xFF);
    }
    
    /* Clear sensitive information */
    util_secure_zero(ctx, sizeof(sha256_ctx_t));
}

/* All-in-one function */
void sha256(const uint8_t* data, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]) {
    sha256_ctx_t ctx;
    
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* HMAC-SHA256 implementation */
void hmac_sha256(const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len,
                uint8_t digest[SHA256_DIGEST_LENGTH]) {
    sha256_ctx_t ctx;
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t tk[SHA256_DIGEST_LENGTH];
    size_t i;
    
    /* If key is longer than block size, hash it */
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, tk);
        key = tk;
        key_len = SHA256_DIGEST_LENGTH;
    }
    
    /* Prepare inner and outer padded keys */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    
    /* Inner hash: H(K XOR ipad || data) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, digest);
    
    /* Outer hash: H(K XOR opad || inner_hash) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, digest, SHA256_DIGEST_LENGTH);
    sha256_final(&ctx, digest);
    
    /* Clean up sensitive data */
    util_secure_zero(k_ipad, sizeof(k_ipad));
    util_secure_zero(k_opad, sizeof(k_opad));
    util_secure_zero(tk, sizeof(tk));
}