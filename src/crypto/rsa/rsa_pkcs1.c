/**
 * @file rsa_pkcs1.c
 * @brief RSA PKCS#1 v1.5 padding implementation
 */

#include "crypto/rsa.h"
#include "crypto/sha256.h"
#include "platform/platform.h"
#include "util/util.h"
#include <string.h>

/* PKCS#1 v1.5 padding for encryption */
int rsa_pkcs1_pad(const uint8_t* in, size_t in_len,
                  uint8_t* out, size_t* out_len,
                  size_t modulus_len) {
    size_t ps_len;
    
    if (!in || !out || !out_len || modulus_len < 11) {
        return -1;
    }
    
    /* Check if message is too long */
    if (in_len > modulus_len - 11) {
        return -1;
    }
    
    /* Calculate padding string length */
    ps_len = modulus_len - in_len - 3;
    
    /* Format: 00 || 02 || PS || 00 || M */
    out[0] = 0x00;
    out[1] = 0x02;
    
    /* Generate random padding string */
    if (crypto_random_bytes(out + 2, ps_len) != 0) {
        return -1;
    }
    
    /* Ensure no zero bytes in padding string */
    for (size_t i = 0; i < ps_len; i++) {
        if (out[i + 2] == 0x00) {
            out[i + 2] = 0x01;  /* Replace with non-zero value */
        }
    }
    
    /* Add separator and message */
    out[ps_len + 2] = 0x00;
    memcpy(out + ps_len + 3, in, in_len);
    
    *out_len = modulus_len;
    return 0;
}

/* PKCS#1 v1.5 unpadding for decryption */
int rsa_pkcs1_unpad(const uint8_t* in, size_t in_len,
                    uint8_t* out, size_t* out_len) {
    size_t i;
    
    if (!in || !out || !out_len || in_len < 11) {
        return -1;
    }
    
    /* Check format */
    if (in[0] != 0x00 || in[1] != 0x02) {
        return -1;
    }
    
    /* Find message separator */
    for (i = 2; i < in_len; i++) {
        if (in[i] == 0x00) {
            break;
        }
    }
    
    /* Check separator position */
    if (i == in_len || i < 10) {  /* At least 8 bytes of padding */
        return -1;
    }
    
    /* Extract message */
    i++;  /* Skip separator */
    *out_len = in_len - i;
    memcpy(out, in + i, *out_len);
    
    return 0;
}

/* PKCS#1 v1.5 signature padding */
int rsa_pkcs1_sign_pad(const uint8_t* hash, size_t hash_len,
                       uint8_t* out, size_t* out_len,
                       size_t modulus_len) {
    static const uint8_t sha256_prefix[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    };
    size_t prefix_len = sizeof(sha256_prefix);
    size_t total_len = prefix_len + hash_len;
    size_t ps_len;
    
    if (!hash || !out || !out_len || modulus_len < total_len + 11) {
        return -1;
    }
    
    /* Calculate padding length */
    ps_len = modulus_len - total_len - 3;
    
    /* Format: 00 || 01 || PS || 00 || T */
    out[0] = 0x00;
    out[1] = 0x01;
    
    /* Add padding string (0xFF) */
    memset(out + 2, 0xFF, ps_len);
    
    /* Add separator */
    out[ps_len + 2] = 0x00;
    
    /* Add DigestInfo prefix and hash */
    memcpy(out + ps_len + 3, sha256_prefix, prefix_len);
    memcpy(out + ps_len + 3 + prefix_len, hash, hash_len);
    
    *out_len = modulus_len;
    return 0;
}

/* PKCS#1 v1.5 signature verification padding */
int rsa_pkcs1_verify_pad(const uint8_t* in, size_t in_len,
                         const uint8_t* hash, size_t hash_len) {
    static const uint8_t sha256_prefix[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    };
    size_t prefix_len = sizeof(sha256_prefix);
    size_t i;
    
    if (!in || !hash || in_len < prefix_len + hash_len + 11) {
        return -1;
    }
    
    /* Check format */
    if (in[0] != 0x00 || in[1] != 0x01) {
        return -1;
    }
    
    /* Find separator */
    for (i = 2; i < in_len; i++) {
        if (in[i] != 0xFF) {
            break;
        }
    }
    
    /* Check separator and minimum padding */
    if (i == in_len || in[i] != 0x00 || i < 10) {
        return -1;
    }
    
    i++;  /* Skip separator */
    
    /* Check DigestInfo prefix */
    if (i + prefix_len + hash_len > in_len ||
        memcmp(in + i, sha256_prefix, prefix_len) != 0) {
        return -1;
    }
    
    /* Compare hash values */
    i += prefix_len;
    if (memcmp(in + i, hash, hash_len) != 0) {
        return -1;
    }
    
    return 0;
}