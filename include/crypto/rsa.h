/**
 * @file rsa.h
 * @brief RSA encryption/decryption functionality
 */

#ifndef PORTABLE_SSL_RSA_H
#define PORTABLE_SSL_RSA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RSA key structure */
typedef struct rsa_key_st {
    /* Public key components */
    uint8_t* n;  /* Modulus */
    size_t n_len;
    uint8_t* e;  /* Public exponent */
    size_t e_len;
    
    /* Private key components (NULL if not available) */
    uint8_t* d;  /* Private exponent */
    size_t d_len;
    uint8_t* p;  /* First prime factor */
    size_t p_len;
    uint8_t* q;  /* Second prime factor */
    size_t q_len;
    uint8_t* dmp1; /* d mod (p-1) */
    size_t dmp1_len;
    uint8_t* dmq1; /* d mod (q-1) */
    size_t dmq1_len;
    uint8_t* iqmp; /* q^-1 mod p */
    size_t iqmp_len;
    
    int is_private; /* Flag indicating whether the key contains private components */
} rsa_key_t;

/* RSA padding modes */
typedef enum {
    RSA_PADDING_NONE,
    RSA_PADDING_PKCS1,
    RSA_PADDING_OAEP
} rsa_padding_t;

/* RSA key generation */
int rsa_generate_key(rsa_key_t* key, int bits);

/* RSA key import/export functions */
int rsa_import_public_key(rsa_key_t* key, const uint8_t* data, size_t data_len);
int rsa_import_private_key(rsa_key_t* key, const uint8_t* data, size_t data_len);
int rsa_export_public_key(const rsa_key_t* key, uint8_t* out, size_t* out_len);
int rsa_export_private_key(const rsa_key_t* key, uint8_t* out, size_t* out_len);

/* RSA encryption/decryption */
int rsa_public_encrypt(const rsa_key_t* key, rsa_padding_t padding,
                      const uint8_t* in, size_t in_len,
                      uint8_t* out, size_t* out_len);
                      
int rsa_private_decrypt(const rsa_key_t* key, rsa_padding_t padding,
                       const uint8_t* in, size_t in_len,
                       uint8_t* out, size_t* out_len);

/* RSA signing/verification */
int rsa_sign(const rsa_key_t* key, const uint8_t* msg, size_t msg_len,
            uint8_t* sig, size_t* sig_len);
            
int rsa_verify(const rsa_key_t* key, const uint8_t* msg, size_t msg_len,
              const uint8_t* sig, size_t sig_len);

/* RSA key cleanup */
void rsa_key_free(rsa_key_t* key);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_SSL_RSA_H */