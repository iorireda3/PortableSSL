/**
 * @file crypto.h
 * @brief Core cryptographic primitives interface
 */

#ifndef PORTABLE_SSL_CRYPTO_H
#define PORTABLE_SSL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Include all crypto algorithm headers */
#include "aes.h"
#include "sha256.h"
#include "rsa.h"

/* Random number generation */
int crypto_random_bytes(uint8_t* buf, size_t len);

/* Initialize crypto subsystem */
int crypto_init(void);

/* Clean up crypto subsystem */
void crypto_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_SSL_CRYPTO_H */