/**
 * @file portable_ssl.h
 * @brief Main header file for the PortableSSL library
 *
 * This is the main entry point for applications using PortableSSL.
 * It includes all necessary headers to use both the cryptographic
 * primitives and the TLS implementation.
 */

#ifndef PORTABLE_SSL_H
#define PORTABLE_SSL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Library version information */
#define PORTABLE_SSL_VERSION_MAJOR 0
#define PORTABLE_SSL_VERSION_MINOR 1
#define PORTABLE_SSL_VERSION_PATCH 0

/* Status codes */
typedef enum {
    PORTABLE_SSL_SUCCESS = 0,
    PORTABLE_SSL_ERROR_GENERAL = -1,
    PORTABLE_SSL_ERROR_MEMORY = -2,
    PORTABLE_SSL_ERROR_IO = -3,
    PORTABLE_SSL_ERROR_INVALID_ARGUMENT = -4,
    PORTABLE_SSL_ERROR_NOT_IMPLEMENTED = -5,
    PORTABLE_SSL_ERROR_CRYPTO = -6,
    PORTABLE_SSL_ERROR_TLS = -7
} portable_ssl_status_t;

/* Core API headers */
#include "crypto/crypto.h"
#include "tls/tls.h"

/* Library initialization/cleanup */
portable_ssl_status_t portable_ssl_init(void);
void portable_ssl_cleanup(void);

/* Version information */
const char* portable_ssl_version_string(void);
void portable_ssl_version(int* major, int* minor, int* patch);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_SSL_H */