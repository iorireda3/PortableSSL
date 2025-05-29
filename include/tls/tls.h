/**
 * @file tls.h
 * @brief Core TLS functionality interface
 */

#ifndef PORTABLE_SSL_TLS_H
#define PORTABLE_SSL_TLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TLS versions */
typedef enum {
    TLS_VERSION_1_0 = 0x0301,
    TLS_VERSION_1_1 = 0x0302,
    TLS_VERSION_1_2 = 0x0303,
    TLS_VERSION_1_3 = 0x0304
} tls_version_t;

/* TLS context */
typedef struct tls_ctx_st tls_ctx_t;
typedef struct tls_st tls_t;

/* I/O callbacks */
typedef int (*tls_io_cb)(void* userdata, uint8_t* buf, size_t len);

/* TLS context creation/destruction */
tls_ctx_t* tls_ctx_new(void);
void tls_ctx_free(tls_ctx_t* ctx);

/* TLS context configuration */
int tls_ctx_set_min_version(tls_ctx_t* ctx, tls_version_t version);
int tls_ctx_set_max_version(tls_ctx_t* ctx, tls_version_t version);
int tls_ctx_set_certificate_file(tls_ctx_t* ctx, const char* file);
int tls_ctx_set_private_key_file(tls_ctx_t* ctx, const char* file);
int tls_ctx_set_verify_mode(tls_ctx_t* ctx, int mode);

/* TLS connection creation/destruction */
tls_t* tls_new(tls_ctx_t* ctx);
void tls_free(tls_t* tls);

/* TLS connection configuration */
int tls_set_hostname(tls_t* tls, const char* hostname);
int tls_set_io_callbacks(tls_t* tls, tls_io_cb read_cb, tls_io_cb write_cb, void* userdata);

/* TLS connection operations */
int tls_connect(tls_t* tls);
int tls_accept(tls_t* tls);
int tls_read(tls_t* tls, uint8_t* buf, size_t len, size_t* bytes_read);
int tls_write(tls_t* tls, const uint8_t* buf, size_t len, size_t* bytes_written);
int tls_shutdown(tls_t* tls);

/* TLS connection information */
tls_version_t tls_get_version(tls_t* tls);
const char* tls_get_cipher(tls_t* tls);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_SSL_TLS_H */