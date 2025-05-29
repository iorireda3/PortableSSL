/**
 * @file portable_ssl.c
 * @brief Main implementation file for PortableSSL library
 */

#include "portable_ssl.h"
#include "platform/platform.h"
#include "crypto/crypto.h"
#include <string.h>

/* Initialize the PortableSSL library */
portable_ssl_status_t portable_ssl_init(void) {
    /* Initialize platform-specific functionality */
    if (platform_init() != 0) {
        return PORTABLE_SSL_ERROR_GENERAL;
    }
    
    /* Initialize cryptographic subsystem */
    if (crypto_init() != 0) {
        platform_cleanup();
        return PORTABLE_SSL_ERROR_CRYPTO;
    }
    
    return PORTABLE_SSL_SUCCESS;
}

/* Clean up the PortableSSL library */
void portable_ssl_cleanup(void) {
    /* Clean up in reverse order of initialization */
    crypto_cleanup();
    platform_cleanup();
}

/* Get version information as a string */
const char* portable_ssl_version_string(void) {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d", 
             PORTABLE_SSL_VERSION_MAJOR,
             PORTABLE_SSL_VERSION_MINOR,
             PORTABLE_SSL_VERSION_PATCH);
    return version;
}

/* Get version information as separate components */
void portable_ssl_version(int* major, int* minor, int* patch) {
    if (major) *major = PORTABLE_SSL_VERSION_MAJOR;
    if (minor) *minor = PORTABLE_SSL_VERSION_MINOR;
    if (patch) *patch = PORTABLE_SSL_VERSION_PATCH;
}