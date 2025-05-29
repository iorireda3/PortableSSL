/**
 * @file crypto.c
 * @brief Implementation of the core crypto module
 */

#include "crypto/crypto.h"
#include "platform/platform.h"
#include <string.h>

int crypto_init(void) {
    /* Initialize platform-specific components */
    if (platform_init() != 0) {
        return -1;
    }
    
    /* Any additional crypto-specific initialization can go here */
    
    return 0;
}

void crypto_cleanup(void) {
    /* Clean up platform-specific components */
    platform_cleanup();
    
    /* Any additional crypto-specific cleanup can go here */
}

int crypto_random_bytes(uint8_t* buf, size_t len) {
    if (buf == NULL) {
        return -1;
    }
    
    return platform_random_bytes(buf, len);
}