/**
 * @file test_sha256.c
 * @brief Test SHA-256 implementation
 */

#include "crypto/sha256.h"
#include "util/util.h"
#include <stdio.h>
#include <string.h>

/* Test vectors from FIPS 180-2 */
struct sha256_test_vector {
    const char* message;
    const char* digest;
};

static const struct sha256_test_vector test_vectors[] = {
    {
        "abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    },
    {
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
        "The quick brown fox jumps over the lazy dog",
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    }
};

static int test_sha256_vector(const struct sha256_test_vector* vector) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t expected[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    size_t hex_len = sizeof(hex) - 1;
    
    /* Calculate SHA-256 digest */
    sha256((const uint8_t*)vector->message, strlen(vector->message), digest);
    
    /* Convert expected digest from hex */
    util_hex_decode(vector->digest, strlen(vector->digest), expected, &hex_len);
    
    /* Compare */
    if (memcmp(digest, expected, SHA256_DIGEST_LENGTH) != 0) {
        printf("FAIL: SHA-256 mismatch for \"%s\"\n", vector->message);
        
        hex_len = sizeof(hex) - 1;
        util_hex_encode(digest, SHA256_DIGEST_LENGTH, hex, &hex_len);
        hex[hex_len] = '\0';
        printf("Got:      %s\n", hex);
        printf("Expected: %s\n", vector->digest);
        
        return 1;
    }
    
    return 0;
}

static int test_hmac_sha256(void) {
    const uint8_t key[] = "key";
    const uint8_t data[] = "The quick brown fox jumps over the lazy dog";
    const char* expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";
    
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t expected_digest[SHA256_DIGEST_LENGTH];
    size_t hex_len = sizeof(expected_digest);
    
    printf("Testing HMAC-SHA256...\n");
    
    /* Calculate HMAC */
    hmac_sha256(key, sizeof(key) - 1, data, sizeof(data) - 1, digest);
    
    /* Decode expected result */
    util_hex_decode(expected, strlen(expected), expected_digest, &hex_len);
    
    /* Compare */
    if (memcmp(digest, expected_digest, SHA256_DIGEST_LENGTH) != 0) {
        printf("FAIL: HMAC-SHA256 mismatch\n");
        return 1;
    }
    
    printf("PASS: HMAC-SHA256\n");
    return 0;
}

int main(void) {
    int i;
    int result = 0;
    
    printf("=== SHA-256 Tests ===\n");
    
    for (i = 0; i < sizeof(test_vectors) / sizeof(test_vectors[0]); i++) {
        printf("Testing vector %d: \"%s\"\n", i + 1, 
               test_vectors[i].message[0] ? test_vectors[i].message : "(empty string)");
        
        result |= test_sha256_vector(&test_vectors[i]);
        
        if (result == 0) {
            printf("PASS\n");
        }
    }
    
    result |= test_hmac_sha256();
    
    if (result == 0) {
        printf("All SHA-256 tests passed!\n");
    } else {
        printf("Some SHA-256 tests failed.\n");
    }
    
    return result;
}