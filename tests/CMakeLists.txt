# Test suite

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# AES tests
add_executable(test_aes
    test_aes.c
)
target_link_libraries(test_aes
    portable_crypto
)
add_test(NAME AES COMMAND test_aes)

# SHA-256 tests
add_executable(test_sha256
    test_sha256.c
)
target_link_libraries(test_sha256
    portable_crypto
)
add_test(NAME SHA256 COMMAND test_sha256)

# RSA tests
add_executable(test_rsa
    test_rsa.c
)
target_link_libraries(test_rsa
    portable_crypto
)
add_test(NAME RSA COMMAND test_rsa)

# TLS tests
add_executable(test_tls
    test_tls.c
)
target_link_libraries(test_tls
    portable_ssl
)
add_test(NAME TLS COMMAND test_tls)

# Utils tests
add_executable(test_utils
    test_utils.c
)
target_link_libraries(test_utils
    util
)
add_test(NAME Utils COMMAND test_utils)