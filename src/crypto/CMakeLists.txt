# Crypto module

# AES submodule
add_subdirectory(aes)

# SHA256 submodule
add_subdirectory(sha256)

# RSA submodule
add_subdirectory(rsa)

# Common crypto library
add_library(crypto
    crypto.c
)

# Dependencies
target_link_libraries(crypto
    crypto_aes
    crypto_hash
    crypto_rsa
)