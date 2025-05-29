# RSA implementation

add_library(crypto_rsa
    rsa.c
    rsa_key.c
    rsa_oaep.c
    rsa_pkcs1.c
)

target_include_directories(crypto_rsa
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)