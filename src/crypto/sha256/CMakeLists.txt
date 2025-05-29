# SHA256 implementation

add_library(crypto_hash
    sha256.c
)

target_include_directories(crypto_hash
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)