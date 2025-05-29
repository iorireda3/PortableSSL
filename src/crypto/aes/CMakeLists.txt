# AES implementation

add_library(crypto_aes
    aes.c
    aes_block.c
    aes_modes.c
)

target_include_directories(crypto_aes
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)