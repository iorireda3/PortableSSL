# TLS client implementation

add_library(tls_client
    client.c
    handshake.c
)

target_include_directories(tls_client
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
)