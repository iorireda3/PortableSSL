# TLS server implementation

add_library(tls_server
    server.c
    handshake.c
)

target_include_directories(tls_server
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
)