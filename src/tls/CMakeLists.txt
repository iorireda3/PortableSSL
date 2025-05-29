# TLS module

add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(common)

# Main TLS library
add_library(tls
    tls.c
)

# Dependencies
target_link_libraries(tls
    tls_client
    tls_server
    tls_common
    crypto
)