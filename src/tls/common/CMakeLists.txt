# TLS common implementation

add_library(tls_common
    record.c
    alert.c
    cipher.c
)

target_include_directories(tls_common
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
)