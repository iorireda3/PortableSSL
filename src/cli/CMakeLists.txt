# CLI tool

add_executable(portable_ssl_cli
    main.c
)

target_include_directories(portable_ssl_cli
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

target_link_libraries(portable_ssl_cli
    portable_crypto
    portable_ssl
)

# Installation
install(TARGETS portable_ssl_cli
    RUNTIME DESTINATION bin
)
