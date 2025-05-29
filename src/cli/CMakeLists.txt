# CLI tool

add_executable(portable_ssl
    main.c
)

target_include_directories(portable_ssl
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

target_link_libraries(portable_ssl
    portable_crypto
    portable_ssl
)

# Installation
install(TARGETS portable_ssl
    RUNTIME DESTINATION bin
)