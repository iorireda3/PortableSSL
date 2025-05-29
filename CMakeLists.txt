cmake_minimum_required(VERSION 3.10)
project(PortableSSL VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(PORTABLE_SSL_BUILD_TESTS "Build test programs" ON)
option(PORTABLE_SSL_BUILD_CLI "Build CLI tool" ON)

# Compiler flags
if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra -pedantic)
endif()

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Core library components
add_subdirectory(src/crypto)
add_subdirectory(src/tls)
add_subdirectory(src/platform)
add_subdirectory(src/util)

# Main library targets
add_library(portable_crypto
  src/crypto/crypto.c
)

add_library(portable_ssl
  src/tls/tls.c
)

target_link_libraries(portable_crypto
  crypto_aes
  crypto_hash
  crypto_rsa
  platform
  util
)

target_link_libraries(portable_ssl
  portable_crypto
  tls_client
  tls_server
  tls_common
)

# CLI Tool
if(PORTABLE_SSL_BUILD_CLI)
  add_subdirectory(src/cli)
endif()

# Tests
if(PORTABLE_SSL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Install targets
install(TARGETS portable_crypto portable_ssl
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY include/
  DESTINATION include/portablessl
)