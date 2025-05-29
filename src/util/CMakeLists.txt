# Utility functions

add_library(util
    util.c
)

target_include_directories(util
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

target_link_libraries(util
    platform
)