# Platform abstraction layer

add_library(platform
    platform.c
)

target_include_directories(platform
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(platform
        ws2_32
    )
elseif(UNIX)
    target_link_libraries(platform
        pthread
    )
endif()