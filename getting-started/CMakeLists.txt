# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13)

# Mbed OS system root path - that probably needs to come from tools
# TODO: @mbed-os-tools
set(MBED_OS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/mbed-os CACHE INTERNAL "")

# TODO: @mbed-os-tools This needs to come from tools
# Build system provides "target" list. This property is defined in mbed_app.json
# to used the PSA source code under features/FEATURE_EXPERIMENTAL_API.
# Note: This must be placed before subdirectories
# DISCO_L475VG_IOT01A
set_property(GLOBAL
  PROPERTY MBED_OS_TARGET_LABELS
    EXPERIMENTAL_API;
)

# TODO: @mbed-os-tools This needs to come from tools
# It was added by the application in mbed_app.json
add_definitions(
    -DMBEDTLS_USER_CONFIG_FILE="mbedtls_user_config.h"
)

# Include standard Mbed definitions
include(${MBED_OS_ROOT}/cmake/app.cmake)

project(getting-started)

# uncomment below to have a verbose build process
#set(CMAKE_VERBOSE_MAKEFILE ON)

# Sources for main application
target_sources(app
    PRIVATE
        main.cpp
)

target_include_directories(mbed-os
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
