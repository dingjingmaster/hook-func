cmake_minimum_required(VERSION 3.15)
project(hook-func LANGUAGES C ASM)

set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 0)
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

set(CMAKE_C_STANDARD 11)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--no-undefined")
set(ENV{PKG_CONFIG_PATH} "/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib64/pkgconfig:$ENV{PKG_CONFIG_PATH}")


if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-D DDEBUG -DDEBUG -D VERSION=\\"${PROJECT_VERSION}\\")
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    add_link_options(-Wl,-strip-all)
    add_compile_options(-fvisibility=hidden -Wno-unused-result)
    add_definitions(-D VERSION=\\"${PROJECT_VERSION}\\")
endif ()

if (WIN32)
    add_definitions(-D PLATFORM_WINDOWS)
elseif (UNIX AND NOT APPLE)
    add_definitions(-D PLATFORM_LINUX)
elseif (APPLE)
    add_definitions(-D PLATFORM_APPLE)
else ()
    message(FATAL_ERROR "Not supported system.")
endif ()

add_definitions(-D _GNU_SOURCE)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "64bit")
    if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(x86_64|amd64)$"
            OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "AMD64"
            OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(x86|i[3-6]86)$")
        add_definitions(-D ARCH_X86_64)
        message(STATUS "AMD64/x86_64")
    elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64"
        OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "ARM64")
        add_definitions(-D ARCH_ARM64)
        message(STATUS "arm64")
    else ()
        message(FATAL_ERROR "Not supported platform.")
    endif ()
elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(STATUS "32bit")
    if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(x86_64|amd64)$"
            OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "AMD64"
            OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(x86|i[3-6]86)$")
        add_definitions(-D ARCH_X86)
        message(STATUS "x86")
    elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64"
            OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "ARM64")
        add_definitions(-D ARCH_ARM32)
        message(STATUS "arm32")
    else ()
        message(FATAL_ERROR "Not supported platform.")
    endif ()
else ()
    message(FATAL_ERROR "Not supported platform bit.")
endif ()


find_package(PkgConfig)
pkg_check_modules(CAPS capstone REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/3thrd)


add_subdirectory(src)
add_subdirectory(examples)
