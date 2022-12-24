# Set the minimum version of cmake required
cmake_minimum_required(VERSION 3.10.2)

# Set the project name
project(CFW_TOOLKIT)

# Generate binary files in `/bin` directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Set to Debug mode by default and echo set value
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
        message(FATAL_ERROR "Please specify a build type of either \"Release\" or \"Debug\"\nCurrent Value: ${CMAKE_BUILD_TYPE}")
    endif()
endif()
message("-- Build Type: ${CMAKE_BUILD_TYPE}")

# Require C++17 or greater
if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
endif()

if(CMAKE_CXX_STANDARD LESS 17)
    message(FATAL_ERROR "Incompatible with C++${CMAKE_CXX_STANDARD}. Requires C++17.")
endif()

# No GNU
set(CMAKE_CXX_EXTENSIONS OFF)

# TODO: Include glog
# find_package(glog REQUIRED)

# Include gflags
find_package(gflags REQUIRED)

# Include OpenSSL
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

# Setup compiler flags
if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -D_SDL_BANNED_RECOMMENDED=true")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g")
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG")
    endif()
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Wall /WX /D_SDL_BANNED_RECOMMENDED=true")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Od /Z7")
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Ox -DNDEBUG")
    endif()
endif()

include_directories(${CMAKE_SOURCE_DIR}/external/banned)
include_directories(${CMAKE_SOURCE_DIR}/external/json/single_include)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(/usr/local/include)

add_subdirectory(${CMAKE_SOURCE_DIR}/src)
