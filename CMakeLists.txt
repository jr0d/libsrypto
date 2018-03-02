cmake_minimum_required(VERSION 3.10)
project(libsrypto C)

set(CMAKE_C_STANDARD 11)

set (CMAKE_C_FLAGS "-Wall")

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s -O2")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s -O2")

set(library_SOURCES
        src/key.c
        src/key.h
        src/keypair.c
        src/keypair.h
        src/srypto.h
        src/crypt.c
        src/crypt.h
        )

add_library(srypto SHARED ${library_SOURCES})
add_library(srypto_static STATIC ${library_SOURCES})

include_directories( src )

add_executable(base_test tests/base_test.c)
target_link_libraries( base_test PRIVATE srypto_static)

add_executable(sdes interface/main.c interface/rng.c interface/rng.h)
target_link_libraries( sdes PRIVATE srypto_static )