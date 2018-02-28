cmake_minimum_required(VERSION 3.10)
project(libsrypto C)

set(CMAKE_C_STANDARD 11)

set (CMAKE_CXX_FLAGS "-Wall")
add_library(srypto SHARED src/key.c src/key.h src/keypair.c src/keypair.h src/srypto.h src/crypt.c src/crypt.h)