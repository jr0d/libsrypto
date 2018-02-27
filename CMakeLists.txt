cmake_minimum_required(VERSION 3.10)
project(libsrypto C)

set(CMAKE_C_STANDARD 11)

set (CMAKE_CXX_FLAGS "-Wall")
add_library(srypto SHARED key.c key.h keypair.c keypair.h srypto.h)