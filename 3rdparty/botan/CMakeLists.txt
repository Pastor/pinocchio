cmake_minimum_required(VERSION 3.4.1)
project(botan_static)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src)
include_directories(src/external)

add_library(botan_static STATIC
        src/botan_all.cpp
        src/botan_all_aesni.cpp
        src/botan_all_avx2.cpp
        src/botan_all_rdrand.cpp
        src/botan_all_rdseed.cpp
        src/botan_all_ssse3.cpp)
