cmake_minimum_required(VERSION 3.4.1)
project(botan)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external)

set(BOTAN_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/botan_all.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botan_all_sha_sse41_ssse3.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botan_all_sha_ssse3.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botan_all_aesni.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botan_all_avx2.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botan_all_rdrand.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botan_all_rdseed.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botan_all_ssse3.cpp)
if (BUILD_SHARED_LIBS)
    add_library(${PROJECT_NAME} SHARED ${BOTAN_SOURCES})
else ()
    add_library(${PROJECT_NAME} STATIC ${BOTAN_SOURCES})
endif ()
target_compile_definitions(${PROJECT_NAME} PRIVATE -DBOTAN_DLL=)
if (CMAKE_COMPILER_IS_GNUCXX)
    set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations")
endif (CMAKE_COMPILER_IS_GNUCXX)
set_target_properties(${PROJECT_NAME}
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC ws2_32 crypt32)
endif ()
target_link_libraries(${PROJECT_NAME} PUBLIC ThirdParty::SQLite)
add_library(ThirdParty::Botan ALIAS ${PROJECT_NAME})

install(FILES ${CMAKE_BINARY_DIR}/botan_all.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/bin
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/lib
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/lib)


