cmake_minimum_required(VERSION 3.4.1)
project(pinocchio)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.build")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PINOCCHIO_PRODUCT_NUMBER 1)
set(PINOCCHIO_PRODUCT_VERSION 6)
set(PINOCCHIO_BUILD_NUMBER 1)

set(USE_STATIC ON)
set(USE_CRYPTO OpenSSL)

if (MSVC)
    set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} /SUBSYSTEM:CONSOLE")
    if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(CMAKE_CFLAGS "${CMAKE_CFLAGS} /MDd /bigobj")
        add_compile_options(/MDd /bigobj)
        #        add_definitions(-DMEMORY_LEAK_DETECT)
        message(STATUS "Memory leak detection enabled")
    else ()
        add_definitions(/MT)
        add_compile_options(/bigobj)
    endif ()
    add_definitions(/wd4267)
    add_definitions(/wd4250)
    add_definitions(/wd4996)
elseif (CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pedantic -Wp,-w -Wa,-mbig-obj")
    set(CMAKE_CFLAGS "${CMAKE_CFLAGS} -pedantic -Wp,-w -Wa,-mbig-obj")
else ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pedantic -Wp,-w")
    set(CMAKE_CFLAGS "${CMAKE_CFLAGS} -pedantic -Wp,-w")
endif ()

if (${USE_CRYPTO} STREQUAL "Botan")
    add_definitions(-DCRYPTO_BOTAN)
    set(TESTS_FILES src/test/botan_tests.cpp)
    if (WIN32)
        if (${USE_STATIC} STREQUAL "ON")
            add_subdirectory(3rdparty/botan)
            set(CRYPTO_LIBRARIES botan_static)
            set(CRYPTO_INCLUDE_DIR
                    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/botan/src
                    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/botan/src/external)
            add_definitions(-DUSE_STATIC)
        else (${USE_STATIC} STREQUAL "ON")
            link_directories(${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/botan/windows/x86_64)
            set(CRYPTO_LIBRARIES botan)
            set(CRYPTO_INCLUDE_DIR
                    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/botan/windows/x86_64/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/botan/windows/x86_64/include/external)
            file(COPY
                    ${CMAKE_SOURCE_DIR}/3rdparty/botan/windows/x86_64/botan.dll
                    DESTINATION
                    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
        endif (${USE_STATIC} STREQUAL "ON")
        set(DEPENDENCY_LIBS ws2_32)
    elseif (APPLE)
        link_directories(/usr/local/Cellar/botan/2.1.0/lib)
        set(CRYPTO_LIBRARIES botan-2)
        set(CRYPTO_INCLUDE_DIR
                /usr/local/Cellar/botan/2.1.0/include/botan-2)
    else ()
        find_package(Botan REQUIRED)
    endif (WIN32)
elseif (${USE_CRYPTO} STREQUAL "OpenSSL")
    add_definitions(-DCRYPTO_OPENSSL)
    #add_definitions(-DMG_ENABLE_SSL)
    set(TESTS_FILES src/test/openssl_c_tests.cpp src/test/openssl_cpp_tests.cpp)
    if (WIN32)
        set(CRYPTO_LIBRARIES libcrypto libssl)
        link_directories(${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/openssl/lib/static_x64)
        set(CRYPTO_INCLUDE_DIR
                ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/openssl/include)
	set(DEPENDENCY_LIBS ws2_32 crypt32)
    elseif (APPLE)
        find_package(OpenSSL REQUIRED)
    else ()
        find_package(OpenSSL REQUIRED)
    endif ()
endif ()
include_directories(src/main)
include_directories(3rdparty/gtest/googletest/include)
include_directories(3rdparty/mongoose)
include_directories(3rdparty/sqlite)
include_directories(3rdparty/json)
include_directories(${CRYPTO_INCLUDE_DIR})

add_subdirectory(3rdparty/gtest/googletest)

set(SOURCE_FILES)
set(MAIN_FILES src/main/main.c src/main/web_server.c)

set(MONGOOSE 3rdparty/mongoose/mongoose.c)
add_definitions(
        -DMG_ENABLE_HTTP_STREAMING_MULTIPART
        -DMG_ENABLE_IPV6
        -DMG_ENABLE_BROADCAST
        -DMG_ENABLE_GETADDRINFO
        -DMG_ENABLE_THREADS
        -DMG_DISABLE_MD5
        -DMG_DISABLE_HTTP_DIGEST_AUTH
        -DMG_VPRINTF_BUFFER_SIZE=1024
)

#add_definitions(-DDISABLE_MD5)

set(SQLITE 3rdparty/sqlite/sqlite3.c src/main/web_server.c)
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main/version.rc.in
        ${CMAKE_CURRENT_BINARY_DIR}/version.rc
        @ONLY
)
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main/version.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/version.h
        @ONLY
)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(${CMAKE_PROJECT_NAME} ${SOURCE_FILES} ${MAIN_FILES} ${CMAKE_BINARY_DIR}/version.rc ${MONGOOSE} ${SQLITE})
add_executable(${CMAKE_PROJECT_NAME}_tests ${TESTS_FILES} src/test/main.cpp ${SOURCE_FILES})
target_link_libraries(${CMAKE_PROJECT_NAME} ${CRYPTO_LIBRARIES} ${DEPENDENCY_LIBS})
target_link_libraries(${CMAKE_PROJECT_NAME}_tests ${CRYPTO_LIBRARIES} gtest ${DEPENDENCY_LIBS})
if (APPLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wno-deprecated-declarations -Wpessimizing-move")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -Wno-deprecated-declarations -Wpessimizing-move")
    target_link_libraries(${CMAKE_PROJECT_NAME} "-framework Security")
    target_link_libraries(${CMAKE_PROJECT_NAME}_tests "-framework Security")
endif (APPLE)

message(STATUS "C_FLAGS:  =${CMAKE_C_FLAGS}")
message(STATUS "CXX_FLAGS:=${CMAKE_CXX_FLAGS}")

file(COPY
        ${CMAKE_SOURCE_DIR}/test_data/request_body.txt
        DESTINATION
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_data)