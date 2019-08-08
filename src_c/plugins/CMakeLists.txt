cmake_minimum_required(VERSION 3.4.1)
project(plugins)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if (BUILD_SHARED_LIBS)
    add_library(plugin_store SHARED plugin_store.cpp)
else ()
    add_library(plugin_store STATIC plugin_store.cpp)
endif ()

if (CMAKE_COMPILER_IS_GNUCXX)
    set_target_properties(plugin_store PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations")
endif (CMAKE_COMPILER_IS_GNUCXX)
target_link_libraries(plugin_store PUBLIC ThirdParty::Botan ThirdParty::SQLite)
add_library(Plugin::Store ALIAS plugin_store)

set_target_properties(plugin_store
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
install(TARGETS plugin_store
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/bin)


