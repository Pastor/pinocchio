cmake_minimum_required(VERSION 3.4.1)
project(tests)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(${PROJECT_NAME}_botan botan_tests.cpp plugin_sore_tests.cpp main.cpp)
if (CMAKE_COMPILER_IS_GNUCXX)
    set_target_properties(${PROJECT_NAME}_botan PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations")
endif (CMAKE_COMPILER_IS_GNUCXX)
target_link_libraries(${PROJECT_NAME}_botan PUBLIC ThirdParty::Botan gtest Plugin::Store)
set_target_properties(gtest
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set_target_properties(${PROJECT_NAME}_botan
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
install(TARGETS ${PROJECT_NAME}_botan
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/bin)


