cmake_minimum_required(VERSION 3.4.1)
project(sqlite)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(${PROJECT_NAME} STATIC sqlite3.c sqlite3.h)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DSQLITE_API=)
if (CMAKE_COMPILER_IS_GNUCXX)
    set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations")
endif (CMAKE_COMPILER_IS_GNUCXX)
set_target_properties(${PROJECT_NAME}
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
add_library(ThirdParty::SQLite ALIAS ${PROJECT_NAME})

install(FILES ${CMAKE_BINARY_DIR}/sqlite.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/lib
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/lib
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/lib)


