cmake_minimum_required(VERSION 3.20)
project(CampusLMS_CPP VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The existing Windows project used the SQLite amalgamation in "SQLite 3".
# Reuse it automatically when the folder is copied alongside this project;
# otherwise use an installed SQLite development package.
set(SQLITE3_AMALGAMATION_DIR "${CMAKE_SOURCE_DIR}/SQLite 3" CACHE PATH
    "Folder containing sqlite3.c and sqlite3.h (optional)")

if(EXISTS "${SQLITE3_AMALGAMATION_DIR}/sqlite3.c" AND
   EXISTS "${SQLITE3_AMALGAMATION_DIR}/sqlite3.h")
    add_library(sqlite3_local STATIC "${SQLITE3_AMALGAMATION_DIR}/sqlite3.c")
    target_include_directories(sqlite3_local PUBLIC "${SQLITE3_AMALGAMATION_DIR}")
    set(SQLITE_TARGET sqlite3_local)
else()
    find_package(SQLite3 REQUIRED)
    set(SQLITE_TARGET SQLite::SQLite3)
endif()

if(WIN32)
    set(PLATFORM_CRYPTO_LIB bcrypt)
else()
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    set(PLATFORM_CRYPTO_LIB OpenSSL::Crypto)
endif()

add_executable(CampusLMS src/main.cpp)
target_include_directories(CampusLMS PRIVATE include)
target_link_libraries(CampusLMS PRIVATE ${SQLITE_TARGET} ${PLATFORM_CRYPTO_LIB})

if(MSVC)
    target_compile_options(CampusLMS PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(CampusLMS PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

# The database and uploaded files are kept in a data folder beside the executable's
# working directory. start.bat changes to the project directory before launching.
