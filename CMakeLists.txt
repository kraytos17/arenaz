cmake_minimum_required(VERSION 3.30.0)
project(arenaz VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_DEBUG_POSTFIX "-d")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()

set(CATCH_HPP_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/catch_amalgamated.hpp)
set(CATCH_CPP_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/catch_amalgamated.cpp)

if(NOT EXISTS ${CATCH_CPP_PATH})
    file(DOWNLOAD 
        https://github.com/catchorg/Catch2/releases/download/v3.9.0/catch_amalgamated.cpp
        ${CATCH_CPP_PATH}
        SHOW_PROGRESS)
endif()

if(NOT EXISTS ${CATCH_HPP_PATH})
    file(DOWNLOAD 
        https://github.com/catchorg/Catch2/releases/download/v3.9.0/catch_amalgamated.hpp
        ${CATCH_HPP_PATH}
        SHOW_PROGRESS)
endif()

add_executable(arenaz
    src/catch_amalgamated.cpp
    src/arena_test.cpp
)

target_include_directories(arenaz PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME arenaz COMMAND arenaz)