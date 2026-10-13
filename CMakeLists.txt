cmake_minimum_required(VERSION 3.16)
project(kwik_yyc LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT VITA)
    add_subdirectory(runtime)
endif()

add_executable(kwik-yyc
    source/main.cpp
    source/elf.cpp
    source/iff.cpp
    source/yyc.cpp
    source/analysis.cpp
    source/emitter.cpp
    source/assets.cpp
)

target_include_directories(kwik-yyc PRIVATE include)
target_link_libraries(kwik-yyc PRIVATE bz2)
if(MSVC)
    target_compile_options(kwik-yyc PRIVATE /W4)
else()
    target_compile_options(kwik-yyc PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(NOT VITA)
    add_dependencies(kwik-yyc kwik_runtime)
    target_compile_definitions(kwik-yyc PRIVATE
        KWIK_YYC_SOURCE_ROOT="${CMAKE_SOURCE_DIR}"
        KWIK_RUNTIME_ARCHIVE="${CMAKE_BINARY_DIR}/runtime/libkwik_runtime.a"
    )
endif()
