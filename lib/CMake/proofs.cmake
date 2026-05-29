# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_compile_definitions(OPENSSL_SUPPRESS_DEPRECATED=1)
include(GoogleTest)

option(PROOFS_BUILD_TESTS "Build tests and benchmarks" OFF)
if(PROOFS_BUILD_TESTS)
    find_package(benchmark REQUIRED)
    find_package(GTest REQUIRED)
endif()

find_library(PROOFS_ZSTD_LIBRARY NAMES zstd libzstd.so.1
             PATHS /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu)
if(NOT PROOFS_ZSTD_LIBRARY)
    message(FATAL_ERROR "zstd library not found; install libzstd-dev or provide libzstd.so.1")
endif()

macro(proofs_add_testing_libraries PROG)
    if(NOT PROOFS_BUILD_TESTS)
        return()
    endif()
    # libraries that are common enough to be useful in all tests
    target_link_libraries(${PROG} testing_main)    

#   -static won't work on Debian because libbenchmark-dev is
#   dynamic only.  One could enable -static and comment out
#   benchmark, in which case some tests won't build

#    target_link_libraries(${PROG} -static)

    # on Debian buster, gtest seems to need pthread
    target_link_libraries(${PROG} gtest pthread)
    target_link_libraries(${PROG} benchmark::benchmark)

    gtest_discover_tests(${PROG})
endmacro()

macro(proofs_add_test PROG)
    if(NOT PROOFS_BUILD_TESTS)
        return()
    endif()
    add_executable(${PROG} ${PROG}.cc ${ARGN})
    target_link_libraries(${PROG} ec)    
    target_link_libraries(${PROG} algebra)
    target_link_libraries(${PROG} util)
    proofs_add_testing_libraries(${PROG})
endmacro()

macro(proofs_add_tests)
    if(NOT PROOFS_BUILD_TESTS)
        return()
    endif()
    foreach (PROG ${ARGN})
        proofs_add_test(${PROG})
    endforeach ()
endmacro()
