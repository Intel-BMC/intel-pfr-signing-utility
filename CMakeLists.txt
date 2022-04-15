#
# Copyright (c) 2020 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
cmake_minimum_required(VERSION 2.8.10 FATAL_ERROR)
project(intel-pfr-signing-utility C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
find_package(OpenSSL REQUIRED)
#PKG_SEARCH_MODULE(LIBCRYPTO REQUIRED libcrypto openssl)
PKG_CHECK_MODULES(LIBXML2 libxml-2.0 REQUIRED)
#find_package(libxml2 REQUIRED)

if (MSVC)
	# level 4 warning and all warnings as errors
	add_compile_options(/W4 /WX)
else ()
	add_compile_options(-Wall -Wextra -pedantic -Werror)
endif ()

add_compile_options(-g)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${LIBXML2_INCLUDE_DIRS})
add_executable(intel-pfr-signing-utility argparse.c cpld.c blocksign.c sslhelper.c main.c s_helpers.c log.c)
target_link_libraries (intel-pfr-signing-utility ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(intel-pfr-signing-utility xml2)
install (TARGETS intel-pfr-signing-utility DESTINATION bin)
