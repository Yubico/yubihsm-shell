#
# Copyright 2015-2018 Yubico AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required (VERSION 2.8)
if (CMAKE_VERSION VERSION_GREATER 3.0.0)
  # policy CMP0025 is to get AppleClang identifier rather than Clang for both
  # this matters since the apple compiler accepts different flags.
  cmake_policy(SET CMP0025 NEW)
  cmake_policy(SET CMP0042 NEW)
  cmake_policy(SET CMP0054 NEW)
endif ()

project (yubihsm-shell)

option(BUILD_ONLY_LIB "Library only build" OFF)
option(SUPRESS_MSVC_WARNINGS "Suppresses a lot of the warnings when compiling with MSVC" ON)

include(${CMAKE_SOURCE_DIR}/cmake/SecurityFlags.cmake)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

# Set various install paths
if (NOT DEFINED YUBIHSM_INSTALL_LIB_DIR)
  set(YUBIHSM_INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE PATH "Installation directory for libraries")
endif ()

if (NOT DEFINED YUBIHSM_INSTALL_INC_DIR)
  set(YUBIHSM_INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
endif ()

if (NOT DEFINED YUBIHSM_INSTALL_BIN_DIR)
  set(YUBIHSM_INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for executables")
endif ()

if (NOT DEFINED YUBIHSM_INSTALL_MAN_DIR)
  set(YUBIHSM_INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Installation directory for manual pages")
endif ()

if (NOT DEFINED YUBIHSM_INSTALL_PKGCONFIG_DIR)
  set(YUBIHSM_INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
endif ()

if (NOT CMAKE_BUILD_TYPE)
   if (${RELEASE_BUILD} MATCHES 1)
      set (CMAKE_BUILD_TYPE Release)
   else ()
      set (CMAKE_BUILD_TYPE Debug)
   endif ()
endif ()

if(MSVC)
  set(DISABLE_LTO 1)
endif()
if (NOT DISABLE_LTO)
  if (CMAKE_C_COMPILER_ID STREQUAL GNU)
    if (CMAKE_C_COMPILER_VERSION VERSION_GREATER 6.0)
      set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
    endif ()
  else ()
    if (CMAKE_C_COMPILER_VERSION VERSION_GREATER 7.0)
      set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
    endif ()
  endif ()
endif ()

if (CMAKE_C_COMPILER_ID STREQUAL AppleClang)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-nullability-completeness -Wno-nullability-extension -Wno-expansion-to-defined -Wno-undef-prefix")
elseif (NOT MSVC)
  # -Wl,--strip-all is dependent on linker not compiler...
  set (CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wl,--strip-all")
endif ()

set (CMAKE_C_STANDARD 11)

set (yubihsm_shell_VERSION_MAJOR 2)
set (yubihsm_shell_VERSION_MINOR 3)
set (yubihsm_shell_VERSION_PATCH 0)
set (VERSION "${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/openssl@1.1/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
  set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/libedit/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  set(ENV{PKG_CONFIG_PATH} "/usr/libdata/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif ()

if (NOT DEFINED DEFAULT_CONNECTOR_URL)
  set (DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345")
endif()

enable_testing()
find_package(codecov)

if(WIN32)
  add_definitions(-DWIN32_LEAN_AND_MEAN=1)
  set(_WIN32 1)
  set(__WIN32 1)
  set(_WIN32_BCRYPT 1)
endif()

if(MSVC)
  message("win32")
  set(_MSVC 1)

  if(SUPRESS_MSVC_WARNINGS)
  set(MSVC_DISABLED_WARNINGS_LIST
            "C4200" # nonstandard extension used: zero-sized array in struct/union;
            "C4204" # nonstandard extension used: non-constant aggregate initializer;
            "C4706" # assignment within conditional expression;
            "C4996" # The POSIX name for this item is deprecated. Instead, use the ISO C and C++ conformant name

            "C4005" # redefinition of micros. Status codes are defined in winnt.h and then redefined in ntstatus.h with the same values
            "C4267" # conversion of size_t to other types. Since we don't have sizes that occupy more than 2 bytes, this should be safe to ignore
            "C4100" # unreferenced formal parameter
            "C4201" # nonstandard extension used: nameless struct/union
            "C4295" # array is too small to include a terminating null character. They arrays it's complaining about aren't meant to include terminating null character (triggered in tests and examples only)
            "C4127" # conditional expression is constant
            )
    # The construction in the following 3 lines was taken from LibreSSL's
    # CMakeLists.txt.
    string(REPLACE "C" " -wd" MSVC_DISABLED_WARNINGS_STR ${MSVC_DISABLED_WARNINGS_LIST})
    string(REGEX REPLACE "[/-]W[1234][ ]?" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -MP -W4 ${MSVC_DISABLED_WARNINGS_STR}")
  endif(SUPRESS_MSVC_WARNINGS)
  set (WITHOUT_MANPAGES 1)
  if (NOT WITHOUT_WIN32_BCRYPT)
    set (WIN32_BCRYPT 1)
  endif()
else()
  message(STATUS "not win32")

  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-format-zero-length")

  include(CheckFunctionExists)

  check_function_exists(memset_s HAVE_MEMSET_S)
  if (HAVE_MEMSET_S)
    add_definitions (-DHAVE_MEMSET_S)
  endif()

  check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
  if (HAVE_EXPLICIT_BZERO)
    add_definitions (-DHAVE_EXPLICIT_BZERO)
  endif ()

  find_package (PkgConfig REQUIRED)
  if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    if (NOT LIBCRYPTO_LDFLAGS)
      set (LIBCRYPTO_LDFLAGS "-lcrypto")
    endif()
    if (NOT LIBCRYPTO_VERSION)
      set (LIBCRYPTO_VERSION "1.1.1")
    endif()
  else()
    include(${CMAKE_SOURCE_DIR}/cmake/openssl.cmake)
    find_libcrypto()
  endif()
  if(NOT BUILD_ONLY_LIB)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
      set (LIBEDIT_LDFLAGS "-ledit")
    else()
      pkg_search_module (LIBEDIT REQUIRED libedit)
    endif()
  endif()
  pkg_search_module (LIBCURL REQUIRED libcurl)
  pkg_search_module (LIBUSB REQUIRED libusb-1.0)
endif()

message("LIBCRYPTO_VERSION: ${LIBCRYPTO_VERSION}")

# If disabled, make sure to make the 'ykhsmauth-label' option in src/cmdline.ggo invisible
option(ENABLE_YKHSM_AUTH "Enable/disable ykhsmauth module" ON)
if(ENABLE_YKHSM_AUTH)
  add_definitions(-DYKHSMAUTH_ENABLED="1")
endif()

option(ENABLE_EXPERIMENTAL_ASYMMETRIC_AUTH "Enable support for experimental asymmetric authentication" OFF)

add_subdirectory (lib)

if(NOT BUILD_ONLY_LIB)
  add_subdirectory (pkcs11)

  if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    pkg_search_module (LIBPCSC REQUIRED libpcsclite)
  elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set (LIBPCSC_LDFLAGS "winscard.lib")
  elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(LIBPCSC_LDFLAGS "-Wl,-framework -Wl,PCSC")
  endif()

  if(ENABLE_YKHSM_AUTH)
    add_subdirectory (ykhsmauth)
    add_subdirectory (yubihsm-auth)
  endif()

  add_subdirectory (src)

  add_subdirectory (examples)

  add_subdirectory(yhwrap)
endif()

add_custom_target (
  cppcheck
  COMMENT "Running cppcheck"
  COMMAND cppcheck
  --enable=warning,style,unusedFunction,missingInclude
  --template="[{severity}][{id}] {message} {callstack} \(On {file}:{line}\)"
  -i ${CMAKE_SOURCE_DIR}/src/cmdline.c
  -i ${CMAKE_SOURCE_DIR}/pkcs11/cmdline.c
  --verbose
  --quiet
  ${CMAKE_SOURCE_DIR}/lib ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/pkcs11
  )

set(ARCHIVE_NAME ${CMAKE_PROJECT_NAME}-${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH})
add_custom_target (
  dist
  COMMAND git archive --prefix=${ARCHIVE_NAME}/ HEAD | gzip > ${CMAKE_BINARY_DIR}/${ARCHIVE_NAME}.tar.gz
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )

coverage_evaluate()


message("Build summary:")
message("")
message("        Project name:     ${CMAKE_PROJECT_NAME}")
message("        Version:          ${VERSION}")
message("        Host type:        ${CMAKE_SYSTEM_NAME}")
message("        Path prefix:      ${CMAKE_PREFIX_PATH}")
message("        Compiler:         ${CMAKE_C_COMPILER}")
message("        Compiler ID:      ${CMAKE_C_COMPILER_ID}")
message("        Compiler version: ${CMAKE_C_COMPILER_VERSION}")
message("        CMake version:    ${CMAKE_VERSION}")
message("        CFLAGS:           ${CMAKE_C_FLAGS}")
message("        CPPFLAGS:         ${CMAKE_CXX_FLAGS}")
message("        Warnings:         ${WARN_FLAGS}")
message("        Build type:       ${CMAKE_BUILD_TYPE}")
message("")
message("        Install prefix:    ${CMAKE_INSTALL_PREFIX}")
message("        Install targets")
message("             Libraries     ${YUBIHSM_INSTALL_LIB_DIR}")
message("             Includes      ${YUBIHSM_INSTALL_INC_DIR}")
message("             Binaries      ${YUBIHSM_INSTALL_BIN_DIR}")
message("             Manuals       ${YUBIHSM_INSTALL_MAN_DIR}")
message("             Pkg-config    ${YUBIHSM_INSTALL_PKGCONFIG_DIR}")
