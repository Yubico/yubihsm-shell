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
endif ()

project (yubihsm-shell)

option(BUILD_ONLY_LIB "Library only build" OFF)

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

message("Install targets")
message("Libraries ${YUBIHSM_INSTALL_LIB_DIR}")
message("Includes ${YUBIHSM_INSTALL_INC_DIR}")
message("Binaries ${YUBIHSM_INSTALL_BIN_DIR}")
message("Manuals ${YUBIHSM_INSTALL_MAN_DIR}")
message("Pkg-config ${YUBIHSM_INSTALL_PKGCONFIG_DIR}")

if (NOT CMAKE_BUILD_TYPE)
   if (${RELEASE_BUILD} MATCHES 1)
      set (CMAKE_BUILD_TYPE Release)
   else ()
      set (CMAKE_BUILD_TYPE Debug)
   endif ()
endif ()

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-format-zero-length -Wno-implicit-fallthrough")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security")

# fortify can only be used with -O2 and higher, so only enable for release builds
set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -D_FORTIFY_SOURCE=2")
if (CMAKE_C_COMPILER_ID STREQUAL GNU)
  if (CMAKE_C_COMPILER_VERSION VERSION_GREATER 6.0)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
  endif ()
else ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
endif ()

if (CMAKE_C_COMPILER_ID STREQUAL AppleClang)
  set (CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fPIE")
else()
  # -Wl,--strip-all is dependent on linker not compiler...
  set (CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wl,--strip-all -fPIE -pie")
endif ()


# cmake 3.1 or greater can do this automatically; assume gcc otherwise.
if ((${CMAKE_MAJOR_VERSION} GREATER 2) AND (${CMAKE_MINOR_VERSION} GREATER 0))
  set (CMAKE_C_STANDARD 11)
else ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu1x")
endif ()

set (yubihsm_shell_VERSION_MAJOR 2)
set (yubihsm_shell_VERSION_MINOR 0)
set (yubihsm_shell_VERSION_PATCH 0)
set (VERSION "${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/openssl/lib/pkgconfig:/usr/local/opt/pcsc-lite/lib/pkgconfig")
endif ()

if (NOT DEFINED DEFAULT_CONNECTOR_URL)
  set (DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345")
endif()

enable_testing()
find_package(codecov)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  message("win32")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-use-linker-plugin -static-libgcc")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--nxcompat")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--disable-auto-image-base -Wl,--dynamicbase")
  if ("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--high-entropy-va")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--image-base -Wl,0x140000000")
  endif ()
  # gcc with -pie puts the entry adress in the wrong spot, help it..
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-emainCRTStartup")
  add_definitions (-D_POSIX_THREAD_SAFE_FUNCTIONS=1)
  add_definitions (-D__USE_MINGW_ANSI_STDIO=1)
  add_definitions (-DWIN32_LEAN_AND_MEAN=1)
  set (WITHOUT_MANPAGES 1)
  set (ENABLE_EXPERIMENTAL_YKYH 1)
  if (NOT WITHOUT_WIN32_BCRYPT)
    set (WIN32_BCRYPT 1)
  endif()
  if (NOT LIBCRYPTO_LDFLAGS)
    set (LIBCRYPTO_LDFLAGS "-lcrypto")
  endif()
  if (NOT LIBCRYPTO_VERSION)
    # msys now installs openssl 1.1.1, hardcode to that until we come up with something cleverer
    set(LIBCRYPTO_VERSION "1.1.1")
  endif()
else()
  message("not win32")

  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")
  if (NOT CMAKE_C_COMPILER_ID MATCHES Clang)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,relro,-z,now")
  endif ()

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
  pkg_search_module (LIBCRYPTO REQUIRED libcrypto)
  if(NOT BUILD_ONLY_LIB)
    pkg_search_module (LIBEDIT REQUIRED libedit)
  endif()
  pkg_search_module (LIBCURL REQUIRED libcurl)
  pkg_search_module (LIBUSB REQUIRED libusb-1.0)
endif()

add_subdirectory (lib)

if(NOT BUILD_ONLY_LIB)
  add_subdirectory (pkcs11)

  if (ENABLE_EXPERIMENTAL_YKYH)
    pkg_search_module (LIBPCSC REQUIRED libpcsclite)
    add_subdirectory (ykyh)
  endif()

  add_subdirectory (src)

  add_subdirectory (examples)

  if (ENABLE_EXPERIMENTAL_YKYH)
    add_subdirectory (yhauth)
  endif()

  add_subdirectory(yhwrap)
endif()

add_custom_target (
  cppcheck
  COMMENT "Running cppcheck"
  COMMAND /usr/bin/cppcheck
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
