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

include(${CMAKE_SOURCE_DIR}/cmake/openssl.cmake)
find_libcrypto()

set(
  SOURCE
  ../common/hash.c
  ../common/util.c
  ../common/parsing.c
  ../common/openssl-compat.c
  util_pkcs11.c
  yubihsm_pkcs11.c
  list.c
  debug_p11.c
  )

if(WIN32)
  set(SOURCE ${SOURCE} cmdline.c ../common/time_win.c ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
  include(${CMAKE_SOURCE_DIR}/cmake/getopt.cmake)
  find_getopt()
else(WIN32)
  include(gengetopt)
  add_gengetopt_files(cmdline "--conf-parser" "--no-handle-error" "--string-parser")
  set(SOURCE ${SOURCE} ${GGO_C})
endif(WIN32)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../lib
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${LIBCRYPTO_INCLUDEDIR}
  )

# NOTE(adma): required by gengetopt
add_definitions(-DPACKAGE="yubihsm_pkcs11")
add_definitions(-DVERSION="${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}")
add_definitions(-DVERSION_MAJOR=${yubihsm_shell_VERSION_MAJOR})
add_definitions(-DVERSION_MINOR=${yubihsm_shell_VERSION_MINOR})
add_definitions(-DVERSION_PATCH=${yubihsm_shell_VERSION_PATCH})

list(APPEND LCOV_REMOVE_PATTERNS "'${PROJECT_SOURCE_DIR}/pkcs11/cmdline.c'")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
set_property(SOURCE ${GGO_C} APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-unused-but-set-variable ")
endif()

add_library(yubihsm_pkcs11 SHARED ${SOURCE})
add_coverage (yubihsm_pkcs11)

# Remove "lib" form the built target
set_target_properties(yubihsm_pkcs11 PROPERTIES PREFIX "")

# Set install RPATH
set_target_properties(yubihsm_pkcs11 PROPERTIES INSTALL_RPATH "${YUBIHSM_INSTALL_LIB_DIR}")

if(NOT MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
endif()
add_definitions(-DCRYPTOKI_EXPORTS)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  # glibc provides the iconv functionality out of the box, this
  # will probably be required on other platforms besides macOS.
  set_target_properties(yubihsm_pkcs11 PROPERTIES LINK_FLAGS "-liconv")
endif()

target_link_libraries(
  yubihsm_pkcs11
  yubihsm
  ${LIBCRYPTO_LDFLAGS}
  ${GETOPT_LIBS}
  )

if(WIN32)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc @ONLY)
endif(WIN32)

install(
  TARGETS yubihsm_pkcs11
  ARCHIVE DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}/pkcs11"
  LIBRARY DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}/pkcs11"
  RUNTIME DESTINATION "${YUBIHSM_INSTALL_BIN_DIR}/pkcs11")
install(FILES pkcs11.h DESTINATION "${YUBIHSM_INSTALL_INC_DIR}/pkcs11")
install(FILES pkcs11y.h DESTINATION "${YUBIHSM_INSTALL_INC_DIR}/pkcs11")

add_subdirectory (tests)

if (FUZZING)
    include_directories(
        ../lib/fuzz
    )
    add_executable(fuzz_get_attribute_value
        # harness sources
        fuzz/fuzz_get_attribute_value.cc
        ../lib/fuzz/yubihsm_fuzz.cc
        # pkcs11 sources
        ../common/hash.c
        ../common/util.c
        ../common/parsing.c
        ../common/openssl-compat.c
        util_pkcs11.c
        yubihsm_pkcs11.c
        list.c
        debug_p11.c
        # libyubihsm sources
        ../aes_cmac/aes.c
        ../aes_cmac/aes_cmac.c
        ../common/hash.c
        ../common/pkcs5.c
        ../common/rand.c
        ../common/ecdh.c
        ../common/openssl-compat.c
        ../lib/error.c
        ../lib/lib_util.c
        ../lib/yubihsm.c
        # cmdline sources
        ${GGO_C}
    )
    set_target_properties (fuzz_get_attribute_value PROPERTIES COMPILE_FLAGS "-DSTATIC -fsanitize=fuzzer")
    set_target_properties (fuzz_get_attribute_value PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
    target_link_libraries(fuzz_get_attribute_value ${LIBCRYPTO_LDFLAGS})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-nested-anon-types")
endif (FUZZING)
