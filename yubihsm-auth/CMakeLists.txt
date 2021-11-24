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

set (
  SOURCE
  main.c
  ../common/parsing.c
  ../common/pkcs5.c
  ../common/hash.c
  )

if(WIN32)
  set(SOURCE ${SOURCE} cmdline.c)
  include(${CMAKE_SOURCE_DIR}/cmake/getopt.cmake)
  find_getopt()
else(WIN32)
  include(gengetopt)
  add_gengetopt_files (cmdline)
  set(SOURCE ${SOURCE} ${GGO_C})
  message("${GGO_C}")
endif(WIN32)

include_directories (
  ${LIBCRYPTO_INCLUDEDIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../ykhsmauth
  ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

if(WIN32)
  list(APPEND SOURCE ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc @ONLY)
  set (BCRYPT_LIBRARY bcrypt ncrypt)
endif(WIN32)

# NOTE(adma): required by gengetopt
add_definitions (-DPACKAGE="yubihsm-auth")
add_definitions (-DVERSION="${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}")

list(APPEND LCOV_REMOVE_PATTERNS "'${PROJECT_SOURCE_DIR}/yubihsm-auth/cmdline.c'")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
set_property(SOURCE ${GGO_C} APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-unused-but-set-variable ")
endif()

add_executable (yubihsm-auth ${SOURCE})

target_link_libraries (
  yubihsm-auth
  ${LIBCRYPTO_LDFLAGS}
  ${GETOPT_LIBS}
  ykhsmauth
  ${BCRYPT_LIBRARY}
  )

# Set install RPATH
set_target_properties(yubihsm-auth PROPERTIES INSTALL_RPATH "${YUBIHSM_INSTALL_LIB_DIR}")

install(
  TARGETS yubihsm-auth
  ARCHIVE DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}"
  LIBRARY DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}"
  RUNTIME DESTINATION "${YUBIHSM_INSTALL_BIN_DIR}")

if (NOT WITHOUT_MANPAGES)
  include (help2man)
  add_help2man_manpage (yubihsm-auth.1 yubihsm-auth)

  add_custom_target (yubihsm-auth-man ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/yubihsm-auth.1
    )

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/yubihsm-auth.1" DESTINATION "${YUBIHSM_INSTALL_MAN_DIR}/man1")
endif ()
