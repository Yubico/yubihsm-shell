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
  commands.c
  main.c
  ../common/util.c
  ../common/hash.c
  ../common/parsing.c
  ../common/openssl-compat.c
  )

if(WIN32)
  set(SOURCE ${SOURCE} cmdline.c)
  include(${CMAKE_SOURCE_DIR}/cmake/getopt.cmake)
  find_getopt()
else(WIN32)
  include(gengetopt)
  find_gengetopt ()
  add_gengetopt_files (cmdline "--conf-parser")
  set(SOURCE ${SOURCE} ${GGO_C})
endif(WIN32)

include_directories (
  ${LIBCRYPTO_INCLUDEDIR}
  ${LIBEDIT_INCLUDEDIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../lib
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../common
  )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../ykhsmauth)
set(YKHSMAUTH_LIB ykhsmauth)
set(YKHSMAUTH_LIB_STATIC ykhsmauth_static)

if(WIN32)
  list(APPEND SOURCE ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc @ONLY)
endif(WIN32)

# NOTE(adma): required by gengetopt
add_definitions (-DPACKAGE="yubihsm-shell")
add_definitions (-DVERSION="${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}")

list(APPEND LCOV_REMOVE_PATTERNS "'${PROJECT_SOURCE_DIR}/src/cmdline.c'")

add_executable (yubihsm-shell ${SOURCE})
if (ENABLE_STATIC)
  add_executable (yubihsm-shell_static ${SOURCE})
  set_target_properties (yubihsm-shell_static PROPERTIES COMPILE_FLAGS "-DSTATIC")
  target_link_libraries(yubihsm-shell_static
    ${LIBCRYPTO_LDFLAGS}
    ${LIBEDIT_LDFLAGS}
    ${GETOPT_LIBS}
    yubihsm_static
    ${YKHSMAUTH_LIB_STATIC})
  add_coverage (yubihsm-shell_static)
endif ()

target_link_libraries (
  yubihsm-shell
  ${LIBCRYPTO_LDFLAGS}
  ${LIBEDIT_LDFLAGS}
  ${GETOPT_LIBS}
  yubihsm
  ${YKHSMAUTH_LIB})

# Set install RPATH
set_target_properties(yubihsm-shell PROPERTIES INSTALL_RPATH "${YUBIHSM_INSTALL_LIB_DIR}")

add_coverage (yubihsm-shell)

install(
  TARGETS yubihsm-shell
  ARCHIVE DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}"
  LIBRARY DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}"
  RUNTIME DESTINATION "${YUBIHSM_INSTALL_BIN_DIR}")

if (NOT WITHOUT_MANPAGES)
  include (help2man)
  add_help2man_manpage (yubihsm-shell.1 yubihsm-shell)

  add_custom_target (yubihsm-shell-man ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/yubihsm-shell.1
    )

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/yubihsm-shell.1" DESTINATION "${YUBIHSM_INSTALL_MAN_DIR}/man1")
endif()

add_subdirectory (tests)
