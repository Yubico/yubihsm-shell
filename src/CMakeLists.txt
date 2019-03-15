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

include(gengetopt)

find_gengetopt ()
add_gengetopt_files (cmdline "--conf-parser")

set (
  SOURCE
  ${GGO_C}
  commands.c
  main.c
  ../common/util.c
  ../common/hash.c
  )

if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE ${SOURCE}
    ../common/openssl-compat.c)
endif()

include_directories (
  ${LIBCRYPTO_INCLUDEDIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../lib
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../common
  ${CMAKE_CURRENT_SOURCE_DIR}/../ykyh
  )

if(${WIN32})
  list(APPEND SOURCE ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc @ONLY)
endif(${WIN32})

if (CMAKE_C_COMPILER_ID MATCHES Clang)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
else ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
endif ()

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
    yubihsm_static)
  add_coverage (yubihsm-shell_static)
endif ()

target_link_libraries (
  yubihsm-shell
  ${LIBCRYPTO_LDFLAGS}
  ${LIBEDIT_LDFLAGS}
  yubihsm
  )

# Set install RPATH
set_target_properties(yubihsm-shell PROPERTIES INSTALL_RPATH "${YUBIHSM_INSTALL_LIB_DIR}")

add_coverage (yubihsm-shell)

if (ENABLE_EXPERIMENTAL_YKYH)
  add_definitions(-DUSE_YKYH="1")
  target_link_libraries (
    yubihsm-shell
    ykyh
    )
  if (ENABLE_STATIC)
    target_link_libraries (
      yubihsm-shell_static
      ykyh_static
      )
  endif()
endif()

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
