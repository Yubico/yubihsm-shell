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

add_gengetopt_files (cmdline)

set (
  SOURCE
  ${GGO_C}
  main.c
  ../common/parsing.c
  )

message("${GGO_C}")

include_directories (
  ${LIBCRYPTO_INCLUDEDIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../ykyh
  ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

if (CMAKE_C_COMPILER_ID MATCHES Clang)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
else ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
endif ()

# NOTE(adma): required by gengetopt
add_definitions (-DPACKAGE="yhauth")
add_definitions (-DVERSION="${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
set_property(SOURCE ${GGO_C} APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-unused-but-set-variable ")
endif()

add_executable (yhauth ${SOURCE})

target_link_libraries (
  yhauth
  ${LIBCRYPTO_LDFLAGS}
  ykyh
  )

# Set install RPATH
set_target_properties(yhauth PROPERTIES INSTALL_RPATH "${YUBIHSM_INSTALL_LIB_DIR}")

install(
  TARGETS yhauth
  ARCHIVE DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}"
  LIBRARY DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}"
  RUNTIME DESTINATION "${YUBIHSM_INSTALL_BIN_DIR}")

if (NOT WITHOUT_MANPAGES)
  include (help2man)
  add_help2man_manpage (yhauth.1 yhauth)

  add_custom_target (yhauth-man ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/yhauth.1
    )

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/yhauth.1" DESTINATION "${YUBIHSM_INSTALL_MAN_DIR}/man1")
endif ()
