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

set (
  SOURCE
  error.c
  ykyh.c
)

include_directories (
  ${LIBPCSC_INCLUDEDIR}
)

add_library (ykyh SHARED ${SOURCE})

#add_definitions (-DVERSION="${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}")

target_link_libraries (ykyh ${LIBPCSC_LDFLAGS})

set_target_properties (ykyh PROPERTIES VERSION "${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}" SOVERSION ${yubihsm_shell_VERSION_MAJOR})

# Set install RPATH
set_target_properties(ykyh PROPERTIES INSTALL_RPATH "${YUBIHSM_INSTALL_LIB_DIR}")

add_library (ykyh_static STATIC ${SOURCE})
set_target_properties (ykyh_static PROPERTIES POSITION_INDEPENDENT_CODE on OUTPUT_NAME ykyh)
set_target_properties (ykyh_static PROPERTIES COMPILE_FLAGS "-DSTATIC")
target_link_libraries (ykyh_static ${LIBPCSC_LDFLAGS})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykyh.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ykyh.pc @ONLY)

install(
  TARGETS ykyh
  ARCHIVE DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}"
  LIBRARY DESTINATION "${YUBIHSM_INSTALL_LIB_DIR}"
  RUNTIME DESTINATION "${YUBIHSM_INSTALL_BIN_DIR}")
install(FILES ykyh.h DESTINATION ${YUBIHSM_INSTALL_INC_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ykyh.pc DESTINATION ${YUBIHSM_INSTALL_PKGCONFIG_DIR})
