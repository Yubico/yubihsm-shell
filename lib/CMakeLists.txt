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

if(MSVC)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
endif()

set (
  SOURCE
  ${CMAKE_CURRENT_SOURCE_DIR}/../aes_cmac/aes.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../aes_cmac/aes_cmac.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/hash.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/pkcs5.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/rand.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/ecdh.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/openssl-compat.c
  error.c
  lib_util.c
  yubihsm.c
)

if(MSVC)
  set(SOURCE ${SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/../common/time_win.c)
endif(MSVC)
set(STATIC_SOURCE ${SOURCE})

if(WIN32)
  set(ADDITIONAL_LIBRARY ws2_32)
  set (
    HTTP_SOURCE
    yubihsm_winhttp.c
    lib_util.c
    ${CMAKE_CURRENT_BINARY_DIR}/version_winhttp.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/time_win.c
    )
  set (
    USB_SOURCE
    yubihsm_usb.c
    yubihsm_winusb.c
    lib_util.c
    ${CMAKE_CURRENT_BINARY_DIR}/version_winusb.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/time_win.c
    )
  set(HTTP_LIBRARY winhttp ws2_32)
  set(USB_LIBRARY winusb ws2_32 setupapi)

  if(${WIN32_BCRYPT})
    set (CRYPT_LIBRARY bcrypt ncrypt)
    add_definitions (-D_WIN32_BCRYPT)
  else(${WIN32_BCRYPT})
    set(CRYPT_LIBRARY ${LIBCRYPTO_LDFLAGS})
  endif(${WIN32_BCRYPT})
  list(APPEND SOURCE ${CMAKE_CURRENT_BINARY_DIR}/version.rc)

  list(APPEND STATIC_SOURCE yubihsm_winusb.c yubihsm_usb.c yubihsm_winhttp.c)
else(WIN32)
  set(ADDITIONAL_LIBRARY -ldl)
  set (
    USB_SOURCE
    yubihsm_usb.c
    yubihsm_libusb.c
    lib_util.c
    )
  set (
    HTTP_SOURCE
    yubihsm_curl.c
    lib_util.c
    )
  set(HTTP_LIBRARY ${LIBCURL_LDFLAGS})
  set(USB_LIBRARY ${LIBUSB_LDFLAGS})
  set(CRYPT_LIBRARY ${LIBCRYPTO_LDFLAGS})

  list(APPEND STATIC_SOURCE yubihsm_libusb.c yubihsm_usb.c yubihsm_curl.c)
endif(WIN32)

include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${LIBCRYPTO_INCLUDEDIR}
  ${LIBCURL_INCLUDEDIR}
)

add_library (yubihsm SHARED ${SOURCE})
add_library (yubihsm_usb SHARED ${USB_SOURCE})
add_library (yubihsm_http SHARED ${HTTP_SOURCE})

set_target_properties(yubihsm PROPERTIES BUILD_RPATH "${CMAKE_BINARY_DIR}/lib")
set_target_properties (yubihsm PROPERTIES VERSION "${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}" SOVERSION ${yubihsm_shell_VERSION_MAJOR})
set_target_properties (yubihsm_usb PROPERTIES VERSION "${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}" SOVERSION ${yubihsm_shell_VERSION_MAJOR})
set_target_properties (yubihsm_http PROPERTIES VERSION "${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}" SOVERSION ${yubihsm_shell_VERSION_MAJOR})
if(MSVC)
  set_target_properties(yubihsm PROPERTIES OUTPUT_NAME libyubihsm)
  set_target_properties(yubihsm_usb PROPERTIES OUTPUT_NAME libyubihsm_usb)
  set_target_properties(yubihsm_http PROPERTIES OUTPUT_NAME libyubihsm_http)
else(MSVC)
  set_target_properties(yubihsm PROPERTIES OUTPUT_NAME yubihsm)
  set_target_properties(yubihsm_usb PROPERTIES OUTPUT_NAME yubihsm_usb)
  set_target_properties(yubihsm_http PROPERTIES OUTPUT_NAME yubihsm_http)
endif(MSVC)

if (ENABLE_STATIC)
  add_library (yubihsm_static STATIC ${STATIC_SOURCE})
  set_target_properties (yubihsm_static PROPERTIES POSITION_INDEPENDENT_CODE on OUTPUT_NAME yubihsm)
  set_target_properties (yubihsm_static PROPERTIES COMPILE_FLAGS "-DSTATIC " )
  add_coverage (yubihsm_static)
endif()

if(${WIN32})
else(${WIN32})
  if(${LIBUSB_VERSION} VERSION_LESS 1.0.16)
    set(LIBUSB_CFLAGS "${LIBUSB_CFLAGS} -DNO_LIBUSB_STRERROR")
  endif()
  set_target_properties (yubihsm_usb PROPERTIES COMPILE_FLAGS ${LIBUSB_CFLAGS})
  if(ENABLE_STATIC)
    set_property(TARGET yubihsm_static APPEND_STRING PROPERTY COMPILE_FLAGS ${LIBUSB_CFLAGS})
  endif(ENABLE_STATIC)
endif(${WIN32})

add_coverage (yubihsm)
add_coverage (yubihsm_usb)
add_coverage (yubihsm_http)

add_definitions (-DVERSION="${yubihsm_shell_VERSION_MAJOR}.${yubihsm_shell_VERSION_MINOR}.${yubihsm_shell_VERSION_PATCH}")
add_definitions (-DSOVERSION="${yubihsm_shell_VERSION_MAJOR}")

target_link_libraries (yubihsm ${CRYPT_LIBRARY} ${ADDITIONAL_LIBRARY})
target_link_libraries (yubihsm_usb ${USB_LIBRARY})
target_link_libraries (yubihsm_http ${HTTP_LIBRARY})
if(ENABLE_STATIC)
  target_link_libraries (yubihsm_static ${CRYPT_LIBRARY} ${ADDITIONAL_LIBRARY} ${HTTP_LIBRARY} ${USB_LIBRARY})
endif(ENABLE_STATIC)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/yubihsm.pc.in ${CMAKE_CURRENT_BINARY_DIR}/yubihsm.pc @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/common/platform-config.h.in ${CMAKE_SOURCE_DIR}/common/platform-config.h @ONLY)

if(WIN32)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc @ONLY)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version_winhttp.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version_winhttp.rc @ONLY)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version_winusb.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version_winusb.rc @ONLY)
endif(WIN32)

install(
  TARGETS yubihsm
  ARCHIVE DESTINATION ${YUBIHSM_INSTALL_LIB_DIR}
  LIBRARY DESTINATION ${YUBIHSM_INSTALL_LIB_DIR}
  RUNTIME DESTINATION ${YUBIHSM_INSTALL_BIN_DIR})
install(
  TARGETS yubihsm_usb
  ARCHIVE DESTINATION ${YUBIHSM_INSTALL_LIB_DIR}
  LIBRARY DESTINATION ${YUBIHSM_INSTALL_LIB_DIR}
  RUNTIME DESTINATION ${YUBIHSM_INSTALL_BIN_DIR})
install(
  TARGETS yubihsm_http
  ARCHIVE DESTINATION ${YUBIHSM_INSTALL_LIB_DIR}
  LIBRARY DESTINATION ${YUBIHSM_INSTALL_LIB_DIR}
  RUNTIME DESTINATION ${YUBIHSM_INSTALL_BIN_DIR})
install(FILES yubihsm.h DESTINATION ${YUBIHSM_INSTALL_INC_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/yubihsm.pc DESTINATION ${YUBIHSM_INSTALL_PKGCONFIG_DIR})

add_subdirectory (tests)

add_test(
  NAME parsing
  COMMAND test_parsing
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/lib/tests/
  )

add_test(
  NAME pbkdf2
  COMMAND test_pbkdf2
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/lib/tests/
  )

add_test(
  NAME attest
  COMMAND attest
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/examples/
  )

add_test(
  NAME generate_ec
  COMMAND generate_ec
  )

add_test(
  NAME generate_hmac
  COMMAND generate_hmac
  )

add_test(
  NAME import_authkey
  COMMAND import_authkey
  )

add_test(
  NAME import_rsa
  COMMAND import_rsa
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/examples/
  )

add_test(
  NAME info
  COMMAND info
  )

add_test(
  NAME wrap
  COMMAND wrap
  )

add_test(
  NAME wrap_data
  COMMAND wrap_data
  )

add_test(
  NAME yubico_otp
  COMMAND yubico_otp
  )

add_test(
  NAME echo
  COMMAND echo
  )

add_test(
  NAME asym_auth
  COMMAND asym_auth
  )

add_test(
  NAME import_ec
  COMMAND import_ec
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/examples/
  )

add_test(
  NAME generate_rsa
  COMMAND generate_rsa
  )

add_test(
  NAME logs
  COMMAND logs
  )

add_test(
  NAME ssh
  COMMAND ssh
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/examples/
  )

add_test(
  NAME decrypt_rsa
  COMMAND decrypt_rsa
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/examples/
  )

add_test(
  NAME decrypt_ec
  COMMAND decrypt_ec
  )

add_test(
  NAME import_ed
  COMMAND import_ed
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/examples/
  )

add_test(
  NAME change_authkey
  COMMAND change_authkey
  )
