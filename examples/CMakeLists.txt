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

add_definitions (-DDEFAULT_CONNECTOR_URL="${DEFAULT_CONNECTOR_URL}")

if (CMAKE_C_COMPILER_ID MATCHES Clang)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
else ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
endif ()

set (
  SOURCE_IMPORT_RSA
  import_rsa.c
  ../common/util.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_IMPORT_RSA ${SOURCE_IMPORT_RSA}
    ../common/openssl-compat.c)
endif()

set (
  SOURCE_GENERATE_EC
  generate_ec.c
  ../common/util.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_GENERATE_EC ${SOURCE_GENERATE_EC}
    ../common/openssl-compat.c)
endif()

set (
  SOURCEINFO
  info.c
  )

set (
  SOURCE_IMPORT_AUTHKEY
  import_authkey.c
  )

set (
  SOURCE_GENERATE_HMAC
  generate_hmac.c
  )

set (
  SOURCE_WRAP
  wrap.c
  )

set (
  SOURCE_WRAP_DATA
  wrap_data.c
  )

set (
  SOURCE_ATTEST
  attest.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_ATTEST ${SOURCE_ATTEST}
    ../common/openssl-compat.c)
endif()

set (
  SOURCE_YUBICO_OTP
  yubico_otp.c
  )

set (
  SOURCE_ECHO
  echo.c
  )

set (
  SOURCE_IMPORT_EC
  import_ec.c
  ../common/util.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_IMPORT_EC ${SOURCE_IMPORT_EC}
    ../common/openssl-compat.c)
endif()

set (
  SOURCE_GENERATE_RSA
  generate_rsa.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_GENERATE_RSA ${SOURCE_GENERATE_RSA}
    ../common/openssl-compat.c)
endif()


set (
  SOURCE_LOGS
  logs.c
  ../common/util.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_LOGS ${SOURCE_LOGS}
    ../common/openssl-compat.c)
endif()

set (
  SOURCE_SSH
  ssh.c
  ../common/util.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_SSH ${SOURCE_SSH}
    ../common/openssl-compat.c)
endif()

set (
  SOURCE_DECRYPT_RSA
  decrypt_rsa.c
  ../common/util.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_DECRYPT_RSA ${SOURCE_DECRYPT_RSA}
    ../common/openssl-compat.c)
endif()

set (
  SOURCE_P11_GENERATE_RSA
  p11_generate_rsa.c
  )

set (
  SOURCE_DECRYPT_EC
  decrypt_ec.c
  ../common/util.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_DECRYPT_EC ${SOURCE_DECRYPT_EC}
    ../common/openssl-compat.c)
endif()

set (
  SOURCE_IMPORT_ED
  import_ed.c
  ../common/util.c
  )
if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
  set(SOURCE_IMPORT_ED ${SOURCE_IMPORT_ED}
    ../common/openssl-compat.c)
endif()

set (
  SOURCE_CHANGE_AUTHKEY
  change_authkey.c
  )

include_directories (
  ${LIBCRYPTO_INCLUDEDIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../lib
  ${CMAKE_CURRENT_SOURCE_DIR}/../pkcs11
  ${CMAKE_CURRENT_SOURCE_DIR}/../common
  )

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/rsa2048_pvtkey.pem
  ${CMAKE_CURRENT_BINARY_DIR}/rsa2048_pvtkey.pem
  COPYONLY)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/p256_pvtkey.pem
  ${CMAKE_CURRENT_BINARY_DIR}/p256_pvtkey.pem
  COPYONLY)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/attestation_template.pem
  ${CMAKE_CURRENT_BINARY_DIR}/attestation_template.pem
  COPYONLY)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/ssh_ca_pvtkey.pem
  ${CMAKE_CURRENT_BINARY_DIR}/ssh_ca_pvtkey.pem
  COPYONLY)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/ssh_req.dat
  ${CMAKE_CURRENT_BINARY_DIR}/ssh_req.dat
  COPYONLY)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/ed25519_pvtkey.pem
  ${CMAKE_CURRENT_BINARY_DIR}/ed25519_pvtkey.pem
  COPYONLY)

add_executable (import_rsa ${SOURCE_IMPORT_RSA})

target_link_libraries (
  import_rsa
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (generate_ec ${SOURCE_GENERATE_EC})

target_link_libraries (
  generate_ec
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (info ${SOURCEINFO})

target_link_libraries (
  info
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (import_authkey ${SOURCE_IMPORT_AUTHKEY})

target_link_libraries (
  import_authkey
  yubihsm
  )

add_executable (generate_hmac ${SOURCE_GENERATE_HMAC})

target_link_libraries (
  generate_hmac
  yubihsm
  )

add_executable (wrap ${SOURCE_WRAP})

target_link_libraries (
  wrap
  yubihsm
  )

add_executable (wrap_data ${SOURCE_WRAP_DATA})

target_link_libraries (
  wrap_data
  yubihsm
  )

add_executable (attest ${SOURCE_ATTEST})

target_link_libraries (
  attest
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (yubico_otp ${SOURCE_YUBICO_OTP})

target_link_libraries (
  yubico_otp
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (echo ${SOURCE_ECHO})

target_link_libraries (
  echo
  yubihsm
  )

add_executable (import_ec ${SOURCE_IMPORT_EC})

target_link_libraries (
  import_ec
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (generate_rsa ${SOURCE_GENERATE_RSA})

target_link_libraries (
  generate_rsa
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (logs ${SOURCE_LOGS})

target_link_libraries (
  logs
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (ssh ${SOURCE_SSH})

target_link_libraries (
  ssh
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (decrypt_rsa ${SOURCE_DECRYPT_RSA})

target_link_libraries (
  decrypt_rsa
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (decrypt_ec ${SOURCE_DECRYPT_EC})

target_link_libraries (
  decrypt_ec
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (import_ed ${SOURCE_IMPORT_ED})

target_link_libraries (
  import_ed
  ${LIBCRYPTO_LDFLAGS}
  yubihsm
  )

add_executable (change_authkey ${SOURCE_CHANGE_AUTHKEY})

target_link_libraries (
  change_authkey
  yubihsm
  )

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  add_executable (p11_generate_rsa ${SOURCE_P11_GENERATE_RSA})

  target_link_libraries (
    p11_generate_rsa
    dl
    )
endif()
