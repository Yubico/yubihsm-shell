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

if (CMAKE_C_COMPILER_ID MATCHES Clang)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
else ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
endif ()

find_program (BASH_PROGRAM bash)

add_test(
  NAME engine_tests
  COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/engine_tests.sh
  )

set(
  SKIPPED_TESTS
  Slot.NoInit
  PKCS11Test.EnumerateMechanisms

  # YH requires login for C_GenerateRandom
  ReadOnlySessionTest.GenerateRandom
  ReadOnlySessionTest.GenerateRandomNone

  ReadOnlySessionTest.UserLoginWrongPIN
  ReadOnlySessionTest.SOLoginFail
  ReadOnlySessionTest.CreateKeyPairObjects
  ReadOnlySessionTest.CreateSecretKeyAttributes
  ReadOnlySessionTest.SecretKeyTestVectors
  ReadOnlySessionTest.SignVerifyRecover
  ReadOnlySessionTest.GenerateKeyInvalid
  ReadOnlySessionTest.GenerateKeyPairInvalid
  ReadOnlySessionTest.WrapUnwrap
  ReadOnlySessionTest.WrapInvalid
  ReadOnlySessionTest.UnwrapInvalid
  ReadWriteSessionTest.CreateCopyDestroyObject
  ReadWriteSessionTest.SetLatchingAttribute
  ReadWriteSessionTest.FindObjectSubset
  ReadWriteSessionTest.ReadOnlySessionSOLoginFail
  ReadWriteSessionTest.SOLogin
  ReadWriteSessionTest.TookanAttackA1
  ReadWriteSessionTest.TookanAttackA3
  ReadWriteSessionTest.TookanAttackA4
  ReadWriteSessionTest.TookanAttackA5a
  ReadWriteSessionTest.TookanAttackA5b
  ReadWriteSessionTest.PublicExponent4Bytes
  ReadWriteSessionTest.ExtractKeys
  ReadWriteSessionTest.AsymmetricTokenKeyPair
  RWUserSessionTest.SOLoginFail
  DataObjectTest.CopyDestroyObjectInvalid
  DataObjectTest.GetMultipleAttributes
  DataObjectTest.GetSetAttributeInvalid
  RWSOSessionTest.SOSessionFail
  RWSOSessionTest.UserLoginFail
  RWEitherSessionTest.TookanAttackA2
  KeyPairTest.EncryptDecrypt
  Ciphers/SecretKeyTest.EncryptDecrypt/0
  Ciphers/SecretKeyTest.EncryptDecrypt/1
  Ciphers/SecretKeyTest.EncryptDecrypt/2
  Ciphers/SecretKeyTest.EncryptDecrypt/3
  Ciphers/SecretKeyTest.EncryptDecrypt/4
  Ciphers/SecretKeyTest.EncryptDecrypt/5
  Ciphers/SecretKeyTest.EncryptFailDecrypt/0
  Ciphers/SecretKeyTest.EncryptFailDecrypt/1
  Ciphers/SecretKeyTest.EncryptFailDecrypt/2
  Ciphers/SecretKeyTest.EncryptFailDecrypt/3
  Ciphers/SecretKeyTest.EncryptFailDecrypt/4
  Ciphers/SecretKeyTest.EncryptFailDecrypt/5
  Ciphers/SecretKeyTest.EncryptDecryptGetSpace/0
  Ciphers/SecretKeyTest.EncryptDecryptGetSpace/1
  Ciphers/SecretKeyTest.EncryptDecryptGetSpace/2
  Ciphers/SecretKeyTest.EncryptDecryptGetSpace/3
  Ciphers/SecretKeyTest.EncryptDecryptGetSpace/4
  Ciphers/SecretKeyTest.EncryptDecryptGetSpace/5
  Ciphers/SecretKeyTest.EncryptDecryptParts/0
  Ciphers/SecretKeyTest.EncryptDecryptParts/1
  Ciphers/SecretKeyTest.EncryptDecryptParts/2
  Ciphers/SecretKeyTest.EncryptDecryptParts/3
  Ciphers/SecretKeyTest.EncryptDecryptParts/4
  Ciphers/SecretKeyTest.EncryptDecryptParts/5
  Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/0
  Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/1
  Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/2
  Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/3
  Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/4
  Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/5
  Ciphers/SecretKeyTest.EncryptErrors/0
  Ciphers/SecretKeyTest.EncryptErrors/1
  Ciphers/SecretKeyTest.EncryptErrors/2
  Ciphers/SecretKeyTest.EncryptErrors/3
  Ciphers/SecretKeyTest.EncryptErrors/4
  Ciphers/SecretKeyTest.EncryptErrors/5
  Ciphers/SecretKeyTest.DecryptErrors/0
  Ciphers/SecretKeyTest.DecryptErrors/1
  Ciphers/SecretKeyTest.DecryptErrors/2
  Ciphers/SecretKeyTest.DecryptErrors/3
  Ciphers/SecretKeyTest.DecryptErrors/4
  Ciphers/SecretKeyTest.DecryptErrors/5
  Ciphers/SecretKeyTest.EncryptUpdateErrors/0
  Ciphers/SecretKeyTest.EncryptUpdateErrors/1
  Ciphers/SecretKeyTest.EncryptUpdateErrors/2
  Ciphers/SecretKeyTest.EncryptUpdateErrors/3
  Ciphers/SecretKeyTest.EncryptUpdateErrors/4
  Ciphers/SecretKeyTest.EncryptUpdateErrors/5
  Ciphers/SecretKeyTest.EncryptModePolicing1/0
  Ciphers/SecretKeyTest.EncryptModePolicing1/1
  Ciphers/SecretKeyTest.EncryptModePolicing1/2
  Ciphers/SecretKeyTest.EncryptModePolicing1/3
  Ciphers/SecretKeyTest.EncryptModePolicing1/4
  Ciphers/SecretKeyTest.EncryptModePolicing1/5
  Ciphers/SecretKeyTest.EncryptModePolicing2/0
  Ciphers/SecretKeyTest.EncryptModePolicing2/1
  Ciphers/SecretKeyTest.EncryptModePolicing2/2
  Ciphers/SecretKeyTest.EncryptModePolicing2/3
  Ciphers/SecretKeyTest.EncryptModePolicing2/4
  Ciphers/SecretKeyTest.EncryptModePolicing2/5
  Ciphers/SecretKeyTest.EncryptInvalidIV/0
  Ciphers/SecretKeyTest.EncryptInvalidIV/1
  Ciphers/SecretKeyTest.EncryptInvalidIV/2
  Ciphers/SecretKeyTest.EncryptInvalidIV/3
  Ciphers/SecretKeyTest.EncryptInvalidIV/4
  Ciphers/SecretKeyTest.EncryptInvalidIV/5
  Ciphers/SecretKeyTest.DecryptInvalidIV/0
  Ciphers/SecretKeyTest.DecryptInvalidIV/1
  Ciphers/SecretKeyTest.DecryptInvalidIV/2
  Ciphers/SecretKeyTest.DecryptInvalidIV/3
  Ciphers/SecretKeyTest.DecryptInvalidIV/4
  Ciphers/SecretKeyTest.DecryptInvalidIV/3
  Ciphers/SecretKeyTest.DecryptInvalidIV/4
  Ciphers/SecretKeyTest.DecryptInvalidIV/5
  Ciphers/SecretKeyTest.DecryptUpdateErrors/0
  Ciphers/SecretKeyTest.DecryptUpdateErrors/1
  Ciphers/SecretKeyTest.DecryptUpdateErrors/2
  Ciphers/SecretKeyTest.DecryptUpdateErrors/3
  Ciphers/SecretKeyTest.DecryptUpdateErrors/4
  Ciphers/SecretKeyTest.DecryptUpdateErrors/5
  Ciphers/SecretKeyTest.EncryptFinalImmediate/0
  Ciphers/SecretKeyTest.EncryptFinalImmediate/1
  Ciphers/SecretKeyTest.EncryptFinalImmediate/2
  Ciphers/SecretKeyTest.EncryptFinalImmediate/3
  Ciphers/SecretKeyTest.EncryptFinalImmediate/4
  Ciphers/SecretKeyTest.EncryptFinalImmediate/5
  Ciphers/SecretKeyTest.EncryptFinalErrors1/0
  Ciphers/SecretKeyTest.EncryptFinalErrors1/1
  Ciphers/SecretKeyTest.EncryptFinalErrors1/2
  Ciphers/SecretKeyTest.EncryptFinalErrors1/3
  Ciphers/SecretKeyTest.EncryptFinalErrors1/4
  Ciphers/SecretKeyTest.EncryptFinalErrors1/5
  Ciphers/SecretKeyTest.EncryptFinalErrors2/0
  Ciphers/SecretKeyTest.EncryptFinalErrors2/1
  Ciphers/SecretKeyTest.EncryptFinalErrors2/2
  Ciphers/SecretKeyTest.EncryptFinalErrors2/3
  Ciphers/SecretKeyTest.EncryptFinalErrors2/4
  Ciphers/SecretKeyTest.EncryptFinalErrors2/5
  Ciphers/SecretKeyTest.DecryptFinalErrors1/0
  Ciphers/SecretKeyTest.DecryptFinalErrors1/1
  Ciphers/SecretKeyTest.DecryptFinalErrors1/2
  Ciphers/SecretKeyTest.DecryptFinalErrors1/3
  Ciphers/SecretKeyTest.DecryptFinalErrors1/4
  Ciphers/SecretKeyTest.DecryptFinalErrors1/5
  Ciphers/SecretKeyTest.DecryptFinalErrors2/0
  Ciphers/SecretKeyTest.DecryptFinalErrors2/1
  Ciphers/SecretKeyTest.DecryptFinalErrors2/2
  Ciphers/SecretKeyTest.DecryptFinalErrors2/3
  Ciphers/SecretKeyTest.DecryptFinalErrors2/4
  Ciphers/SecretKeyTest.DecryptFinalErrors2/5
  Digests/DigestTest.DigestKey/0
  Digests/DigestTest.DigestKey/1
  Digests/DigestTest.DigestKey/2
  Digests/DigestTest.DigestKey/3
  Digests/DigestTest.DigestKey/4
  Digests/DigestTest.DigestKeyInvalid/0
  Digests/DigestTest.DigestKeyInvalid/1
  Digests/DigestTest.DigestKeyInvalid/2
  Digests/DigestTest.DigestKeyInvalid/3
  Digests/DigestTest.DigestKeyInvalid/4
  Signatures/SignTest.SignVerify/0
  Signatures/SignTest.SignFailVerifyWrong/0
  Signatures/SignTest.SignFailVerifyShort/0
  Duals/DualSecretKeyTest.DigestEncrypt/0
  Duals/DualSecretKeyTest.DigestEncrypt/1
  Duals/DualSecretKeyTest.DigestEncrypt/2
  Duals/DualSecretKeyTest.DigestEncrypt/3
  Duals/DualSecretKeyTest.DigestEncrypt/4
  Duals/DualSecretKeyTest.DigestEncrypt/5
  Init.InitArgsBadReserved
  )
string(REPLACE ";" ":" SKIPPED_TESTS_STR "${SKIPPED_TESTS}")

if (DEFINED ENV{PKCS11TEST_PATH})
  if (NOT EXISTS $ENV{PKCS11TEST_PATH}/pkcs11test)
    message(FATAL_ERROR "PKCS11TEST_PATH defined, but $ENV{PKCS11TEST_PATH}/pkcs11test doesn't exist")
    endif ()
else ()
  message(WARNING "PKCS11TEST_PATH not defined, assuming that pkcs11test is in PATH")
endif ()

message(STATUS "Using PKCS11_TESTER: $ENV{PKCS11TEST_PATH}/pkcs11test")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(LIBEXT "dylib")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(LIBEXT "so")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(LIBEXT "dll")
endif ()

add_test(
  NAME pkcs11test
  COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11test.sh
  )

set_property(
  TEST pkcs11test
  APPEND PROPERTY ENVIRONMENT
  SKIPPED_TESTS=${SKIPPED_TESTS_STR})

set_property(
  TEST pkcs11test
  APPEND PROPERTY ENVIRONMENT
  BINDIR=${CMAKE_BINARY_DIR})

set_property(
  TEST pkcs11test
  APPEND PROPERTY ENVIRONMENT
  LIBEXT=${LIBEXT})

set (
  SOURCE_ECDH_DERIVE
  ecdh_derive_test.c
  )

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
add_executable (ecdh_derive_test ${SOURCE_ECDH_DERIVE})

target_link_libraries (
  ecdh_derive_test
  ${LIBCRYPTO_LDFLAGS}
  "-ldl")

add_test (
  NAME ecdh_derive_test
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/ecdh_derive_test ${CMAKE_CURRENT_BINARY_DIR}/../yubihsm_pkcs11.${LIBEXT}
  )
endif()
