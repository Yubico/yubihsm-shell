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

set (
  SOURCE_PARSING
  test_parsing.c
  )

set (
  SOURCE_PBKDF2
  test_pbkdf2.c
  ../../common/pkcs5.c
  ../../common/hash.c
  )

set (
  SOURCE_USB_URL
  test_usb_url.c
  ../lib_util.c
  )

set (
  SOURCE_UTIL
  test_util.c
  ../lib_util.c
  )

include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}/../lib
  )

add_executable (test_parsing ${SOURCE_PARSING})

add_executable (test_pbkdf2 ${SOURCE_PBKDF2})

add_executable (test_usb_url ${SOURCE_USB_URL})

add_executable (test_util ${SOURCE_UTIL})

target_link_libraries (
  test_parsing
  yubihsm
  )

target_link_libraries (
  test_pbkdf2
  # this doesn't really need libyubihsm, needs openssl/windows whatever
  yubihsm
  )
