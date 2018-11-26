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

find_program (BASH_PROGRAM bash)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/data.txt
  ${CMAKE_CURRENT_BINARY_DIR}/data.txt
  COPYONLY)

configure_file (
  ${CMAKE_CURRENT_SOURCE_DIR}/sig.out
  ${CMAKE_CURRENT_BINARY_DIR}/sig.out
  COPYONLY)

add_test(
  NAME bash_tests
  COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/tests.sh
  )

add_test(
  NAME wrapped_tests
  COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/wrapped_tests.sh
  )
