#!/bin/bash

set -e -o pipefail -x

YUBIHSM_SHELL_EXECUTABLE=$1

otool -hv $YUBIHSM_SHELL_EXECUTABLE
# awk only looks at the fourth (last) output line of otool
# the first line is the path to the file
# the second line is simply 'Mach header'
# the third line contains the column names
otool -hv $YUBIHSM_SHELL_EXECUTABLE | awk 'NR == 4 {
            split($0, stdin_split, " ");

            flag_pie = 0;
            flag_allow_stack_execution = 0;
            flag_no_heap_execution = 0;

            # first 7 tokens are unrelated to the header flags
            # so we start looking tokens from the 8th position
            for (i = 8; i <= length(stdin_split); i++) {
              flag = stdin_split[i]
              if (flag == "PIE") {
                flag_pie = 1;
              }
              if (flag == "ALLOW_STACK_EXECUTION") {
                flag_allow_stack_execution = 1;
              }
              if (flag == "NO_HEAP_EXECUTION") {
                flag_no_heap_execution = 1;
              }
            }

            fail = 0;
            if (flag_pie == 0) {
              print "BINARY DOES NOT HAVE THE PIE FLAG";
              fail = 1;
            }
            if (flag_allow_stack_execution == 1) {
              print "BINARY ALLOWS EXECUTION FROM THE STACK";
              fail = 1;
            }
            if (flag_no_heap_execution == 0) {
              print "BINARY ALLOWS EXECUTION FROM THE HEAP";
              # currently we do not treat this as an error
            }
            if (fail == 1) {
              exit 1;
            }
          }'
if [ $? = 1 ]; then
  exit 1
fi

check_import() {
  nm -u $YUBIHSM_SHELL_EXECUTABLE | grep $1 >/dev/null
  # return code of grep is 0 when it finds something
  if [ $? == 0 ]; then
    echo 1
  else
    echo 0
  fi
}
chk_fail=$(check_import '___stack_chk_fail')
chk_guard=$(check_import '___stack_chk_guard')
if [ $chk_fail = 0 ] | [ $chk_guard = 0 ]; then
  echo "BINARY DOES NOT HAVE STACK CANARIES"
  exit 1
fi
