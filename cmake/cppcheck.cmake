macro (add_cppcheck_target _cc_target _cc_directories _cc_ignore)

  set(_cc_directories_var ${_cc_directories})
  string (REPLACE " " " ${CMAKE_CURRENT_SOURCE_DIR}/" _cc_abs_directories ${_cc_directories_var})
  set (_cc_abs_directories "${CMAKE_CURRENT_SOURCE_DIR}/${_cc_abs_directories}")
  separate_arguments (xxx UNIX_COMMAND "${_cc_abs_directories}")

  if (_cc_ignore STREQUAL "")
    string (REPLACE " " "${CMAKE_CURRENT_SOURCE_DIR}/" _cc_abs_ignore ${_cc_ignore})
    set (_cc_abs_ignore ";${CMAKE_CURRENT_SOURCE_DIR}/${_cc_abs_ignore}")
  endif ()

  set (_cc_extra_input "${ARGV3}")

  message ("Replaced ?${_cc_abs_directories}?")
  message ("Replaxxx ?${xxx}?")
  list (LENGTH _cc_abs_directories bla)
  message ("ignored ${_cc_abs_ignore} length is ${bla}")

  file(GLOB_RECURSE ALL_SOURCE_FILES *.c *.h)
  #message (${ALL_SOURCE_FILES})

  #
  #  set (_ignore_arg "--ignore ${_ignore}")
  #else ()
  #  set (_ignore_arg "set ${_ignore}")
  #endif ()

  #list (APPEND _cpp_remove_list "")
  #list (APPEND _cpp_remove_list )
  #set (_ggo_extra_input ${ARGV1})

  add_custom_target (
    ${_cc_target}
    COMMAND /usr/bin/cppcheck
    --enable=all
    --template="[{severity}][{id}] {message} {callstack} \(On {file}:{line}\)"
    --suppress="unusedStructMember"
    -i="${_cc_abs_ignore}"
    --verbose
    --quiet
    ${_cc_extra_input}
    #"${_cc_abs_directories}"
    ${CMAKE_SOURCE_DIR}
#"${xxx}"
#VERBATIM
    )
endmacro(add_cppcheck_target)
