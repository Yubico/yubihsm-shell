macro (find_gengetopt)
  if (NOT GENGETOPT_EXECUTABLE)
    find_program (GENGETOPT_EXECUTABLE gengetopt)
    if (NOT GENGETOPT_EXECUTABLE)
      message (FATAL_ERROR "gengetopt not found. Aborting...")
    endif ()
  endif ()
endmacro ()

macro (add_gengetopt_files _basename)
  find_gengetopt ()

  set (_ggo_extra_input ${ARGV})

  set (_ggo_c ${CMAKE_CURRENT_SOURCE_DIR}/${_basename}.c)
  set (_ggo_h ${CMAKE_CURRENT_SOURCE_DIR}/${_basename}.h)
  set (_ggo_g ${CMAKE_CURRENT_SOURCE_DIR}/${_basename}.ggo)

  add_custom_command (
    OUTPUT ${_ggo_c} ${_ggo_h}
    COMMAND gengetopt ${_ggo_extra_input} -i ${_ggo_g} --output-dir ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${_ggo_g}
#    BYPRODUCTS
    COMMENT "Generating getopt parser code (cmdline.{h,c}) ..."
    VERBATIM
    )

  set (GGO_C ${_ggo_c})
  set (GGO_H ${_ggo_h})

endmacro (add_gengetopt_files)
