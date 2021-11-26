include(CheckCCompilerFlag)
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    include(CheckLinkerFlag)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (CMAKE_C_COMPILER_ID STREQUAL "Clang" OR
    CMAKE_C_COMPILER_ID STREQUAL "AppleClang" OR
    CMAKE_C_COMPILER_ID STREQUAL "GNU")

    check_c_compiler_flag("-fstack-protector-all" HAVE_STACK_PROTECTOR_ALL)
    if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        check_linker_flag(C "-Wl,-z,relro,-z,now" HAVE_RELRO)
        check_linker_flag(C "-Wl,-z,noexecstack" HAVE_NOEXECSTACK)
    endif()

    add_compile_options (-Wall -Wextra -Werror)
    add_compile_options (-Wformat -Wformat-nonliteral -Wformat-security)
    add_compile_options (-Wshadow)
    add_compile_options (-Wcast-qual)
    add_compile_options (-Wmissing-prototypes)
    add_compile_options (-Wbad-function-cast)
    add_compile_options (-Wno-implicit-fallthrough)
    #add_compile_options (-Wwrite-strings)
    add_compile_options (-pedantic -pedantic-errors)
    if (NOT FUZZ)
        add_compile_options(-O2)
        add_definitions (-D_FORTIFY_SOURCE=2)
    endif ()

	if(HAVE_STACK_PROTECTOR_ALL)
        message(STATUS "-fstack-protector-all support detected")
		add_compile_options(-fstack-protector-all)
	endif()
    if (HAVE_RELRO)
        message(STATUS "relro support detected")
        add_link_options(-Wl,-z,relro,-z,now)
    endif ()
    if (HAVE_NOEXECSTACK)
        message(STATUS "noexecstack support detected")
        add_link_options (-Wl,-z,noexecstack)
    endif ()
elseif (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    add_compile_options (/GS)
    add_compile_options (/Gs)
    add_link_options (/NXCOMPAT)
    add_link_options (/guard:cf)
else ()
    message(WARNING "Security related flags cannot be set for unknown C compiler.")
endif ()