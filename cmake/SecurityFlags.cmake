set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (CMAKE_C_COMPILER_ID STREQUAL "Clang" OR
    CMAKE_C_COMPILER_ID STREQUAL "AppleClang" OR
    CMAKE_C_COMPILER_ID STREQUAL "GNU")

    include(CheckCCompilerFlag)
    check_c_compiler_flag("-Wshorten-64-to-32" HAVE_SHORTEN_64_TO_32)
    check_c_compiler_flag("-fstack-protector-all" HAVE_STACK_PROTECTOR_ALL)

    if (CMAKE_VERSION VERSION_GREATER 3.18)
        include(CheckLinkerFlag)
        check_linker_flag(C "-Wl,-z,relro,-z,now" HAVE_RELRO)
        check_linker_flag(C "-Wl,-z,noexecstack" HAVE_NOEXECSTACK)
    endif ()

    add_compile_options (-Wall -Wextra -Werror)
    add_compile_options (-Wformat -Wformat-nonliteral -Wformat-security)
    add_compile_options (-Wshadow)
    #add_compile_options (-Wcast-qual)
    add_compile_options (-Wmissing-prototypes)
    add_compile_options (-Wbad-function-cast)
    add_compile_options (-Wno-implicit-fallthrough)
    #add_compile_options (-Wwrite-strings)
    add_compile_options (-pedantic -pedantic-errors)
    if (NOT FUZZ)
        add_compile_options(-O2)
        add_definitions (-D_FORTIFY_SOURCE=2)
    endif ()

    #set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g2")
    #set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer")

    if(HAVE_SHORTEN_64_TO_32)
        #add_compile_options (-Wshorten-64-to-32)
    endif()

    if(HAVE_STACK_PROTECTOR_ALL)
		add_compile_options(-fstack-protector-all)
	endif()

    if (HAVE_RELRO)
        add_link_options(-Wl,-z,relro,-z,now)
    endif ()

    if (HAVE_NOEXECSTACK)
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
