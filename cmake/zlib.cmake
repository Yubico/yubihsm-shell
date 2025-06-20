macro(find_zlib)
    if(MSVC)
        if (NOT ZLIB_LIB_DIR AND NOT ZLIB_INCLUDE_DIR)
            message(FATAL_ERROR "Missing 'ZLIB_LIB_DIR' and 'ZLIB_INCLUDE_DIR' options to CMake command. Aborting...")
        else (NOT ZLIB_LIB_DIR AND NOT ZLIB_INCLUDE_DIR)
            find_library(ZLIB zlib PATHS ${ZLIB_LIB_DIR})
            set(ZLIB_LIBS ${ZLIB})
            include_directories(${ZLIB_INCLUDE_DIR})
        endif (NOT ZLIB_LIB_DIR AND NOT ZLIB_INCLUDE_DIR)
    else (MSVC)
        find_package(ZLIB REQUIRED)
        set(ZLIB_LIBS ${ZLIB_LIBRARIES})
        include_directories(${ZLIB_INCLUDE_DIRS})
    endif (MSVC)
endmacro()