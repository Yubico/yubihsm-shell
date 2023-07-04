option(FUZZING "Compile binaries with fuzzing instrumentation" OFF)
option(LIBFUZZER_ASAN "Enable ASAN instrumentation with libfuzzer" OFF)

if (FUZZING)
    message(STATUS "Building with fuzzing instrumentation.")

    string (APPEND CMAKE_C_FLAGS " -DFUZZING")
    string (APPEND CMAKE_C_FLAGS " -fno-omit-frame-pointer -O1")

    string (APPEND CMAKE_CXX_FLAGS " -std=c++17")
    string (APPEND CMAKE_CXX_FLAGS " -DFUZZING")
    string (APPEND CMAKE_CXX_FLAGS " -fno-omit-frame-pointer -O1")

    string (APPEND CMAKE_C_FLAGS " -fsanitize=address")
    string (APPEND CMAKE_CXX_FLAGS " -fsanitize=address")
    string (APPEND CMAKE_EXE_LINKER_FLAGS " -fsanitize=address")

    string (APPEND CMAKE_C_FLAGS " -fsanitize=undefined")
    string (APPEND CMAKE_CXX_FLAGS " -fsanitize=undefined")
    string (APPEND CMAKE_EXE_LINKER_FLAGS " -fsanitize=undefined")
endif ()
