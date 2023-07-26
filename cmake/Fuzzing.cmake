option(FUZZING "Compile binaries with fuzzing instrumentation" OFF)
option(LIBFUZZER_ASAN "Enable ASAN instrumentation with libfuzzer" OFF)
option(FUZZING_MSAN "Compile binaries with MemorySanitizer instrumentation" OFF)

if (FUZZING)
    message(STATUS "Building with fuzzing instrumentation.")

    string (APPEND CMAKE_C_FLAGS " -DFUZZING")
    string (APPEND CMAKE_C_FLAGS " -fno-omit-frame-pointer -O1 -g")

    string (APPEND CMAKE_CXX_FLAGS " -std=c++17")
    string (APPEND CMAKE_CXX_FLAGS " -DFUZZING")
    string (APPEND CMAKE_CXX_FLAGS " -fno-omit-frame-pointer -O1 -g")

    string (APPEND CMAKE_EXE_LINKER_FLAGS " -g")

    if (FUZZING_MSAN)
        string (APPEND CMAKE_C_FLAGS " -fsanitize=memory")
        string (APPEND CMAKE_CXX_FLAGS " -fsanitize=memory")
        string (APPEND CMAKE_EXE_LINKER_FLAGS " -fsanitize=memory")
    else (FUZZING_MSAN)
        string (APPEND CMAKE_C_FLAGS " -fsanitize=address -fsanitize=undefined")
        string (APPEND CMAKE_CXX_FLAGS " -fsanitize=address -fsanitize=undefined")
        string (APPEND CMAKE_EXE_LINKER_FLAGS " -fsanitize=address -fsanitize=undefined")
    endif (FUZZING_MSAN)

endif ()
