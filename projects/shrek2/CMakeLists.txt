# =============================================================================
# Shrek 2 (PC, 2004) -- the recompiled application body
#
#   cmake -S projects/shrek2 -B build -G "Visual Studio 17 2022" -A Win32
#   cmake --build build --config Release
#
# The generated C is not committed (it is derived from the game); produce it
# first with the driver, or let the `lift` target do it:
#
#   set SHREK2_GAME=C:\Games\Shrek 2\System\game.exe
#   cmake --build build --config Release --target lift
#
# Why x86 only: the guest is a 32-bit program, the engine DLLs it calls are
# 32-bit, and native32's bridge and callback trampoline are MSVC x86 inline
# asm.  A 64-bit build cannot load the engine, so it is rejected here rather
# than at 4 GB of memory access.
# =============================================================================

cmake_minimum_required(VERSION 3.20)
project(shrek2_recomp LANGUAGES C)

if(NOT MSVC)
    message(FATAL_ERROR
        "This project is MSVC-only: runtime/native32 bridges to the real 32-bit "
        "Windows API with inline asm. Build with Visual Studio 2017+ (x86).")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR
        "Configure for x86:  cmake -S . -B build -A Win32   (the engine DLLs and "
        "the guest image are 32-bit).")
endif()

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(LIFT_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/src/game/recomp/gen")
set(RUNTIME   "${REPO_ROOT}/runtime")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# The generated lift
# -----------------------------------------------------------------------------
file(GLOB LIFT_SOURCES CONFIGURE_DEPENDS "${LIFT_DIR}/recomp_[0-9][0-9][0-9][0-9].c")
list(APPEND LIFT_SOURCES "${LIFT_DIR}/recomp_dispatch.c")
if(NOT EXISTS "${LIFT_DIR}/recomp_dispatch.c")
    message(FATAL_ERROR
        "No generated code in ${LIFT_DIR}.\n"
        "Generate it first:\n"
        "  python3 projects/shrek2/tools/build_lift.py --game <install>/System/game.exe")
endif()
list(LENGTH LIFT_SOURCES LIFT_COUNT)
message(STATUS "lift: ${LIFT_COUNT} generated source files")

# -----------------------------------------------------------------------------
# Executable
# -----------------------------------------------------------------------------
add_executable(shrek2 WIN32
    src/main.c
    ${RUNTIME}/native32/native32.c   # includes eh32.c and x87crt.c itself
    ${RUNTIME}/recomp32/image_loader.c
    ${RUNTIME}/recomp32/recomp_trace.c
    ${LIFT_SOURCES}
)

target_include_directories(shrek2 PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${LIFT_DIR}"
    "${RUNTIME}/native32"
    "${RUNTIME}/recomp32"
)

target_compile_definitions(shrek2 PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(shrek2 PRIVATE
    kernel32 user32 gdi32 advapi32 shell32 ole32 oleaut32 winmm version comdlg32
)

# -----------------------------------------------------------------------------
# Link and code-generation settings
#
# /DYNAMICBASE:NO + a fixed low base: the host must never be placed anywhere
# near the guest image at 0x10900000.
#
# /STACK:262144: native32_hold_image reserves the guest range in a suspended
# child before its loader runs; a small first stack keeps that reservation
# clear even when the game picks a low image base.  The lifted code itself runs
# on a 64 MB thread (main.c), which is where depth actually happens.
# -----------------------------------------------------------------------------
if(MSVC)
    add_link_options(/DYNAMICBASE:NO /FIXED /STACK:262144)
    add_compile_options(/MP /bigobj /W1)
    # Generated code trips these by construction; none of them is a bug.
    add_compile_options(/wd4018 /wd4101 /wd4102 /wd4146 /wd4244 /wd4267 /wd4996)
    add_compile_options(/wd4305 /wd4311 /wd4312 /wd4005 /wd4028 /wd4047)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /Oi /Gy")
    set(CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG} /Od /Zi")
endif()

set_target_properties(shrek2 PROPERTIES
    OUTPUT_NAME "shrek2"
    PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# -----------------------------------------------------------------------------
# Regenerate the lift from the original binary (optional)
#
#   cmake -S projects/shrek2 -B build -A Win32 -DSHREK2_GAME="C:\...\game.exe"
#   cmake --build build --target lift
# (or set the SHREK2_GAME environment variable before configuring)
# -----------------------------------------------------------------------------
set(SHREK2_GAME "$ENV{SHREK2_GAME}" CACHE FILEPATH
    "the original System/game.exe the lift is generated from")
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_custom_target(lift
        COMMAND ${Python3_EXECUTABLE}
                "${CMAKE_CURRENT_SOURCE_DIR}/tools/build_lift.py"
                --game "${SHREK2_GAME}"
                --out  "${LIFT_DIR}"
                --analysis "${CMAKE_CURRENT_SOURCE_DIR}/analysis"
        WORKING_DIRECTORY "${REPO_ROOT}"
        COMMENT "Lifting ${SHREK2_GAME}"
        VERBATIM)
endif()

message(STATUS "shrek2: hybrid lift, engine DLLs stay native (Core/Engine/KWGame)")
