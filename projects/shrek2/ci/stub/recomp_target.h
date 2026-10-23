/* A stub catalog, so the host, the runtime and the MSVC toolchain can be built
 * and smoked without the game binary.
 *
 * This is our own code, not lifted output: the repo's audit policy forbids
 * committing anything derived from the game, and the real lift needs
 * System/game.exe.  Configure with -DSHREK2_SYNTHETIC=ON to use it; the
 * resulting executable answers SHREK2_HELP and the "no game here" diagnostic
 * exactly like the real one, then calls one function that returns.
 */
#pragma once

#define RECOMP_IMAGE_BASE     0x10900000u
#define RECOMP_ENTRY_VA       0x1091AACBu
#define RECOMP_FUNCTION_COUNT 1u
#define RECOMP_SOURCE_SHA256  "stub (no lift: built with SHREK2_SYNTHETIC=ON)"
