/* See recomp_target.h: the one-function stand-in catalog.
 *
 * The locals are the ones every lifted body declares (lift32.FUNCTION_LOCALS);
 * the runtime's RECOMP_ENTER / RECOMP_FLAGS_OUT write them, so they must exist
 * even in a body this small. */
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"

void sub_1091AACB(void)
{
    uint32_t _flag_a = 0, _flag_b = 0;
    uint32_t _cf = 0;
    uint32_t _flag_k = FK_NONE;

    RECOMP_ENTER(0x1091AACBu);
    /* The real entry is the CRT startup; this one returns, which the host
     * reports as "[host] WinMain returned" and exits 0 with. */
    RECOMP_FLAGS_OUT();
    esp += 4;
}
