/* ne_resources.h - runtime loader for the original NE binaries' STRINGTABLE and
 * resource directory (CATZDLL.DLL, CATZ.WAD, CATZREZX.DLL). Lets the Win16 shims
 * serve LoadString / FindResource / LoadResource from the real game data, which
 * the engine needs to get past its "CATZREZX.DLL did not load" startup throw. */
#ifndef NE_RESOURCES_H
#define NE_RESOURCES_H
#include <stdint.h>

/* Lazily loads+parses CATZDLL.DLL@hinst59 and CATZ.WAD@hinst66 on first use. */
void ne_init(void);

/* LoadLibrary(name): if `name` (any path/case, with/without .DLL) is a game NE we
 * can serve resources from, parse it and return its assigned hInstance handle;
 * otherwise return 0 (caller substitutes a benign handle). */
uint16_t ne_loadlib(const char *name);

/* LoadString(hinst,id): copy the string into out (<=max, NUL-terminated).
 * Returns length copied, or 0 if not found. */
int ne_load_string(uint16_t hinst, uint16_t id, char *out, int max);

/* FindResource(hinst,name,type): type/name are int IDs if *_int>=0, else the
 * asciiz string (*_str). Returns an opaque non-zero HRSRC, or 0 if not found. */
uint16_t ne_find_resource(uint16_t hinst, int type_int, const char *type_str,
                          int name_int, const char *name_str);

/* Host pointer + length of a resource previously returned by ne_find_resource. */
const uint8_t *ne_resource_bytes(uint16_t hrsrc, uint32_t *out_len);

#endif
