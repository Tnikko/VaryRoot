#include "model.h"

VR_EXPORT int model_n03(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    if (!p) note();
    return request_pointer(p);
}

VR_EXPORT int model_n04(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    if (!p) { note(); return BLOCKED; }
    return request_pointer(p);
}

VR_EXPORT int model_n07(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    if (!p && x.mode) return BLOCKED;
    return request_pointer(p);
}

VR_EXPORT int model_n08(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    if (!p) return BLOCKED;
    return request_pointer(p);
}

VR_EXPORT int model_n11(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    unsigned char peer_storage = 0;
    const unsigned char *other = x.peer_live ? &peer_storage : 0;
    (void)other;
    const unsigned char *alias = p;
    if (!alias) return BLOCKED;
    return request_pointer(alias);
}

VR_EXPORT int model_n12(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    unsigned char peer_storage = 0;
    const unsigned char *other = x.peer_live ? &peer_storage : 0;
    (void)other;
    const unsigned char *alias = p;
    if (!other) return BLOCKED;
    return request_pointer(alias);
}
