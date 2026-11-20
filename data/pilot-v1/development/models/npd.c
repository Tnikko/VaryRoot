#include "model.h"

VR_EXPORT int model_n01(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    return request_pointer(p);
}

VR_EXPORT int model_n02(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    if (!p) return BLOCKED;
    return request_pointer(p);
}

VR_EXPORT int model_n05(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    unsigned char peer_storage = 0;
    const unsigned char *other = x.peer_live ? &peer_storage : 0;
    (void)other;
    if (!other) return BLOCKED;
    return request_pointer(p);
}

VR_EXPORT int model_n06(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    unsigned char peer_storage = 0;
    const unsigned char *other = x.peer_live ? &peer_storage : 0;
    (void)other;
    if (!p) return BLOCKED;
    return request_pointer(p);
}

VR_EXPORT int model_n09(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    if (!p) return BLOCKED;
    return request_pointer(p);
}

VR_EXPORT int model_n10(Input x, Target *target)
{
    unsigned char target_storage = 0;
    const unsigned char *p = x.target_live ? &target_storage : 0;
    if (!p) goto done;
    return request_pointer(p);
done:
    return BLOCKED;
}
