#include "model.h"

VR_EXPORT int model_o03(Input x, Target *target)
{
    if (x.offset < 0 || x.offset >= x.capacity) return BLOCKED;
    return request_span(target, x.offset, 1);
}

VR_EXPORT int model_o04(Input x, Target *target)
{
    if (x.offset < 0 || x.offset >= x.capacity) return BLOCKED;
    return request_span(target, x.offset, 2);
}

VR_EXPORT int model_o07(Input x, Target *target)
{
    if (x.offset < 0 || (x.mode && x.offset > x.capacity - x.width)) return BLOCKED;
    return request_span(target, x.offset, x.width);
}

VR_EXPORT int model_o08(Input x, Target *target)
{
    if (x.offset < 0 || x.offset > x.capacity - x.width) return BLOCKED;
    return request_span(target, x.offset, x.width);
}

VR_EXPORT int model_o11(Input x, Target *target)
{
    int bytes = 2 * x.offset;
    if (bytes < 0 || bytes > x.capacity - x.width) return BLOCKED;
    return request_span(target, bytes, x.width);
}

VR_EXPORT int model_o12(Input x, Target *target)
{
    int bytes = 2 * x.offset;
    if (bytes < 0 || x.offset > x.capacity - x.width) return BLOCKED;
    return request_span(target, bytes, x.width);
}
