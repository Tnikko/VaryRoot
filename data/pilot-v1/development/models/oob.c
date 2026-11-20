#include "model.h"

VR_EXPORT int model_o01(Input x, Target *target)
{
    return request_span(target, x.offset, x.width);
}

VR_EXPORT int model_o02(Input x, Target *target)
{
    if (x.offset < 0 || x.offset > x.capacity - x.width) return BLOCKED;
    return request_span(target, x.offset, x.width);
}

VR_EXPORT int model_o05(Input x, Target *target)
{
    if (x.offset < 0 || x.offset > x.peer_capacity - x.width) return BLOCKED;
    return request_span(target, x.offset, x.width);
}

VR_EXPORT int model_o06(Input x, Target *target)
{
    if (x.offset < 0 || x.offset > x.capacity - x.width) return BLOCKED;
    return request_span(target, x.offset, x.width);
}

VR_EXPORT int model_o09(Input x, Target *target)
{
    if (x.offset < 0 || x.offset > x.capacity - x.width) return BLOCKED;
    return request_span(target, x.offset, x.width);
}

VR_EXPORT int model_o10(Input x, Target *target)
{
    if (x.offset < 0 || x.offset > x.capacity - x.width) goto done;
    return request_span(target, x.offset, x.width);
done:
    return BLOCKED;
}
