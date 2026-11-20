#ifndef VARYROOT_MODEL_H
#define VARYROOT_MODEL_H
#ifdef __cplusplus
#define VR_EXPORT extern "C"
#else
#define VR_EXPORT
#endif

typedef struct {
    int target_live, peer_live, mode;
    int capacity, peer_capacity, offset, width;
} Input;

typedef struct { int offset; } Target;
enum { BLOCKED = -1 };
static inline void note(void) {}
static inline int request_pointer(const unsigned char *p) { return p != 0; }
static inline int request_span(Target *target, int offset, int width) { target->offset = offset; return width; }
#endif
