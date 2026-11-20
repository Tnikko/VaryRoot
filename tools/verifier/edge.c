/* All side effects are sequenced by the comma operator in the reference expression. */
#ifdef __cplusplus
extern "C" {
#endif
typedef int (*permit)(long long, unsigned, unsigned, int);
static int sequence, reads;
int checked_add(int a, int b, int *result) {
    if ((b > 0 && a > __INT_MAX__ - b) || (b < 0 && a < (-__INT_MAX__ - 1) - b)) return 0;
    *result = a + b;
    return 1;
}
static int tick(int event) { sequence = 10 * sequence + event; return event; }
static long long offset(long long raw, int narrow) { return narrow ? (unsigned char)raw : raw; }
#define INDEX (tick(1), tick(2), offset(raw,narrow))
#define RUN(N, TAG) \
int edge##TAG(long long raw, unsigned width, int narrow, permit check, int *out) { \
    unsigned char data[N] = {0}; int value = 0; sequence = 0; reads = 0; \
    for (unsigned k=0;k<N;++k) data[k]=(unsigned char)(k+3); \
    if (check) { \
        long long i = INDEX; \
        if (check(i, width, sizeof data, 1) && i >= 0 && i < N && width && width <= N - (unsigned)i) { \
            for (unsigned j = 0; j < width; ++j) value += data[i+j]; \
            ++reads; \
        } \
    } else { \
        /* Reference entry is used exclusively on independently checked, positive-width intervals. */ \
        long long i = offset(raw,narrow); \
        if (i >= 0 && i < N && width && width <= N - (unsigned)i) { \
            value = data[INDEX]; \
            for (unsigned j = 1; j < width; ++j) value += data[i+j]; \
            ++reads; \
        } \
    } \
    out[0] = sequence; out[1] = reads; return value; \
}
RUN(8,8)
RUN(255,255)
#ifdef __cplusplus
}
#endif
