// 位置由原始 UTF-8 字节确定。
#define PAIR(x) ((x) + (x))
static inline unsigned read0(const volatile unsigned (&buf)[4]) { return buf[0]; }

unsigned accesses(unsigned (&buf)[4]) {
    unsigned same = buf[0] + buf[1];
    unsigned twice = PAIR(buf[2]);
    buf[3] = same;
    buf[1] += twice;
    return read0(buf) + read0(buf) + same + twice;
}
