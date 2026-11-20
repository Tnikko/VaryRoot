#include <stddef.h>
#include <string.h>

struct Frame {
  unsigned char *body;
  size_t body_bytes;
  size_t wire_bytes;
};

void scan_parent(struct Frame *frame, unsigned char *out) {
  unsigned char *cursor = frame->body;
  unsigned char *limit = cursor + frame->body_bytes;
  if (frame->wire_bytes >= 8) {
    cursor += 2;
    if (cursor < limit) {
      memcpy(out, cursor, 8);
    }
  }
}

void scan_fixed(struct Frame *frame, unsigned char *out) {
  unsigned char *cursor = frame->body;
  unsigned char *limit = cursor + frame->body_bytes;
  cursor += 2;
  if (limit - cursor >= 8) {
    memcpy(out, cursor, 8);
  }
}

void scan_wrong_object(struct Frame *frame, struct Frame *other,
                       unsigned char *out) {
  unsigned char *cursor = frame->body;
  unsigned char *limit = cursor + frame->body_bytes;
  if (other->wire_bytes >= 8) {
    cursor += 2;
    if (cursor < limit) {
      memcpy(out, cursor, 8);
    }
  }
}

void scan_no_target(struct Frame *frame, unsigned char *out) {
  (void)frame;
  (void)out;
}
