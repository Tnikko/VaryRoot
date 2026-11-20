#define DECODE_OK 7
struct Record { int payload; };
extern int decode_records(int channel, int mode, struct Record **out);

int unequal_check(int channel) {
  int status;
  struct Record *items;
  for (status = decode_records(channel, 0, &items);
       status == DECODE_OK;
       status = decode_records(channel, 0, &items)) {
    int i = 0;
    if (items != 0) ;
    return items[i].payload; /* target_unequal */
  }
  return 0;
}

int negated_check(int channel) {
  int status;
  struct Record *items;
  for (status = decode_records(channel, 0, &items);
       status == DECODE_OK;
       status = decode_records(channel, 0, &items)) {
    int i = 0;
    if (!items) ;
    return items[i].payload; /* target_negated */
  }
  return 0;
}

int negated_break(int channel) {
  int status;
  struct Record *items;
  for (status = decode_records(channel, 0, &items);
       status == DECODE_OK;
       status = decode_records(channel, 0, &items)) {
    int i = 0;
    if (!items) break;
    return items[i].payload; /* target_break */
  }
  return 0;
}

int loop_false_branch(int channel) {
  int status;
  struct Record *items;
  for (status = decode_records(channel, 0, &items);
       status == DECODE_OK;
       status = decode_records(channel, 0, &items)) {
    int i;
    for (i = 0; i < 1 && items; ++i) ;
    return items[i].payload; /* target_false_branch */
  }
  return 0;
}

int access_before_guard(int channel) {
  int status;
  struct Record *items;
  for (status = decode_records(channel, 0, &items);
       status == DECODE_OK;
       status = decode_records(channel, 0, &items)) {
    int i;
    for (i = 0; items[i].payload != 0 && items; ++i) ; /* target_before_guard */
  }
  return 0;
}
