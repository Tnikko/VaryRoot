#define DECODE_OK 7
struct Record { int payload; };
extern int decode_records(int channel, int mode, struct Record **out);

int sample(int channel) {
  int status;
  struct Record *items;
  for (status = decode_records(channel, 0, &items);
       status == DECODE_OK;
       status = decode_records(channel, 0, &items)) {
    int i;
    if (items == 0) break;
    for (i = 0; items[i].payload != 0; ++i) {
    }
  }
  return 0;
}
