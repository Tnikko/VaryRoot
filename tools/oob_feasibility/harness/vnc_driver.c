#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <stdarg.h>
#include <stdint.h>

/* Link the unmodified original ec_vnc.c translation unit against minimal
 * environment stubs. All packet bytes and allocation extents are explicit. */
struct vnc_status_for_harness {
   u_char status;
   u_char challenge[16];
   u_char response[16];
   u_char banner[16];
};

extern void *dissector_vnc(u_char *, u_int16, int *, struct packet_object *);
extern int __asan_address_is_poisoned(void const volatile *addr);
static struct packet_object packet;
static struct ec_session session;
static struct vnc_status_for_harness state;
static struct ec_globals globals;
static struct ec_options options;
struct ec_globals *ec_gbls = &globals;
FILE *debug_file = NULL;

void debug_msg(const char *fmt, ...) { (void)fmt; }
void error_msg(char *file, const char *function, int line, char *message, ...) {
   fprintf(stderr, "unrelated_error:%s:%s:%d:%s\n", file, function, line, message);
   abort();
}
void ui_msg(const char *fmt, ...) { (void)fmt; }
char *ip_addr_ntoa(struct ip_addr *sa, char *dst) {
   (void)sa;
   strcpy(dst, "127.0.0.1");
   return dst;
}
void dissect_add(char *name, u_int8 level, u_int32 port, FUNC_DECODER_PTR(decoder)) {
   (void)name; (void)level; (void)port; (void)decoder;
}
int dissect_on_port(char *name, u_int16 port) {
   (void)name; (void)port;
   return E_SUCCESS;
}
size_t dissect_create_ident(void **ident, struct packet_object *po, void *code) {
   (void)po; (void)code;
   *ident = calloc(1, sizeof(struct dissect_ident));
   if (!*ident) abort();
   return sizeof(struct dissect_ident);
}
int session_get(struct ec_session **out, void *ident, size_t ident_len) {
   (void)ident; (void)ident_len;
   *out = &session;
   return E_SUCCESS;
}
void session_put(struct ec_session *s) { (void)s; }
void dissect_create_session(struct ec_session **s, struct packet_object *po, void *code) {
   (void)po; (void)code;
   *s = &session;
}
void dissect_wipe_session(struct packet_object *po, void *code) {
   (void)po; (void)code;
}

void *__real_memcpy(void *dest, const void *src, size_t n);
void *__wrap_memcpy(void *dest, const void *src, size_t n) {
   uintptr_t p = (uintptr_t)src;
   uintptr_t b = (uintptr_t)packet.DATA.disp_data;
   if (packet.DATA.disp_data && p >= b && p <= b + packet.DATA.disp_len + 1
       && n == 16 && dest != state.challenge && dest != state.response) {
      size_t off = p - b;
      printf("TARGET_MEMCPY base=%p ptr=%p end=%p offset=%zu width=%zu logical=%zu physical=%zu\n",
             (void *)b, src, (void *)(b + packet.DATA.disp_len),
             off, n, packet.DATA.disp_len, packet.DATA.disp_len + 1);
      fflush(stdout);
   }
   return __real_memcpy(dest, src, n);
}

int main(int argc, char **argv) {
   if (argc != 4) {
      fprintf(stderr, "usage: %s L WAIT_AUTH|WAIT_CHALLENGE auth1|auth2\n", argv[0]);
      return 64;
   }
   char *endptr = NULL;
   unsigned long l = strtoul(argv[1], &endptr, 10);
   if (*endptr || l > 4096) return 64;
   int start = strcmp(argv[2], "WAIT_AUTH") == 0 ? 1 :
               strcmp(argv[2], "WAIT_CHALLENGE") == 0 ? 2 : -1;
   int auth = strcmp(argv[3], "auth1") == 0 ? 1 :
              strcmp(argv[3], "auth2") == 0 ? 2 : -1;
   if (start < 0 || auth < 0) return 64;

   globals.options = &options;
   options.superquiet = 1;
   state.status = (u_char)start;
   strcpy((char *)state.banner, "RFB 003.007");
   session.data = &state;
   u_char *input = calloc(l + 1, 1);
   packet.DATA.data = calloc(l + 1, 1);
   if (!input || !packet.DATA.data) abort();
   packet.DATA.len = l;
   memset(input, 'A', l);
   memset(packet.DATA.data, 'A', l);
   if (l >= 4) {
      input[0] = 0;
      input[1] = 0;
      input[2] = 0;
      input[3] = (u_char)auth;
   }
   if (l >= 12) memcpy(input + 4, "VNCAUTH_", 8);
   if (packet_disp_data(&packet, input, l) != (int)l) abort();
   free(input);
   if (packet.DATA.disp_len != l ||
       __asan_address_is_poisoned(packet.DATA.disp_data + l) ||
       !__asan_address_is_poisoned(packet.DATA.disp_data + l + 1)) abort();
   printf("SOURCE_CAPACITY base=%p end=%p L=%lu C=%lu\n",
          (void *)packet.DATA.disp_data,
          (void *)(packet.DATA.disp_data + l), l, l + 1);
   u_char decoder_buf[17] = {0};
   int decoded_len = 0;
   printf("CASE L=%lu start=%s auth=%d C=%lu\n", l, argv[2], auth, l + 1);
   fflush(stdout);
   (void)dissector_vnc(decoder_buf, sizeof(decoder_buf), &decoded_len, &packet);
   printf("RETURN status=%u\n", state.status);
   fflush(stdout);
   free(packet.DATA.disp_data);
   free(packet.DATA.data);
   return 0;
}
