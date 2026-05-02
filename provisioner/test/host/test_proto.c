// Host-side unit tests for the prov_cop protocol parser.
//
// Builds against provisioner/src/provisioner_proto.[ch] plus a tiny
// mbedtls/base64 stub. Has no ESP-IDF or FreeRTOS dependency.

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/base64.h"
#include "provisioner_proto.h"

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

typedef struct
{
    char*  buf;
    size_t len;
    size_t cap;
} buffer_t;

static void buf_append(buffer_t* b, const char* data, size_t n)
{
    if (b->len + n + 1 > b->cap)
    {
        b->cap = (b->len + n + 1) * 2;
        b->buf = (char*)realloc(b->buf, b->cap);
        assert(b->buf);
    }
    memcpy(b->buf + b->len, data, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

static void buf_reset(buffer_t* b) { b->len = 0; if (b->buf) b->buf[0] = '\0'; }

typedef struct
{
    buffer_t write_log;
    buffer_t forward_log;
    int      callback_calls;
    bool     callback_result;
    char     last_ssid[64];
    char     last_pass[80];
    char*    forced_err;
} ctx_t;

static void cb_write(void* io, const char* data, size_t n)
{
    buf_append(&((ctx_t*)io)->write_log, data, n);
}
static void cb_forward(void* io, const char* data, size_t n)
{
    buf_append(&((ctx_t*)io)->forward_log, data, n);
}

static uint32_t g_now_ms;
static uint32_t cb_now(void) { return g_now_ms; }

static bool cb_creds(const char* ssid,
                     const char* password,
                     char*       err_out,
                     size_t      err_out_len,
                     void*       user_ctx)
{
    ctx_t* c = (ctx_t*)user_ctx;
    c->callback_calls++;
    snprintf(c->last_ssid, sizeof c->last_ssid, "%s", ssid);
    snprintf(c->last_pass, sizeof c->last_pass, "%s", password);
    if (!c->callback_result && c->forced_err)
    {
        snprintf(err_out, err_out_len, "%s", c->forced_err);
    }
    return c->callback_result;
}

static void feed_str(prov_proto_t* p, const char* s)
{
    prov_proto_feed(p, (const uint8_t*)s, strlen(s));
}

static char* b64(const char* in)
{
    static char out[256];
    size_t      olen = 0;
    int rc = mbedtls_base64_encode((unsigned char*)out,
                                   sizeof out,
                                   &olen,
                                   (const unsigned char*)in,
                                   strlen(in));
    assert(rc == 0);
    out[olen] = '\0';
    return out;
}

static char* mkset(const char* ssid, const char* pass)
{
    // Use the parser's own CRC so we test the same code path.
    static char       line[512];
    static char       inner[400];
    char              ssid_b64[200];
    char              pass_b64[200];
    snprintf(ssid_b64, sizeof ssid_b64, "%s", b64(ssid));
    snprintf(pass_b64, sizeof pass_b64, "%s", b64(pass));
    snprintf(inner, sizeof inner, "%s %s", ssid_b64, pass_b64);
    uint16_t crc = prov_proto_crc16(inner, strlen(inner));
    snprintf(line, sizeof line, "<<PROV:SET %s %s %04X>>\n", ssid_b64, pass_b64, crc);
    return line;
}

static int g_failures;

#define CHECK(cond)                                                                                \
    do                                                                                             \
    {                                                                                              \
        if (!(cond))                                                                               \
        {                                                                                          \
            fprintf(stderr,                                                                        \
                    "  FAIL %s:%d: %s\n",                                                          \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    #cond);                                                                        \
            g_failures++;                                                                          \
        }                                                                                          \
    } while (0)

#define CHECK_STR_CONTAINS(haystack, needle)                                                       \
    do                                                                                             \
    {                                                                                              \
        const char* __h = (haystack);                                                              \
        const char* __n = (needle);                                                                \
        if (!__h || !strstr(__h, __n))                                                             \
        {                                                                                          \
            fprintf(stderr,                                                                        \
                    "  FAIL %s:%d: expected %s to contain %s; got: %s\n",                          \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    #haystack,                                                                     \
                    __n,                                                                           \
                    __h ? __h : "(null)");                                                         \
            g_failures++;                                                                          \
        }                                                                                          \
    } while (0)

#define CHECK_STR_NOT_CONTAINS(haystack, needle)                                                   \
    do                                                                                             \
    {                                                                                              \
        const char* __h = (haystack);                                                              \
        const char* __n = (needle);                                                                \
        if (__h && strstr(__h, __n))                                                               \
        {                                                                                          \
            fprintf(stderr,                                                                        \
                    "  FAIL %s:%d: expected %s to NOT contain %s; got: %s\n",                      \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    #haystack,                                                                     \
                    __n,                                                                           \
                    __h);                                                                          \
            g_failures++;                                                                          \
        }                                                                                          \
    } while (0)

static void mk_proto(prov_proto_t* p, ctx_t* c, prov_proto_config_t cfg_overrides)
{
    memset(c, 0, sizeof *c);
    c->callback_result = true;

    prov_proto_config_t cfg = cfg_overrides;
    cfg.write              = cb_write;
    cfg.forward            = cb_forward;
    cfg.io_ctx             = c;
    cfg.on_credentials     = cb_creds;
    cfg.user_ctx           = c;
    if (!cfg.now_ms)
    {
        cfg.now_ms = cb_now;
    }
    prov_proto_init(p, &cfg);
}

static void free_ctx(ctx_t* c)
{
    free(c->write_log.buf);
    free(c->forward_log.buf);
    memset(c, 0, sizeof *c);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_crc_known_vector(void)
{
    // CRC-16/CCITT-FALSE("123456789") = 0x29B1, classic test vector.
    CHECK(prov_proto_crc16("123456789", 9) == 0x29B1);
}

static void test_probe_basic(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    feed_str(&p, "<<PROV?>>\n");
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV!>>\n");
    CHECK_STR_NOT_CONTAINS(c.write_log.buf, "<<PROV:ID");
    free_ctx(&c);
}

static void test_probe_with_device_name(void)
{
    prov_proto_t p;
    ctx_t        c;
    prov_proto_config_t cfg = {.device_name = "Kitchen Caller ID"};
    mk_proto(&p, &c, cfg);

    feed_str(&p, "<<PROV?>>\n");
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV!>>\n");
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:ID ");
    // The encoded name should be after the "ID " token.
    CHECK_STR_CONTAINS(c.write_log.buf, b64("Kitchen Caller ID"));
    free_ctx(&c);
}

static void test_probe_rate_limit(void)
{
    prov_proto_t p;
    ctx_t        c;
    g_now_ms = 1000;
    prov_proto_config_t cfg = {.min_probe_interval_ms = 200};
    mk_proto(&p, &c, cfg);

    feed_str(&p, "<<PROV?>>\n");
    int first_responses = 0;
    for (const char* s = c.write_log.buf; (s = strstr(s, "<<PROV!>>")) != NULL; s++)
    {
        first_responses++;
    }
    CHECK(first_responses == 1);

    // Second probe within window: should be dropped.
    g_now_ms = 1100;
    feed_str(&p, "<<PROV?>>\n");
    int second_responses = 0;
    for (const char* s = c.write_log.buf; (s = strstr(s, "<<PROV!>>")) != NULL; s++)
    {
        second_responses++;
    }
    CHECK(second_responses == 1);

    // After the window: should respond again.
    g_now_ms = 1500;
    feed_str(&p, "<<PROV?>>\n");
    int third_responses = 0;
    for (const char* s = c.write_log.buf; (s = strstr(s, "<<PROV!>>")) != NULL; s++)
    {
        third_responses++;
    }
    CHECK(third_responses == 2);
    free_ctx(&c);
}

static void test_set_happy_path(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    feed_str(&p, mkset("HomeWifi", "supersecret"));
    CHECK(c.callback_calls == 1);
    CHECK(strcmp(c.last_ssid, "HomeWifi") == 0);
    CHECK(strcmp(c.last_pass, "supersecret") == 0);
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:OK>>\n");
    free_ctx(&c);
}

static void test_set_open_network(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    feed_str(&p, mkset("OpenNet", ""));
    CHECK(c.callback_calls == 1);
    CHECK(strcmp(c.last_pass, "") == 0);
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:OK>>\n");
    free_ctx(&c);
}

static void test_set_bad_crc(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    // Build a valid line, then mutate the CRC.
    char line[512];
    snprintf(line, sizeof line, "%s", mkset("HomeWifi", "x"));
    // Find the last space (before crc) and corrupt the next char.
    char* last_space = strrchr(line, ' ');
    assert(last_space);
    last_space[1] = (last_space[1] == '0') ? '1' : '0';
    feed_str(&p, line);
    CHECK(c.callback_calls == 0);
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:ERR crc>>");
    free_ctx(&c);
}

static void test_set_too_long_ssid(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    char ssid[40];
    memset(ssid, 'A', sizeof ssid);
    ssid[33] = '\0'; // 33 bytes, one over the limit
    feed_str(&p, mkset(ssid, "x"));
    CHECK(c.callback_calls == 0);
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:ERR ssid_too_long>>");
    free_ctx(&c);
}

static void test_set_too_long_pass(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    char pass[80];
    memset(pass, 'p', sizeof pass);
    pass[64] = '\0'; // 64 bytes, one over the limit
    feed_str(&p, mkset("ok", pass));
    CHECK(c.callback_calls == 0);
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:ERR pass_too_long>>");
    free_ctx(&c);
}

static void test_set_empty_ssid(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    feed_str(&p, mkset("", "p"));
    CHECK(c.callback_calls == 0);
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:ERR ssid_empty>>");
    free_ctx(&c);
}

static void test_set_bad_b64_password(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    // Hand-build a malformed line: invalid base64 in the password slot but
    // matching CRC over the textual fields.
    char inner[64];
    snprintf(inner, sizeof inner, "%s !!notb64!!", b64("ok"));
    uint16_t crc = prov_proto_crc16(inner, strlen(inner));
    char     line[128];
    snprintf(line, sizeof line, "<<PROV:SET %s %04X>>\n", inner, crc);
    feed_str(&p, line);
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:ERR b64pass>>");
    free_ctx(&c);
}

static void test_set_field_count(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    feed_str(&p, "<<PROV:SET only_one_field>>\n");
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:ERR fields>>");
    free_ctx(&c);
}

static void test_callback_failure_reason(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});
    c.callback_result = false;
    c.forced_err      = "auth";

    feed_str(&p, mkset("HomeWifi", "x"));
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV:ERR auth>>");
    free_ctx(&c);
}

static void test_overflow_recovery(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    // Send a giant line that exceeds the buffer, then a valid frame.
    char giant[PROV_PROTO_LINE_MAX * 2];
    memset(giant, 'x', sizeof giant);
    giant[sizeof giant - 1] = '\n';
    prov_proto_feed(&p, (const uint8_t*)giant, sizeof giant);

    // Now a valid probe.
    feed_str(&p, "<<PROV?>>\n");
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV!>>\n");
    free_ctx(&c);
}

static void test_share_replays_unknown_frames(void)
{
    prov_proto_t p;
    ctx_t        c;
    prov_proto_config_t cfg = {.share_with_console = true};
    mk_proto(&p, &c, cfg);

    // Random console output: should be forwarded verbatim, not consumed.
    feed_str(&p, "hello world\n");
    CHECK(strcmp(c.forward_log.buf, "hello world\n") == 0);

    // A frame that *is not ours* (starts with << but not <<PROV...).
    feed_str(&p, "<<OTHER:thing>>\n");
    CHECK_STR_CONTAINS(c.forward_log.buf, "<<OTHER:thing>>\n");

    // A real probe: consumed (no forward), reply emitted.
    buf_reset(&c.forward_log);
    feed_str(&p, "<<PROV?>>\n");
    CHECK(c.forward_log.len == 0);
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV!>>\n");
    free_ctx(&c);
}

static void test_share_passthrough_byte(void)
{
    prov_proto_t p;
    ctx_t        c;
    prov_proto_config_t cfg = {.share_with_console = true};
    mk_proto(&p, &c, cfg);

    feed_str(&p, "abc");
    CHECK(strcmp(c.forward_log.buf, "abc") == 0);
    feed_str(&p, "\n<<PROV?>>\n");
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV!>>\n");
    free_ctx(&c);
}

static void test_share_crlf_frame(void)
{
    prov_proto_t p;
    ctx_t        c;
    prov_proto_config_t cfg = {.share_with_console = true};
    mk_proto(&p, &c, cfg);

    feed_str(&p, "<<PROV?>>\r\n");
    CHECK_STR_CONTAINS(c.write_log.buf, "<<PROV!>>\n");
    CHECK(c.forward_log.len == 0);
    free_ctx(&c);
}

// Verify that the long-lived line buffer is wiped after dispatch so an
// encoded password doesn't sit in RAM indefinitely.
static void test_line_buffer_scrubbed(void)
{
    prov_proto_t p;
    ctx_t        c;
    mk_proto(&p, &c, (prov_proto_config_t){0});

    feed_str(&p, mkset("HomeWifi", "secret_marker_xyz"));
    char* pass_b64_marker = b64("secret_marker_xyz");
    // The encoded password should NOT be sitting in p.line after dispatch.
    bool found = false;
    for (size_t i = 0; i + strlen(pass_b64_marker) <= sizeof p.line; i++)
    {
        if (memcmp(p.line + i, pass_b64_marker, strlen(pass_b64_marker)) == 0)
        {
            found = true;
            break;
        }
    }
    CHECK(!found);
    free_ctx(&c);
}

// ---------------------------------------------------------------------------

#define RUN(t)                                                                                     \
    do                                                                                             \
    {                                                                                              \
        printf("- %s\n", #t);                                                                      \
        int before = g_failures;                                                                   \
        t();                                                                                       \
        if (g_failures == before)                                                                  \
        {                                                                                          \
            printf("  ok\n");                                                                      \
        }                                                                                          \
    } while (0)

int main(void)
{
    RUN(test_crc_known_vector);
    RUN(test_probe_basic);
    RUN(test_probe_with_device_name);
    RUN(test_probe_rate_limit);
    RUN(test_set_happy_path);
    RUN(test_set_open_network);
    RUN(test_set_bad_crc);
    RUN(test_set_too_long_ssid);
    RUN(test_set_too_long_pass);
    RUN(test_set_empty_ssid);
    RUN(test_set_bad_b64_password);
    RUN(test_set_field_count);
    RUN(test_callback_failure_reason);
    RUN(test_overflow_recovery);
    RUN(test_share_replays_unknown_frames);
    RUN(test_share_passthrough_byte);
    RUN(test_share_crlf_frame);
    RUN(test_line_buffer_scrubbed);

    if (g_failures)
    {
        fprintf(stderr, "\n%d failure(s)\n", g_failures);
        return 1;
    }
    printf("\nall tests passed\n");
    return 0;
}
