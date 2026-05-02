// provisioner_proto.c - transport-agnostic core of the prov_cop protocol.
//
// This file deliberately has no ESP-IDF dependency beyond mbedtls/base64
// so it can be built and unit-tested on a host. See provisioner_proto.h
// for the API contract.

#include "provisioner_proto.h"

#include <string.h>

#include "mbedtls/base64.h"

// Frame strings.
static const char PROV_PROBE[]   = "<<PROV?>>";
static const char PROV_READY[]   = "<<PROV!>>\n";
static const char PROV_SET_PFX[] = "<<PROV:SET ";
static const char PROV_OK[]      = "<<PROV:OK>>\n";
static const char PROV_ERR_PFX[] = "<<PROV:ERR ";
static const char PROV_ERR_SFX[] = ">>\n";
static const char PROV_ID_PFX[]  = "<<PROV:ID ";
static const char PROV_ID_SFX[]  = ">>\n";

// ---------------------------------------------------------------------------
// CRC-16/CCITT-FALSE
// ---------------------------------------------------------------------------
uint16_t prov_proto_crc16(const char* data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++)
    {
        crc ^= ((uint16_t)(uint8_t)data[i]) << 8;
        for (int b = 0; b < 8; b++)
        {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------
static void prov_emit(prov_proto_t* p, const char* s, size_t n)
{
    if (p->cfg.write && n)
    {
        p->cfg.write(p->cfg.io_ctx, s, n);
    }
}

static void prov_send_err(prov_proto_t* p, const char* reason)
{
    // Sanitise: tokens must not contain spaces, '>', or NL.
    char   buf[48];
    size_t n = 0;
    for (const char* r = reason; *r && n + 1 < sizeof buf; r++)
    {
        char c = *r;
        if (c == ' ' || c == '>' || c == '\r' || c == '\n')
        {
            c = '_';
        }
        buf[n++] = c;
    }
    buf[n] = '\0';
    if (n == 0)
    {
        strcpy(buf, "fail");
        n = 4;
    }
    prov_emit(p, PROV_ERR_PFX, sizeof(PROV_ERR_PFX) - 1);
    prov_emit(p, buf, n);
    prov_emit(p, PROV_ERR_SFX, sizeof(PROV_ERR_SFX) - 1);
}

static void prov_send_id(prov_proto_t* p)
{
    if (!p->cfg.device_name || p->cfg.device_name[0] == '\0')
    {
        return;
    }
    // Truncate name to PROV_PROTO_MAX_NAME_LEN bytes and base64-encode.
    // Use a manual scan rather than strnlen() because the latter is a
    // POSIX extension not available in strict ISO-C builds (e.g. host
    // tests built with -std=c11 -pedantic).
    size_t name_len = 0;
    while (name_len < PROV_PROTO_MAX_NAME_LEN && p->cfg.device_name[name_len] != '\0')
    {
        name_len++;
    }
    // Encoded size = 4 * ceil(n / 3) + 1 (NUL). For n=64 -> 88+1.
    unsigned char enc[4 * ((PROV_PROTO_MAX_NAME_LEN + 2) / 3) + 1];
    size_t        olen = 0;
    int           rc   = mbedtls_base64_encode(enc,
                                   sizeof enc,
                                   &olen,
                                   (const unsigned char*)p->cfg.device_name,
                                   name_len);
    if (rc != 0 || olen == 0)
    {
        return;
    }
    prov_emit(p, PROV_ID_PFX, sizeof(PROV_ID_PFX) - 1);
    prov_emit(p, (const char*)enc, olen);
    prov_emit(p, PROV_ID_SFX, sizeof(PROV_ID_SFX) - 1);
}

// ---------------------------------------------------------------------------
// Forwarding helper for non-frame bytes
// ---------------------------------------------------------------------------
static void prov_forward(prov_proto_t* p, const char* data, size_t n)
{
    if (!p->cfg.share_with_console || !p->cfg.forward || n == 0)
    {
        return;
    }
    p->cfg.forward(p->cfg.io_ctx, data, n);
}

static void prov_forward_byte(prov_proto_t* p, char c)
{
    prov_forward(p, &c, 1);
}

// ---------------------------------------------------------------------------
// Base64 decode (mbedtls). Returns true on success and writes a NUL-terminated
// string into `out` (size out_size, including NUL). Empty input yields "".
// On failure, writes nothing useful to *written_out.
// ---------------------------------------------------------------------------
static bool prov_b64_decode(const char* in,
                            size_t      in_len,
                            char*       out,
                            size_t      out_size,
                            size_t*     written_out)
{
    if (written_out)
    {
        *written_out = 0;
    }
    if (in_len == 0)
    {
        if (out_size == 0)
        {
            return false;
        }
        out[0] = '\0';
        return true;
    }
    if (out_size == 0)
    {
        return false;
    }
    size_t written = 0;
    int    rc      = mbedtls_base64_decode((unsigned char*)out,
                                   out_size - 1,
                                   &written,
                                   (const unsigned char*)in,
                                   in_len);
    if (rc != 0)
    {
        return false;
    }
    if (memchr(out, '\0', written) != NULL)
    {
        return false;
    }
    out[written] = '\0';
    if (written_out)
    {
        *written_out = written;
    }
    return true;
}

// ---------------------------------------------------------------------------
// SET handling
// ---------------------------------------------------------------------------
static void prov_handle_set(prov_proto_t* p, const char* args, size_t args_len)
{
    // args points into p->line and is NUL-terminated; args_len is its length.
    // args = "ssid_b64 pass_b64 crc16hex" (pass_b64 may be empty).
    (void)args_len;
    const char* s1 = strchr(args, ' ');
    if (!s1)
    {
        prov_send_err(p, "fields");
        return;
    }
    const char* s2 = strchr(s1 + 1, ' ');
    if (!s2)
    {
        prov_send_err(p, "fields");
        return;
    }
    if (strchr(s2 + 1, ' ') != NULL)
    {
        prov_send_err(p, "fields");
        return;
    }

    size_t      ssid_b64_len = (size_t)(s1 - args);
    size_t      pass_b64_len = (size_t)(s2 - (s1 + 1));
    const char* crc_str      = s2 + 1;

    // CRC over "ssid_b64 pass_b64".
    if (strlen(crc_str) != 4)
    {
        prov_send_err(p, "crc");
        return;
    }
    uint16_t want = prov_proto_crc16(args, (size_t)(s2 - args));
    uint16_t got  = 0;
    for (int i = 0; i < 4; i++)
    {
        char    c = crc_str[i];
        uint8_t v;
        if (c >= '0' && c <= '9')
        {
            v = (uint8_t)(c - '0');
        }
        else if (c >= 'A' && c <= 'F')
        {
            v = (uint8_t)(10 + c - 'A');
        }
        else if (c >= 'a' && c <= 'f')
        {
            v = (uint8_t)(10 + c - 'a');
        }
        else
        {
            prov_send_err(p, "crc");
            return;
        }
        got = (uint16_t)((got << 4) | v);
    }
    if (got != want)
    {
        prov_send_err(p, "crc");
        return;
    }

    // Provide enough room to detect "too long" rather than have mbedtls
    // mis-report it as a generic base64 failure. We size the buffers one
    // byte beyond the protocol limit so an over-sized payload decodes
    // successfully and we can then reject it with a clear error.
    char   ssid[PROV_PROTO_MAX_SSID_LEN + 2];
    char   pass[PROV_PROTO_MAX_PASS_LEN + 2];
    size_t ssid_len = 0;
    size_t pass_len = 0;

    if (!prov_b64_decode(args, ssid_b64_len, ssid, sizeof ssid, &ssid_len))
    {
        prov_send_err(p, "b64ssid");
        goto scrub;
    }
    if (!prov_b64_decode(s1 + 1, pass_b64_len, pass, sizeof pass, &pass_len))
    {
        prov_send_err(p, "b64pass");
        goto scrub;
    }

    if (ssid_len == 0)
    {
        prov_send_err(p, "ssid_empty");
        goto scrub;
    }
    if (ssid_len > PROV_PROTO_MAX_SSID_LEN)
    {
        prov_send_err(p, "ssid_too_long");
        goto scrub;
    }
    if (pass_len > PROV_PROTO_MAX_PASS_LEN)
    {
        prov_send_err(p, "pass_too_long");
        goto scrub;
    }

    if (!p->cfg.on_credentials)
    {
        prov_send_err(p, "nocallback");
        goto scrub;
    }

    char err_buf[32] = {0};
    bool ok = p->cfg.on_credentials(ssid, pass, err_buf, sizeof err_buf, p->cfg.user_ctx);

    if (ok)
    {
        prov_emit(p, PROV_OK, sizeof(PROV_OK) - 1);
    }
    else
    {
        const char* reason = err_buf[0] ? err_buf : "callback";
        prov_send_err(p, reason);
    }

scrub:
    // Wipe local copies of the credentials before returning.
    {
        volatile char* vs = (volatile char*)ssid;
        for (size_t i = 0; i < sizeof ssid; i++)
        {
            vs[i] = 0;
        }
        volatile char* vp = (volatile char*)pass;
        for (size_t i = 0; i < sizeof pass; i++)
        {
            vp[i] = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Line dispatch
// ---------------------------------------------------------------------------
bool prov_proto_handle_line(prov_proto_t* p, char* line, size_t len)
{
    // Only consider lines that look like our framing: "<<PROV...>>".
    if (len < 5 || line[0] != '<' || line[1] != '<')
    {
        return false;
    }

    if (len == sizeof(PROV_PROBE) - 1 && memcmp(line, PROV_PROBE, len) == 0)
    {
        // Optional rate-limit: if a clock is provided and the previous
        // response was very recent, drop this probe silently.
        bool allow = true;
        if (p->cfg.now_ms && p->cfg.min_probe_interval_ms > 0)
        {
            uint32_t now = p->cfg.now_ms();
            if (p->have_last_probe)
            {
                uint32_t delta = now - p->last_probe_ms;
                if (delta < p->cfg.min_probe_interval_ms)
                {
                    allow = false;
                }
            }
            if (allow)
            {
                p->have_last_probe = true;
                p->last_probe_ms   = now;
            }
        }
        if (allow)
        {
            prov_emit(p, PROV_READY, sizeof(PROV_READY) - 1);
            prov_send_id(p);
        }
        return true;
    }

    size_t pfx = sizeof(PROV_SET_PFX) - 1;
    if (len > pfx + 2 && memcmp(line, PROV_SET_PFX, pfx) == 0 && line[len - 1] == '>' &&
        line[len - 2] == '>')
    {
        line[len - 2] = '\0';
        prov_handle_set(p, line + pfx, len - pfx - 2);
        return true;
    }
    // Other framed lines are not ours.
    return false;
}

// ---------------------------------------------------------------------------
// Byte feeder
// ---------------------------------------------------------------------------
static void prov_scrub_line(prov_proto_t* p)
{
    // Wipe the per-instance line buffer so any encoded credentials it held
    // do not linger in long-lived RAM after dispatch.
    volatile char* v = (volatile char*)p->line;
    for (size_t i = 0; i < sizeof p->line; i++)
    {
        v[i] = 0;
    }
    p->line_len = 0;
}

void prov_proto_init(prov_proto_t* p, const prov_proto_config_t* cfg)
{
    memset(p, 0, sizeof *p);
    p->cfg         = *cfg;
    p->share_state = PROV_PSS_LINE_START;
}

void prov_proto_feed(prov_proto_t* p, const uint8_t* buf, size_t n)
{
    const bool share = p->cfg.share_with_console;

    for (size_t i = 0; i < n; i++)
    {
        char c = (char)buf[i];

        if (!share)
        {
            // Non-shared path: '\r' stripped, accumulate until '\n', then
            // try to interpret. Anything else is dropped.
            if (c == '\r')
            {
                continue;
            }
            if (c == '\n')
            {
                if (p->overflow)
                {
                    prov_scrub_line(p);
                    p->overflow = false;
                    continue;
                }
                p->line[p->line_len] = '\0';
                (void)prov_proto_handle_line(p, p->line, p->line_len);
                prov_scrub_line(p);
                continue;
            }
            if (p->line_len + 1 >= sizeof p->line)
            {
                p->overflow = true;
                continue;
            }
            p->line[p->line_len++] = c;
            continue;
        }

        // ---- shared mode ----
        switch (p->share_state)
        {
            case PROV_PSS_LINE_START:
                if (c == '<')
                {
                    p->line[0]     = c;
                    p->line_len    = 1;
                    p->share_state = PROV_PSS_GOT_ONE_LT;
                }
                else if (c == '\n')
                {
                    prov_forward_byte(p, c);
                    // stay in PROV_PSS_LINE_START
                }
                else
                {
                    prov_forward_byte(p, c);
                    p->share_state = PROV_PSS_PASSTHROUGH;
                }
                break;

            case PROV_PSS_GOT_ONE_LT:
                if (c == '<')
                {
                    p->line[1]     = c;
                    p->line_len    = 2;
                    p->overflow    = false;
                    p->share_state = PROV_PSS_BUFFER_FRAME;
                }
                else if (c == '\n')
                {
                    // "<\n" -- not a frame, flush.
                    prov_forward(p, p->line, p->line_len);
                    prov_forward_byte(p, c);
                    prov_scrub_line(p);
                    p->share_state = PROV_PSS_LINE_START;
                }
                else
                {
                    prov_forward(p, p->line, p->line_len);
                    prov_forward_byte(p, c);
                    prov_scrub_line(p);
                    p->share_state = PROV_PSS_PASSTHROUGH;
                }
                break;

            case PROV_PSS_BUFFER_FRAME:
                if (c == '\r')
                {
                    // CRLF and LF both supported: '\r' inside a frame is
                    // stripped.
                    break;
                }
                if (c == '\n')
                {
                    if (p->overflow)
                    {
                        prov_forward_byte(p, c);
                        prov_scrub_line(p);
                        p->overflow    = false;
                        p->share_state = PROV_PSS_LINE_START;
                        break;
                    }
                    p->line[p->line_len] = '\0';
                    bool consumed        = prov_proto_handle_line(p, p->line, p->line_len);
                    if (!consumed)
                    {
                        // Not one of ours; replay the line to the console.
                        prov_forward(p, p->line, p->line_len);
                        prov_forward_byte(p, '\n');
                    }
                    prov_scrub_line(p);
                    p->share_state = PROV_PSS_LINE_START;
                    break;
                }
                if (p->line_len + 1 >= sizeof p->line)
                {
                    // Frame too long to be ours -- flush what we have and
                    // pass the rest through.
                    if (!p->overflow)
                    {
                        prov_forward(p, p->line, p->line_len);
                        p->overflow = true;
                    }
                    prov_forward_byte(p, c);
                    p->share_state = PROV_PSS_PASSTHROUGH;
                    break;
                }
                p->line[p->line_len++] = c;
                break;

            case PROV_PSS_PASSTHROUGH:
            default:
                prov_forward_byte(p, c);
                if (c == '\n')
                {
                    prov_scrub_line(p);
                    p->overflow    = false;
                    p->share_state = PROV_PSS_LINE_START;
                }
                break;
        }
    }
}
