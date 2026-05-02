// provisioner_proto.h - transport-agnostic core of the prov_cop protocol.
//
// This header is *private* to the component. The public API lives in
// provisioner.h. The split exists so that the protocol parser can be
// exercised by host-side unit tests without pulling in ESP-IDF.

#ifndef PROV_COP_PROVISIONER_PROTO_H
#define PROV_COP_PROVISIONER_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

// Maximum size of one inbound line. SET line with two base64-encoded
// strings (max ~44 + ~88 chars) plus framing easily fits in 320 bytes.
#define PROV_PROTO_LINE_MAX     320
#define PROV_PROTO_MAX_SSID_LEN 32
#define PROV_PROTO_MAX_PASS_LEN 63
// Cap on device-name length advertised in <<PROV:ID ...>> responses.
// Names longer than this are silently truncated.
#define PROV_PROTO_MAX_NAME_LEN 64

// User-supplied callback that receives validated credentials. Same contract
// as provisioner_credentials_cb_t in the public header.
typedef bool (*prov_proto_credentials_cb_t)(const char* ssid,
                                            const char* password,
                                            char* err_out,
                                            size_t err_out_len,
                                            void* user_ctx);

// Byte-stream sink: write `len` bytes to the peer (e.g. UART TX).
typedef void (*prov_proto_write_cb_t)(void* io_ctx, const char* data, size_t len);

// Byte-stream sink: forward bytes that are *not* part of a recognised frame
// to a downstream consumer (e.g. the redirected stdin stream). May be NULL
// to drop non-frame bytes.
typedef void (*prov_proto_forward_cb_t)(void* io_ctx, const char* data, size_t len);

// Optional clock source used for probe rate-limiting. If NULL, probes are
// always answered.
typedef uint32_t (*prov_proto_now_ms_cb_t)(void);

typedef struct
{
    prov_proto_write_cb_t       write;
    prov_proto_forward_cb_t     forward;
    void*                       io_ctx;
    prov_proto_credentials_cb_t on_credentials;
    void*                       user_ctx;
    // Optional NUL-terminated device-name. May be NULL or "". When set,
    // the protocol will respond to a probe with both <<PROV!>> and
    // <<PROV:ID <name_b64>>>. Names longer than PROV_PROTO_MAX_NAME_LEN
    // are truncated.
    const char* device_name;
    // If true the parser preserves non-frame lines and forwards them via
    // `forward`; otherwise it discards them after each '\n'.
    bool share_with_console;
    // Minimum interval (in ms) between successive <<PROV!>> responses.
    // Set to 0 to disable rate-limiting.
    uint32_t               min_probe_interval_ms;
    prov_proto_now_ms_cb_t now_ms;
} prov_proto_config_t;

enum prov_proto_share_state
{
    PROV_PSS_LINE_START = 0, // start of a line; no bytes accumulated yet
    PROV_PSS_GOT_ONE_LT,     // saw a single '<' at line start
    PROV_PSS_BUFFER_FRAME,   // accumulating a possible "<<...>>" frame
    PROV_PSS_PASSTHROUGH,    // forwarding bytes verbatim until next '\n'
};

typedef struct
{
    prov_proto_config_t         cfg;
    char                        line[PROV_PROTO_LINE_MAX];
    size_t                      line_len;
    bool                        overflow;
    enum prov_proto_share_state share_state;
    bool                        have_last_probe;
    uint32_t                    last_probe_ms;
} prov_proto_t;

// Initialise a protocol parser with the given configuration. The config is
// copied; the strings it points to (e.g. device_name) must outlive `p`.
void prov_proto_init(prov_proto_t* p, const prov_proto_config_t* cfg);

// Feed `n` bytes received from the peer into the parser. Frames are
// answered via `cfg.write`; non-frame bytes are forwarded via
// `cfg.forward` when share_with_console is set, otherwise discarded.
void prov_proto_feed(prov_proto_t* p, const uint8_t* buf, size_t n);

// Internal helper exposed for host-side tests. Mutates `line` (writes a
// NUL into the trailing ">>"). Returns true if the line was a recognised
// frame and was consumed; false if it should be replayed downstream.
bool prov_proto_handle_line(prov_proto_t* p, char* line, size_t len);

// Internal helper exposed for host-side tests. CRC-16/CCITT-FALSE.
uint16_t prov_proto_crc16(const char* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // PROV_COP_PROVISIONER_PROTO_H
