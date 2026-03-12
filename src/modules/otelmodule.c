/* otelmodule.c -- OpenTelemetry distributed tracing module for Valkey using RESP4 request headers.
 *
 * This module leverages RESP4 request-side attributes (request headers) to implement
 * W3C Trace Context propagation through Valkey. It enables end-to-end distributed
 * tracing by allowing clients to send OpenTelemetry trace context as RESP4 headers,
 * which the module captures, logs, attaches to commandlog entries, and exposes
 * through diagnostic commands.
 *
 * Supported RESP4 Headers (W3C Trace Context):
 *   - traceparent    : W3C traceparent header (version-traceid-spanid-traceflags)
 *   - tracestate     : W3C tracestate header (vendor-specific trace data)
 *
 * Additional Headers:
 *   - baggage         : W3C baggage header for application-level context propagation
 *   - otel-resource   : Optional resource identifier for the originating service
 *
 * Commands Provided:
 *   OTEL.TRACE       - Return the current trace context (traceparent + tracestate) or nil
 *   OTEL.CONTEXT     - Return all OpenTelemetry headers as a map
 *   OTEL.SPANID      - Extract and return just the span-id from traceparent, or nil
 *   OTEL.TRACEID     - Extract and return just the trace-id from traceparent, or nil
 *   OTEL.STATS       - Return module statistics (commands traced, headers received, etc.)
 *
 * Command Filter:
 *   A command filter captures traceparent and tracestate on every command and attaches
 *   them as commandlog (slowlog) metadata, enabling correlation between slow queries
 *   and distributed traces.
 *
 * Copyright (c) Valkey Contributors
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "../valkeymodule.h"
#include <string.h>
#include <strings.h>
#include <ctype.h>

/* ============================================================================
 * Constants — W3C Trace Context header names
 * ============================================================================ */

#define HEADER_TRACEPARENT  "traceparent"
#define HEADER_TRACESTATE   "tracestate"
#define HEADER_BAGGAGE      "baggage"
#define HEADER_OTEL_RESOURCE "otel-resource"

/* W3C traceparent format: VERSION-TRACEID-SPANID-FLAGS
 * Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
 *
 * VERSION:  2 hex chars (1 byte)
 * TRACEID: 32 hex chars (16 bytes)
 * SPANID:  16 hex chars (8 bytes)
 * FLAGS:    2 hex chars (1 byte)
 * Total with dashes: 2 + 1 + 32 + 1 + 16 + 1 + 2 = 55 chars
 */
#define TRACEPARENT_LEN 55
#define TRACEID_OFFSET  3
#define TRACEID_LEN     32
#define SPANID_OFFSET   36
#define SPANID_LEN      16
#define FLAGS_OFFSET    53
#define FLAGS_LEN       2

/* ============================================================================
 * Module statistics — atomic counters for observability
 * ============================================================================ */

static long long stats_commands_traced = 0;       /* Commands that had traceparent */
static long long stats_commands_total = 0;         /* Total commands seen by filter */
static long long stats_traceparent_invalid = 0;    /* traceparent headers that failed validation */
static long long stats_tracestate_received = 0;    /* Commands that had tracestate */
static long long stats_baggage_received = 0;       /* Commands that had baggage */
static long long stats_keyspace_events = 0;        /* Total keyspace events observed */
static long long stats_key_misses = 0;             /* Key miss events */
static long long stats_key_overwrites = 0;         /* Key overwrite events */
static long long stats_key_expirations = 0;        /* Key expiration events */
static long long stats_key_evictions = 0;          /* Key eviction events */
static long long stats_client_connects = 0;        /* Client connection events */
static long long stats_client_disconnects = 0;     /* Client disconnection events */

/* ============================================================================
 * Recent events ring buffer — stores last N traced events for OTEL.EVENTS
 * ============================================================================ */

#define MAX_EVENTS 64

typedef struct {
    long long timestamp_ms;   /* Milliseconds since epoch */
    char type[32];            /* Event type: "keyspace", "key_miss", "expired", etc. */
    char detail[128];         /* Event detail: key name, event info */
} OtelEvent;

static OtelEvent event_ring[MAX_EVENTS];
static int event_ring_pos = 0;
static int event_ring_count = 0;

static void record_event(const char *type, const char *detail, long long ts) {
    OtelEvent *ev = &event_ring[event_ring_pos % MAX_EVENTS];
    ev->timestamp_ms = ts;
    strncpy(ev->type, type, sizeof(ev->type) - 1);
    ev->type[sizeof(ev->type) - 1] = '\0';
    strncpy(ev->detail, detail, sizeof(ev->detail) - 1);
    ev->detail[sizeof(ev->detail) - 1] = '\0';
    event_ring_pos = (event_ring_pos + 1) % MAX_EVENTS;
    if (event_ring_count < MAX_EVENTS) event_ring_count++;
}

/* ============================================================================
 * Utility — W3C traceparent validation
 * ============================================================================ */

/* Return 1 if c is a valid lowercase hex digit. */
static int is_lower_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Validate a W3C traceparent string.
 * Must be exactly 55 chars: VV-TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT-SSSSSSSSSSSSSSSS-FF
 * where V,T,S,F are lowercase hex chars and dashes are at positions 2, 35, 52. */
static int validate_traceparent(const char *tp, size_t len) {
    if (len != TRACEPARENT_LEN) return 0;
    if (tp[2] != '-' || tp[35] != '-' || tp[52] != '-') return 0;

    /* Check version (positions 0-1) */
    for (int i = 0; i < 2; i++) {
        if (!is_lower_hex(tp[i])) return 0;
    }
    /* Version 0xff is invalid per spec */
    if (tp[0] == 'f' && tp[1] == 'f') return 0;

    /* Check trace-id (positions 3-34): must not be all zeros */
    int all_zero = 1;
    for (int i = TRACEID_OFFSET; i < TRACEID_OFFSET + TRACEID_LEN; i++) {
        if (!is_lower_hex(tp[i])) return 0;
        if (tp[i] != '0') all_zero = 0;
    }
    if (all_zero) return 0;

    /* Check span-id (positions 36-51): must not be all zeros */
    all_zero = 1;
    for (int i = SPANID_OFFSET; i < SPANID_OFFSET + SPANID_LEN; i++) {
        if (!is_lower_hex(tp[i])) return 0;
        if (tp[i] != '0') all_zero = 0;
    }
    if (all_zero) return 0;

    /* Check flags (positions 53-54) */
    for (int i = FLAGS_OFFSET; i < FLAGS_OFFSET + FLAGS_LEN; i++) {
        if (!is_lower_hex(tp[i])) return 0;
    }

    return 1;
}

/* ============================================================================
 * Command Filter — captures trace context on every command for commandlog
 * ============================================================================ */

/* This filter runs before every command. If RESP4 trace headers are present,
 * it attaches them as commandlog metadata so that COMMANDLOG GET / SLOWLOG GET
 * entries include the trace context for correlation with distributed traces. */
void OtelCommandFilter(ValkeyModuleCommandFilterCtx *fctx) {
    stats_commands_total++;

    /* Check for traceparent header */
    ValkeyModuleString *traceparent =
        ValkeyModule_CommandFilterGetRequestHeader(fctx, HEADER_TRACEPARENT);

    if (traceparent) {
        size_t tp_len;
        const char *tp_str = ValkeyModule_StringPtrLen(traceparent, &tp_len);

        if (validate_traceparent(tp_str, tp_len)) {
            stats_commands_traced++;

            /* Attach traceparent to commandlog entry */
            ValkeyModule_CommandFilterSetCommandlogMetadata(
                fctx, HEADER_TRACEPARENT, traceparent);

            /* Also attach tracestate if present */
            ValkeyModuleString *tracestate =
                ValkeyModule_CommandFilterGetRequestHeader(fctx, HEADER_TRACESTATE);
            if (tracestate) {
                stats_tracestate_received++;
                ValkeyModule_CommandFilterSetCommandlogMetadata(
                    fctx, HEADER_TRACESTATE, tracestate);
            }
        } else {
            stats_traceparent_invalid++;
        }
    }

    /* Track baggage presence for stats */
    ValkeyModuleString *baggage =
        ValkeyModule_CommandFilterGetRequestHeader(fctx, HEADER_BAGGAGE);
    if (baggage) {
        stats_baggage_received++;
    }
}

/* ============================================================================
 * OTEL.TRACE — Return traceparent [and tracestate] from the current request
 * ============================================================================ */

/* OTEL.TRACE
 * Returns the traceparent value if present (and valid), or nil.
 * If tracestate is also present, returns a 2-element array [traceparent, tracestate].
 * If only traceparent is present, returns just the traceparent string. */
int OtelTraceCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    if (argc != 1) return ValkeyModule_WrongArity(ctx);

    ValkeyModuleString *traceparent =
        ValkeyModule_GetRequestHeader(ctx, HEADER_TRACEPARENT);

    if (!traceparent) {
        ValkeyModule_ReplyWithNull(ctx);
        return VALKEYMODULE_OK;
    }

    /* Validate the traceparent */
    size_t tp_len;
    const char *tp_str = ValkeyModule_StringPtrLen(traceparent, &tp_len);
    if (!validate_traceparent(tp_str, tp_len)) {
        ValkeyModule_ReplyWithError(ctx, "ERR invalid traceparent format; "
            "expected: VERSION-TRACEID-SPANID-FLAGS "
            "(e.g. 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01)");
        return VALKEYMODULE_OK;
    }

    ValkeyModuleString *tracestate =
        ValkeyModule_GetRequestHeader(ctx, HEADER_TRACESTATE);

    if (tracestate) {
        ValkeyModule_ReplyWithArray(ctx, 2);
        ValkeyModule_ReplyWithString(ctx, traceparent);
        ValkeyModule_ReplyWithString(ctx, tracestate);
    } else {
        ValkeyModule_ReplyWithString(ctx, traceparent);
    }

    return VALKEYMODULE_OK;
}

/* ============================================================================
 * OTEL.CONTEXT — Return all OpenTelemetry headers as a map
 * ============================================================================ */

/* OTEL.CONTEXT
 * Returns a map of all recognized OpenTelemetry headers present on the current
 * request. Keys: traceparent, tracestate, baggage, otel-resource.
 * Returns an empty map if no OTel headers are present. */
int OtelContextCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    if (argc != 1) return ValkeyModule_WrongArity(ctx);

    /* Count how many OTel headers are present */
    const char *header_names[] = {
        HEADER_TRACEPARENT,
        HEADER_TRACESTATE,
        HEADER_BAGGAGE,
        HEADER_OTEL_RESOURCE
    };
    int num_headers = sizeof(header_names) / sizeof(header_names[0]);

    ValkeyModuleString *values[4];
    int present_count = 0;

    for (int i = 0; i < num_headers; i++) {
        values[i] = ValkeyModule_GetRequestHeader(ctx, header_names[i]);
        if (values[i]) present_count++;
    }

    ValkeyModule_ReplyWithMap(ctx, present_count);
    for (int i = 0; i < num_headers; i++) {
        if (values[i]) {
            ValkeyModule_ReplyWithCString(ctx, header_names[i]);
            ValkeyModule_ReplyWithString(ctx, values[i]);
        }
    }

    return VALKEYMODULE_OK;
}

/* ============================================================================
 * OTEL.TRACEID — Extract and return the trace-id from traceparent
 * ============================================================================ */

/* OTEL.TRACEID
 * Extracts the 32-char trace-id from the traceparent header.
 * Returns the trace-id as a string, or nil if traceparent is absent/invalid. */
int OtelTraceIdCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    if (argc != 1) return ValkeyModule_WrongArity(ctx);

    ValkeyModuleString *traceparent =
        ValkeyModule_GetRequestHeader(ctx, HEADER_TRACEPARENT);

    if (!traceparent) {
        ValkeyModule_ReplyWithNull(ctx);
        return VALKEYMODULE_OK;
    }

    size_t tp_len;
    const char *tp_str = ValkeyModule_StringPtrLen(traceparent, &tp_len);

    if (!validate_traceparent(tp_str, tp_len)) {
        ValkeyModule_ReplyWithNull(ctx);
        return VALKEYMODULE_OK;
    }

    ValkeyModule_ReplyWithStringBuffer(ctx, tp_str + TRACEID_OFFSET, TRACEID_LEN);
    return VALKEYMODULE_OK;
}

/* ============================================================================
 * OTEL.SPANID — Extract and return the span-id from traceparent
 * ============================================================================ */

/* OTEL.SPANID
 * Extracts the 16-char span-id from the traceparent header.
 * Returns the span-id as a string, or nil if traceparent is absent/invalid. */
int OtelSpanIdCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    if (argc != 1) return ValkeyModule_WrongArity(ctx);

    ValkeyModuleString *traceparent =
        ValkeyModule_GetRequestHeader(ctx, HEADER_TRACEPARENT);

    if (!traceparent) {
        ValkeyModule_ReplyWithNull(ctx);
        return VALKEYMODULE_OK;
    }

    size_t tp_len;
    const char *tp_str = ValkeyModule_StringPtrLen(traceparent, &tp_len);

    if (!validate_traceparent(tp_str, tp_len)) {
        ValkeyModule_ReplyWithNull(ctx);
        return VALKEYMODULE_OK;
    }

    ValkeyModule_ReplyWithStringBuffer(ctx, tp_str + SPANID_OFFSET, SPANID_LEN);
    return VALKEYMODULE_OK;
}

/* ============================================================================
 * OTEL.STATS — Return module statistics
 * ============================================================================ */

/* OTEL.STATS
 * Returns a map of module statistics:
 *   commands_total        - Total commands observed by the filter
 *   commands_traced       - Commands that carried a valid traceparent
 *   traceparent_invalid   - Commands with malformed traceparent
 *   tracestate_received   - Commands that carried tracestate
 *   baggage_received      - Commands that carried baggage
 *   trace_ratio           - Ratio of traced to total commands (double) */
int OtelStatsCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    if (argc != 1) return ValkeyModule_WrongArity(ctx);

    ValkeyModule_ReplyWithMap(ctx, 13);

    ValkeyModule_ReplyWithCString(ctx, "commands_total");
    ValkeyModule_ReplyWithLongLong(ctx, stats_commands_total);

    ValkeyModule_ReplyWithCString(ctx, "commands_traced");
    ValkeyModule_ReplyWithLongLong(ctx, stats_commands_traced);

    ValkeyModule_ReplyWithCString(ctx, "traceparent_invalid");
    ValkeyModule_ReplyWithLongLong(ctx, stats_traceparent_invalid);

    ValkeyModule_ReplyWithCString(ctx, "tracestate_received");
    ValkeyModule_ReplyWithLongLong(ctx, stats_tracestate_received);

    ValkeyModule_ReplyWithCString(ctx, "baggage_received");
    ValkeyModule_ReplyWithLongLong(ctx, stats_baggage_received);

    ValkeyModule_ReplyWithCString(ctx, "trace_ratio");
    if (stats_commands_total > 0) {
        ValkeyModule_ReplyWithDouble(ctx,
            (double)stats_commands_traced / (double)stats_commands_total);
    } else {
        ValkeyModule_ReplyWithDouble(ctx, 0.0);
    }

    /* Hook-based stats */
    ValkeyModule_ReplyWithCString(ctx, "keyspace_events");
    ValkeyModule_ReplyWithLongLong(ctx, stats_keyspace_events);

    ValkeyModule_ReplyWithCString(ctx, "key_misses");
    ValkeyModule_ReplyWithLongLong(ctx, stats_key_misses);

    ValkeyModule_ReplyWithCString(ctx, "key_overwrites");
    ValkeyModule_ReplyWithLongLong(ctx, stats_key_overwrites);

    ValkeyModule_ReplyWithCString(ctx, "key_expirations");
    ValkeyModule_ReplyWithLongLong(ctx, stats_key_expirations);

    ValkeyModule_ReplyWithCString(ctx, "key_evictions");
    ValkeyModule_ReplyWithLongLong(ctx, stats_key_evictions);

    ValkeyModule_ReplyWithCString(ctx, "client_connects");
    ValkeyModule_ReplyWithLongLong(ctx, stats_client_connects);

    ValkeyModule_ReplyWithCString(ctx, "client_disconnects");
    ValkeyModule_ReplyWithLongLong(ctx, stats_client_disconnects);

    return VALKEYMODULE_OK;
}

/* ============================================================================
 * Keyspace Notification Callback — tracks key-level events
 * ============================================================================ */

/* Called for every keyspace event (SET, DEL, EXPIRE, EVICT, etc.).
 * We record the event in our ring buffer and update stats. */
int OtelKeyspaceCallback(ValkeyModuleCtx *ctx, int type, const char *event,
                         ValkeyModuleString *key) {
    VALKEYMODULE_NOT_USED(ctx);
    stats_keyspace_events++;

    size_t key_len;
    const char *key_str = ValkeyModule_StringPtrLen(key, &key_len);
    mstime_t now = ValkeyModule_Milliseconds();

    /* Build detail string: "event_name key_name" */
    char detail[128];
    snprintf(detail, sizeof(detail), "%s %.90s", event, key_str);

    /* Categorize by notification type */
    if (type & VALKEYMODULE_NOTIFY_KEY_MISS) {
        stats_key_misses++;
        record_event("key_miss", detail, now);
    } else if (type & VALKEYMODULE_NOTIFY_EXPIRED) {
        stats_key_expirations++;
        record_event("expired", detail, now);
    } else if (type & VALKEYMODULE_NOTIFY_EVICTED) {
        stats_key_evictions++;
        record_event("evicted", detail, now);
    } else if (type & VALKEYMODULE_NOTIFY_NEW) {
        record_event("new_key", detail, now);
    } else {
        record_event("keyspace", detail, now);
    }

    return VALKEYMODULE_OK;
}

/* ============================================================================
 * Server Event Callback — tracks client connections and key lifecycle
 * ============================================================================ */

void OtelServerEventCallback(ValkeyModuleCtx *ctx, ValkeyModuleEvent eid,
                             uint64_t subevent, void *data) {
    VALKEYMODULE_NOT_USED(ctx);
    mstime_t now = ValkeyModule_Milliseconds();

    if (eid.id == VALKEYMODULE_EVENT_CLIENT_CHANGE) {
        if (subevent == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_CONNECTED) {
            stats_client_connects++;
            record_event("client_connect", "new client connected", now);
        } else if (subevent == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_DISCONNECTED) {
            stats_client_disconnects++;
            record_event("client_disconnect", "client disconnected", now);
        }
    } else if (eid.id == VALKEYMODULE_EVENT_KEY) {
        const char *key_name = "(unknown)";
        /* ValkeyModuleKeyInfoV1 contains a ValkeyModuleKey* (opened key handle).
         * We just use a placeholder since extracting the key name from
         * ValkeyModuleKey* requires ValkeyModule_KeyName() which needs a
         * non-NULL opened key — and the data pointer may not always be safe. */
        (void)data;
        char detail[128];
        if (subevent == VALKEYMODULE_SUBEVENT_KEY_DELETED) {
            snprintf(detail, sizeof(detail), "del %.100s", key_name);
            record_event("key_deleted", detail, now);
        } else if (subevent == VALKEYMODULE_SUBEVENT_KEY_EXPIRED) {
            stats_key_expirations++;
            snprintf(detail, sizeof(detail), "expire %.100s", key_name);
            record_event("key_expired", detail, now);
        } else if (subevent == VALKEYMODULE_SUBEVENT_KEY_EVICTED) {
            stats_key_evictions++;
            snprintf(detail, sizeof(detail), "evict %.100s", key_name);
            record_event("key_evicted", detail, now);
        } else if (subevent == VALKEYMODULE_SUBEVENT_KEY_OVERWRITTEN) {
            stats_key_overwrites++;
            snprintf(detail, sizeof(detail), "overwrite %.100s", key_name);
            record_event("key_overwrite", detail, now);
        }
    } else if (eid.id == VALKEYMODULE_EVENT_PERSISTENCE) {
        if (subevent == 0) {
            record_event("rdb_start", "RDB save started", now);
        } else {
            record_event("rdb_end", "RDB save ended", now);
        }
    }
}

/* ============================================================================
 * OTEL.EVENTS — Return recent traced events from the ring buffer
 * ============================================================================ */

/* OTEL.EVENTS [count]
 * Returns the last N events (default 10, max 64) from the event ring buffer.
 * Each event is a map with: timestamp_ms, type, detail */
int OtelEventsCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    long long count = 10;
    if (argc > 2) return ValkeyModule_WrongArity(ctx);
    if (argc == 2) {
        if (ValkeyModule_StringToLongLong(argv[1], &count) != VALKEYMODULE_OK) {
            ValkeyModule_ReplyWithError(ctx, "ERR count must be a number");
            return VALKEYMODULE_OK;
        }
        if (count < 0) count = 0;
        if (count > MAX_EVENTS) count = MAX_EVENTS;
    }

    int avail = event_ring_count;
    if (count > avail) count = avail;

    ValkeyModule_ReplyWithArray(ctx, count);

    /* Walk backward from the most recent event */
    for (int i = 0; i < (int)count; i++) {
        int idx = (event_ring_pos - 1 - i + MAX_EVENTS) % MAX_EVENTS;
        OtelEvent *ev = &event_ring[idx];

        ValkeyModule_ReplyWithMap(ctx, 3);
        ValkeyModule_ReplyWithCString(ctx, "timestamp_ms");
        ValkeyModule_ReplyWithLongLong(ctx, ev->timestamp_ms);
        ValkeyModule_ReplyWithCString(ctx, "type");
        ValkeyModule_ReplyWithCString(ctx, ev->type);
        ValkeyModule_ReplyWithCString(ctx, "detail");
        ValkeyModule_ReplyWithCString(ctx, ev->detail);
    }

    return VALKEYMODULE_OK;
}

/* ============================================================================
 * OTEL.EXEC — Execute a command with server-side timing reply attributes
 * ============================================================================ */

/* OTEL.EXEC <command> [args...]
 *
 * Executes the given command on the server and returns the result, but also
 * attaches RESP4 reply-side attributes with server-side timing information
 * including sub-path latency breakdown.
 * This enables the client to create a "server" child span with actual
 * server-side execution duration and sub-path detail.
 *
 * Reply attributes returned (RESP4 clients only):
 *   server-start-us        : server timestamp (microseconds since epoch) when execution started
 *   server-end-us          : server timestamp (microseconds since epoch) when execution ended
 *   server-duration-us     : total execution duration in microseconds
 *   input-buffer-wait-us   : time waiting in input buffer before parsing (0 for module calls)
 *   blocked-wait-us        : time spent blocked/throttled before execution (0 for module calls)
 *   processing-us          : time spent executing the inner command
 *   output-buffer-wait-us  : time waiting in output buffer before socket write (0 at report time)
 *   traceparent            : echoed back from request (if present)
 *
 * This gives the client enough information to create sub-path spans:
 *
 *   Client span:  |----------- network RTT + server time ----------|
 *   Server span:       |--- server-duration-us ---|
 *     Sub-paths:       [input-buf][blocked][processing][output-buf]
 *
 * Example:
 *   > OTEL.EXEC SET foo bar
 *   # attribute: server-start-us=1698776172000123, server-end-us=1698776172000456,
 *   #            server-duration-us=333, processing-us=330, traceparent=00-...
 *   OK
 */
int OtelExecCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    if (argc < 2) {
        ValkeyModule_ReplyWithError(ctx,
            "ERR wrong number of arguments for 'OTEL.EXEC' command. "
            "Usage: OTEL.EXEC <command> [args...]");
        return VALKEYMODULE_OK;
    }

    /* Get the command name */
    const char *cmd = ValkeyModule_StringPtrLen(argv[1], NULL);

    /* Snapshot the event ring position BEFORE executing the command.
     * Any events that fire during ValkeyModule_Call() (keyspace notifications,
     * key lifecycle hooks) will appear after this position. */
    int events_before_pos = event_ring_pos;
    int events_before_count = event_ring_count;

    /* Capture start timestamp using monotonic microseconds for sub-path tracking.
     * The time from OTEL.EXEC entry to ValkeyModule_Call is the input-buffer-wait
     * analog (command dispatch overhead). */
    ustime_t otel_entry_us = ValkeyModule_Microseconds();
    uint64_t mono_pre_call = ValkeyModule_MonotonicMicroseconds();

    /* Execute the command */
    ValkeyModuleCallReply *reply;
    if (argc == 2) {
        reply = ValkeyModule_Call(ctx, cmd, "");
    } else {
        reply = ValkeyModule_Call(ctx, cmd, "v", argv + 2, argc - 2);
    }

    /* Capture end timestamp */
    uint64_t mono_post_call = ValkeyModule_MonotonicMicroseconds();
    ustime_t otel_end_us = ValkeyModule_Microseconds();

    long long processing_us = (long long)(mono_post_call - mono_pre_call);
    long long total_duration_us = (long long)(otel_end_us - otel_entry_us);

    /* Sub-path latency breakdown for OTEL.EXEC:
     * - input-buffer-wait: not directly measurable here (the outer OTEL.EXEC
     *   command's own qb/parse wait is tracked by the core). We report 0.
     * - blocked-wait: not applicable for module-dispatched calls. We report 0.
     * - processing: time inside ValkeyModule_Call (the actual command execution).
     * - output-buffer-wait: not yet written to socket. We report 0. */
    long long input_buffer_wait_us = 0;
    long long blocked_wait_us = 0;
    long long output_buffer_wait_us = 0;

    /* Count events that fired DURING this command */
    int new_events = event_ring_count - events_before_count;
    if (event_ring_count == events_before_count) {
        /* Ring count didn't change but pos might have wrapped */
        new_events = (event_ring_pos - events_before_pos + MAX_EVENTS) % MAX_EVENTS;
    }
    if (new_events < 0) new_events = 0;
    if (new_events > MAX_EVENTS) new_events = MAX_EVENTS;

    /* Send reply attributes: timing + sub-path latencies + events */
    ValkeyModule_ReplyWithAttribute(ctx, 9);

    ValkeyModule_ReplyWithCString(ctx, "server-start-us");
    ValkeyModule_ReplyWithLongLong(ctx, (long long)otel_entry_us);

    ValkeyModule_ReplyWithCString(ctx, "server-end-us");
    ValkeyModule_ReplyWithLongLong(ctx, (long long)otel_end_us);

    ValkeyModule_ReplyWithCString(ctx, "server-duration-us");
    ValkeyModule_ReplyWithLongLong(ctx, total_duration_us);

    /* Sub-path latency breakdown */
    ValkeyModule_ReplyWithCString(ctx, "input-buffer-wait-us");
    ValkeyModule_ReplyWithLongLong(ctx, input_buffer_wait_us);

    ValkeyModule_ReplyWithCString(ctx, "blocked-wait-us");
    ValkeyModule_ReplyWithLongLong(ctx, blocked_wait_us);

    ValkeyModule_ReplyWithCString(ctx, "processing-us");
    ValkeyModule_ReplyWithLongLong(ctx, processing_us);

    ValkeyModule_ReplyWithCString(ctx, "output-buffer-wait-us");
    ValkeyModule_ReplyWithLongLong(ctx, output_buffer_wait_us);

    /* Echo back traceparent if present */
    ValkeyModuleString *traceparent =
        ValkeyModule_GetRequestHeader(ctx, HEADER_TRACEPARENT);
    ValkeyModule_ReplyWithCString(ctx, "traceparent");
    if (traceparent) {
        ValkeyModule_ReplyWithString(ctx, traceparent);
    } else {
        ValkeyModule_ReplyWithNull(ctx);
    }

    /* Include the events that fired during this command as an array of maps.
     * This lets the client create child spans for each internal step. */
    ValkeyModule_ReplyWithCString(ctx, "events");
    ValkeyModule_ReplyWithArray(ctx, new_events);
    for (int i = 0; i < new_events; i++) {
        int idx = (events_before_pos + i) % MAX_EVENTS;
        OtelEvent *ev = &event_ring[idx];
        ValkeyModule_ReplyWithMap(ctx, 3);
        ValkeyModule_ReplyWithCString(ctx, "timestamp_ms");
        ValkeyModule_ReplyWithLongLong(ctx, ev->timestamp_ms);
        ValkeyModule_ReplyWithCString(ctx, "type");
        ValkeyModule_ReplyWithCString(ctx, ev->type);
        ValkeyModule_ReplyWithCString(ctx, "detail");
        ValkeyModule_ReplyWithCString(ctx, ev->detail);
    }

    /* Forward the actual reply */
    if (reply) {
        ValkeyModule_ReplyWithCallReply(ctx, reply);
        ValkeyModule_FreeCallReply(reply);
    } else {
        ValkeyModule_ReplyWithError(ctx, "ERR failed to execute command");
    }

    return VALKEYMODULE_OK;
}

/* ============================================================================
 * Module initialization
 * ============================================================================ */

int ValkeyModule_OnLoad(ValkeyModuleCtx *ctx, ValkeyModuleString **argv,
                        int argc) {
    VALKEYMODULE_NOT_USED(argv);
    VALKEYMODULE_NOT_USED(argc);

    if (ValkeyModule_Init(ctx, "otel", 1, VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    /* ---- Register RESP4 request headers ----
     * We register the W3C Trace Context headers plus baggage and a custom
     * resource header. -1 for expected_type means "any scalar type". */
    if (ValkeyModule_RegisterRequestHeader(ctx, HEADER_TRACEPARENT, 0, -1) == VALKEYMODULE_ERR) {
        ValkeyModule_Log(ctx, "warning",
            "otel: failed to register '%s' header (may be registered by another module)",
            HEADER_TRACEPARENT);
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterRequestHeader(ctx, HEADER_TRACESTATE, 0, -1) == VALKEYMODULE_ERR) {
        ValkeyModule_Log(ctx, "warning",
            "otel: failed to register '%s' header", HEADER_TRACESTATE);
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterRequestHeader(ctx, HEADER_BAGGAGE, 0, -1) == VALKEYMODULE_ERR) {
        ValkeyModule_Log(ctx, "warning",
            "otel: failed to register '%s' header", HEADER_BAGGAGE);
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterRequestHeader(ctx, HEADER_OTEL_RESOURCE, 0, -1) == VALKEYMODULE_ERR) {
        ValkeyModule_Log(ctx, "warning",
            "otel: failed to register '%s' header", HEADER_OTEL_RESOURCE);
        return VALKEYMODULE_ERR;
    }

    ValkeyModule_Log(ctx, "notice",
        "otel: registered RESP4 headers: %s, %s, %s, %s",
        HEADER_TRACEPARENT, HEADER_TRACESTATE, HEADER_BAGGAGE, HEADER_OTEL_RESOURCE);

    /* ---- Register command filter for commandlog metadata ---- */
    if (ValkeyModule_RegisterCommandFilter(ctx, OtelCommandFilter, 0) == NULL) {
        ValkeyModule_Log(ctx, "warning", "otel: failed to register command filter");
        return VALKEYMODULE_ERR;
    }

    /* ---- Register commands ---- */
    if (ValkeyModule_CreateCommand(ctx, "otel.trace",
            OtelTraceCommand, "fast", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    if (ValkeyModule_CreateCommand(ctx, "otel.context",
            OtelContextCommand, "fast", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    if (ValkeyModule_CreateCommand(ctx, "otel.traceid",
            OtelTraceIdCommand, "fast", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    if (ValkeyModule_CreateCommand(ctx, "otel.spanid",
            OtelSpanIdCommand, "fast", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    if (ValkeyModule_CreateCommand(ctx, "otel.stats",
            OtelStatsCommand, "fast", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    if (ValkeyModule_CreateCommand(ctx, "otel.exec",
            OtelExecCommand, "write", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    if (ValkeyModule_CreateCommand(ctx, "otel.events",
            OtelEventsCommand, "fast", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    /* ---- Subscribe to keyspace notifications ----
     * This captures key-level events: writes, expirations, evictions, misses.
     * Events are recorded in the ring buffer and exposed via OTEL.EVENTS. */
    if (ValkeyModule_SubscribeToKeyspaceEvents(ctx,
            VALKEYMODULE_NOTIFY_ALL | VALKEYMODULE_NOTIFY_KEY_MISS | VALKEYMODULE_NOTIFY_NEW,
            OtelKeyspaceCallback) == VALKEYMODULE_ERR) {
        ValkeyModule_Log(ctx, "warning", "otel: failed to subscribe to keyspace events");
        /* Non-fatal: continue without keyspace tracking */
    } else {
        ValkeyModule_Log(ctx, "notice", "otel: subscribed to keyspace notifications");
    }

    /* ---- Subscribe to server events ----
     * Track client connections/disconnections and key lifecycle events. */
    if (ValkeyModule_SubscribeToServerEvent(ctx,
            ValkeyModuleEvent_ClientChange,
            OtelServerEventCallback) == VALKEYMODULE_ERR) {
        ValkeyModule_Log(ctx, "warning", "otel: failed to subscribe to client change events");
    }

    if (ValkeyModule_SubscribeToServerEvent(ctx,
            ValkeyModuleEvent_Key,
            OtelServerEventCallback) == VALKEYMODULE_ERR) {
        ValkeyModule_Log(ctx, "warning", "otel: failed to subscribe to key events");
    }

    if (ValkeyModule_SubscribeToServerEvent(ctx,
            ValkeyModuleEvent_Persistence,
            OtelServerEventCallback) == VALKEYMODULE_ERR) {
        ValkeyModule_Log(ctx, "warning", "otel: failed to subscribe to persistence events");
    }

    ValkeyModule_Log(ctx, "notice", "otel: subscribed to server events (client, key, persistence)");

    ValkeyModule_Log(ctx, "notice",
        "otel: OpenTelemetry tracing module loaded. "
        "Commands: OTEL.TRACE, OTEL.CONTEXT, OTEL.TRACEID, OTEL.SPANID, OTEL.STATS, OTEL.EXEC, OTEL.EVENTS");

    return VALKEYMODULE_OK;
}
