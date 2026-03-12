#!/usr/bin/env python3
"""
OpenTelemetry + RESP4 Demo for Valkey

Demonstrates how RESP4 request headers enable distributed tracing between
a client application and Valkey. The client sends W3C traceparent as a
RESP4 header, and the server participates in the trace by reporting
execution timing and internal events.

Generates many traces with randomized keys across different commands
(SET, GET, INCR, DEL, EXPIRE) so you can explore query and filtering
capabilities in Jaeger/Grafana (search by operation, tag, duration, etc.)

Usage:
    python3 demo.py [--host HOST] [--port PORT] [--jaeger-endpoint URL]
                    [--count N]
"""

import argparse
import random
import string
import sys
import time

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

from resp4_client import Resp4Client

# Key prefixes to simulate different application domains
KEY_PREFIXES = ["user", "session", "cache", "counter", "config", "cart", "order"]


def setup_otel(jaeger_endpoint, service_name="valkey-otel-demo"):
    resource = Resource.create({
        "service.name": service_name,
        "service.version": "1.0.0",
    })
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=f"{jaeger_endpoint}/v1/traces")))
    trace.set_tracer_provider(provider)
    return trace.get_tracer("valkey-resp4-demo")


def inject_headers():
    """Get W3C traceparent from current span context."""
    carrier = {}
    TraceContextTextMapPropagator().inject(carrier)
    return carrier


def random_key():
    """Generate a random key like 'user:a3f2', 'cache:x9b1', etc."""
    prefix = random.choice(KEY_PREFIXES)
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{prefix}:{suffix}"


def random_value():
    """Generate a random value."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 32)))


def valkey_exec(client, tracer, *args):
    """Execute via OTEL.EXEC with RESP4 trace context propagation.

    The client sends traceparent as a RESP4 request header, so the server
    can correlate its execution to the client's trace and report:
      - Server-side execution duration (microseconds)
      - Sub-path latency breakdown (input-buffer-wait, blocked-wait, processing, output-buffer-wait)
      - Internal events (keyspace notifications, hook activity)

    Each call produces one trace:
      valkey SET (client)                  ← measures network RTT
        └── valkey.server SET              ← server-reported total duration
              ├── input-buffer-wait        ← time in query buffer
              ├── blocked-wait             ← time blocked/throttled
              ├── processing               ← actual command execution
              ├── output-buffer-wait       ← time in output buffer
              ├── hook: set key            ← keyspace notification
              └── hook: NEW_KEY key        ← new key created
    """
    cmd = args[0].upper()
    stmt = " ".join(str(a) for a in args)

    with tracer.start_as_current_span(
        f"valkey {cmd}",
        kind=trace.SpanKind.CLIENT,
        attributes={
            "db.system": "valkey",
            "db.operation": cmd,
            "db.statement": stmt,
            "server.address": client.host,
            "server.port": client.port,
        },
    ) as span:
        headers = inject_headers()
        result = client.command("OTEL.EXEC", *args, headers=headers)
        attrs = client.last_reply_attributes or {}
        dur = attrs.get("server-duration-us", 0)
        events = attrs.get("events", [])

        # Sub-path latencies from server (microseconds)
        input_buf_wait = attrs.get("input-buffer-wait-us", 0)
        blocked_wait = attrs.get("blocked-wait-us", 0)
        processing = attrs.get("processing-us", 0)
        output_buf_wait = attrs.get("output-buffer-wait-us", 0)
        server_start = attrs.get("server-start-us", 0)

        span.set_attribute("server.duration_us", dur if isinstance(dur, int) else 0)
        span.set_attribute("server.input_buffer_wait_us", input_buf_wait if isinstance(input_buf_wait, int) else 0)
        span.set_attribute("server.blocked_wait_us", blocked_wait if isinstance(blocked_wait, int) else 0)
        span.set_attribute("server.processing_us", processing if isinstance(processing, int) else 0)
        span.set_attribute("server.output_buffer_wait_us", output_buf_wait if isinstance(output_buf_wait, int) else 0)
        if isinstance(result, Exception):
            span.set_status(trace.StatusCode.ERROR, str(result))
        else:
            span.set_status(trace.StatusCode.OK)
        span.set_attribute("db.response", str(result)[:100])
        span.set_attribute("server.events_count", len(events) if isinstance(events, list) else 0)

        # Build server-side span and sub-path children using explicit
        # start_time / end_time derived from the server's timestamps.
        # This ensures the spans have real duration in the trace viewer
        # and share the same trace-id as the parent client span.
        #
        # We use tracer.start_span() (not start_as_current_span) so we
        # can set start_time, then manually end() with end_time.
        # Parent linkage: server_span parents to the current client span
        # via the implicit current context; sub-path spans parent to the
        # server_span via an explicit context we construct.

        server_start_ns = int(server_start) * 1000 if isinstance(server_start, int) and server_start > 0 else None
        server_dur_ns = int(dur) * 1000 if isinstance(dur, int) else 0

        if server_start_ns:
            server_end_ns = server_start_ns + server_dur_ns

            # Server span — parented to the current (client) span automatically
            server_span = tracer.start_span(
                f"valkey.server {cmd}",
                kind=trace.SpanKind.SERVER,
                start_time=server_start_ns,
                attributes={
                    "db.system": "valkey",
                    "db.operation": cmd,
                    "server.duration_us": dur if isinstance(dur, int) else 0,
                },
            )

            # Build a context with the server span as current, so sub-path
            # spans become its children (same trace-id, parent = server span).
            server_ctx = trace.set_span_in_context(server_span)

            # Sub-path latency spans tile sequentially within the server span
            cursor_ns = server_start_ns
            subpath_phases = [
                ("input-buffer-wait", input_buf_wait),
                ("blocked-wait", blocked_wait),
                ("processing", processing),
                ("output-buffer-wait", output_buf_wait),
            ]
            for phase_name, phase_us in subpath_phases:
                phase_us = phase_us if isinstance(phase_us, int) else 0
                phase_ns = phase_us * 1000
                if phase_ns > 0:
                    subpath_span = tracer.start_span(
                        f"valkey.subpath {phase_name}",
                        context=server_ctx,
                        kind=trace.SpanKind.INTERNAL,
                        start_time=cursor_ns,
                        attributes={
                            "subpath.phase": phase_name,
                            "subpath.duration_us": phase_us,
                        },
                    )
                    subpath_span.end(end_time=cursor_ns + phase_ns)
                cursor_ns += phase_ns

            # Hook events as children of the server span
            if isinstance(events, list):
                for ev in events:
                    if not isinstance(ev, dict):
                        continue
                    etype = ev.get('type', '?')
                    detail = ev.get('detail', '')
                    ts = ev.get('timestamp_ms', 0)

                    parts = detail.split(' ', 1) if detail else ['?']
                    ev_cmd = parts[0] if parts else '?'
                    ev_key = parts[1] if len(parts) > 1 else ''

                    if etype == 'new_key':
                        name = f"hook: NEW_KEY {ev_key}"
                    elif etype == 'key_overwrite':
                        name = f"hook: OVERWRITE {ev_key}"
                    elif etype == 'keyspace':
                        name = f"hook: {ev_cmd} {ev_key}"
                    else:
                        name = f"hook: {etype} {detail}"

                    ev_span = tracer.start_span(
                        name,
                        context=server_ctx,
                        kind=trace.SpanKind.INTERNAL,
                        attributes={
                            "event.type": etype,
                            "event.detail": detail,
                            "event.timestamp_ms": ts,
                        },
                    )
                    ev_span.end()

            server_span.end(end_time=server_end_ns)

        else:
            # No server timestamps available — fall back to simple span
            with tracer.start_as_current_span(
                f"valkey.server {cmd}",
                kind=trace.SpanKind.SERVER,
                attributes={
                    "db.system": "valkey",
                    "db.operation": cmd,
                },
            ):
                pass

        return result


def generate_traces(client, tracer, count):
    """Generate many traces with randomized keys and mixed commands."""
    keys_written = []

    print(f"\n→ Generating {count} traced commands with random keys...\n")

    for i in range(count):
        # Pick a random operation, weighted toward SET/GET/INCR
        op = random.choices(
            ["SET", "GET", "INCR", "DEL", "EXPIRE"],
            weights=[30, 25, 20, 10, 15],
            k=1,
        )[0]

        if op == "SET":
            key = random_key()
            val = random_value()
            result = valkey_exec(client, tracer, "SET", key, val)
            keys_written.append(key)
            print(f"  [{i+1:3d}/{count}] SET {key} -> {result}")

        elif op == "GET":
            # GET a key we've written, or a random one
            if keys_written and random.random() < 0.7:
                key = random.choice(keys_written)
            else:
                key = random_key()
            result = valkey_exec(client, tracer, "GET", key)
            print(f"  [{i+1:3d}/{count}] GET {key} -> {str(result)[:30]}")

        elif op == "INCR":
            key = f"counter:{random.choice(KEY_PREFIXES)}:hits"
            result = valkey_exec(client, tracer, "INCR", key)
            keys_written.append(key)
            print(f"  [{i+1:3d}/{count}] INCR {key} -> {result}")

        elif op == "DEL":
            if keys_written:
                key = keys_written.pop(random.randrange(len(keys_written)))
            else:
                key = random_key()
            result = valkey_exec(client, tracer, "DEL", key)
            print(f"  [{i+1:3d}/{count}] DEL {key} -> {result}")

        elif op == "EXPIRE":
            if keys_written:
                key = random.choice(keys_written)
            else:
                key = random_key()
            ttl = random.choice([60, 120, 300, 600, 3600])
            result = valkey_exec(client, tracer, "EXPIRE", key, str(ttl))
            print(f"  [{i+1:3d}/{count}] EXPIRE {key} {ttl}s -> {result}")

        # Small delay to spread traces over time for better visualization
        time.sleep(0.02)


def show_stats(client):
    print("\n" + "=" * 60)
    print("  Module Statistics (OTEL.STATS)")
    print("=" * 60)
    stats = client.command("OTEL.STATS")
    if isinstance(stats, dict):
        for k, v in stats.items():
            print(f"    {k}: {v}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6379)
    parser.add_argument("--jaeger-endpoint", default="http://localhost:4318")
    parser.add_argument("--count", type=int, default=50,
                        help="Number of traced commands to generate (default: 50)")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  RESP4 Distributed Tracing Demo                        ║")
    print("║                                                          ║")
    print("║  Generates many traces with random keys so you can      ║")
    print("║  explore query/filter capabilities in Jaeger/Grafana.   ║")
    print("║                                                          ║")
    print("║  Each command = 1 trace with client + server spans.     ║")
    print("╚══════════════════════════════════════════════════════════╝")

    tracer = setup_otel(args.jaeger_endpoint)

    print(f"\n→ Connecting to Valkey at {args.host}:{args.port} with RESP4...")
    client = Resp4Client(host=args.host, port=args.port)
    try:
        r = client.connect()
        print(f"  Connected! proto={r.get('proto')}, version={r.get('version')}")
    except Exception as e:
        print(f"\n✗ Connection failed: {e}")
        sys.exit(1)

    try:
        generate_traces(client, tracer, args.count)
        show_stats(client)

        print("\n→ Flushing traces...")
        trace.get_tracer_provider().force_flush()
        time.sleep(1)

        print(f"\n╔══════════════════════════════════════════════════════════╗")
        print(f"║  ✓ Done! {args.count} traces exported to Grafana/Jaeger          ║")
        print(f"║                                                          ║")
        print(f"║  Try these queries in Grafana Explore (Jaeger):          ║")
        print(f"║                                                          ║")
        print(f"║  • Service: valkey-otel-demo                             ║")
        print(f"║  • Operation: valkey SET / valkey GET / valkey INCR      ║")
        print(f"║  • Tag: db.operation=SET  or  db.statement=SET user:*    ║")
        print(f"║  • Min Duration: 1ms (find slow commands)                ║")
        print(f"╚══════════════════════════════════════════════════════════╝")

    finally:
        client.close()
        trace.get_tracer_provider().shutdown()


if __name__ == "__main__":
    main()
