# Distributed NCS cookbook

Forward log lines or scored threat events between two (or more) ArxSentinel
instances over a real network connection — no shared filesystem, no Redis, no
VPN beyond what the built-in transport already provides.

## What this is

ArxSentinel's Named Channel Switch (NCS) already lets one pipeline write
events into a named queue that another pipeline reads back — normally that
queue lives in the same process's memory. **Distributed NCS**
(`arx-core/pkg/transport`) extends the same queue abstraction across a
network: the queue's backend becomes a QUIC connection (TLS 1.3, Ed25519
node identity, TOFU peer pinning) to a **different node's** process instead
of a local channel. The rest of the pipeline — sinks, sources, detectors,
executors — is unaware anything crossed a network boundary.

```
   Node A (collector)                           Node B (detector)
   ┌─────────────────────────┐                  ┌─────────────────────────┐
   │ access.log               │                  │                           │
   │   │ tail                 │                  │                           │
   │   ▼                      │                  │                           │
   │ pipeline (raw_forward)   │   QUIC / TLS 1.3  │  sentinel source          │
   │   │ parse only,          │   Ed25519 + TOFU  │  (mode: raw)              │
   │   │ NO scoring           │ ───────────────▶  │    │                      │
   │   ▼                      │  queue: transport │    ▼                     │
   │ sentinel-threat sink     │  mode: send/recv  │  ordinary pipeline        │
   │  format: raw-line        │                   │  (real detector chain)   │
   │  queue: transport        │                   │    │                      │
   │  mode: send              │                   │    ▼                     │
   └─────────────────────────┘                   │  threats.log / executor  │
                                                   └─────────────────────────┘
```

## Why forward BEFORE scoring, not after

You can also forward already-scored `ThreatEvent`s between nodes (the
original in-process `sentinel-threat` sink / `sentinel` source pair, `mode`
omitted or `mode: threat`) — useful for centralising the *response* (one
node owns Cloudflare/MikroTik credentials, several edge nodes detect
locally and forward verdicts to it).

This recipe forwards RAW, unscored lines instead — useful when you want to
centralise the *detection*: one lightweight collector node per log source,
one detector node running the full scoring chain (and its own tuning,
whitelist, WAF rules) against everything, without needing the scorer's
tracker state replicated or shared across nodes.

## Files

| File | Role |
|------|------|
| [`collector.yaml`](collector.yaml) | Tails a local access log, `raw_forward: true`, forwards every parsed line to `edge-raw` via a transport-backed `sentinel-threat` sink (`queue.mode: send`). |
| [`detector.yaml`](detector.yaml) | Reads `edge-raw` via a transport-backed `sentinel` source (`mode: raw`, `queue.mode: recv`) into an ordinary pipeline — the real detector chain scores each forwarded entry. |

Both are self-contained: copy the one matching each node's role, fill in
the peer `host:port` placeholders, and run.

## Setup

1. **Pick two hosts** (or two ports on one host for testing) and decide
   which runs `collector.yaml` and which runs `detector.yaml`.
2. **Replace the peer placeholders**: `node-b.example.net:4097` in
   `collector.yaml` → the detector's real address; `node-a.example.net:4097`
   in `detector.yaml` → the collector's real address.
3. **`transport.identity` / `transport.known_nodes`** need a writable parent
   directory (e.g. `/etc/arxsentinel/`) — both files are created
   automatically on first start (Ed25519 keypair, empty TOFU pinning store).
   No manual key generation needed.
4. **Firewall**: open the configured `transport.listen` UDP port
   (`4097` in these examples) between the two nodes — this is QUIC, over UDP.
5. **Start order doesn't matter for correctness** (the transport redials
   automatically with backoff), but starting the detector first avoids the
   collector's first dial attempt failing and burning ~1s on the initial
   retry backoff.
6. **`edge-raw` must match exactly** on both sides — the collector's sink
   `name:` and the detector's source `addr: ncs://<name>` (via the
   `ncs://` prefix). A mismatch is not caught at config-validation time (the
   name is only meaningful once both nodes are running) — it shows up as a
   growing drop counter and a rate-limited WARN log on the detector side
   (`arx-core/pkg/transport/OPERATIONS.md` §4 documents the diagnosis
   procedure).

## Verifying it works

On the collector node, append a probe line to the tailed log a few times
(a single hit scores 25 against the `probe` detector's default weight —
under the default `AlertThreshold: 50`, so nothing would reach
`threats.log` yet; a handful of requests from the same IP is what a real
scan looks like, and is enough to cross the threshold):

```bash
for i in 1 2 3; do
  echo '203.0.113.77 - - [04/Jul/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.77"' >> /var/log/nginx/access.log
  sleep 0.5
done
```

Within a second or two, the detector node's `threats.log` should contain a
scored line for `203.0.113.77` — proof the line travelled collector →
transport → detector → detector chain → sink, unscored the whole way until
the very last step.

## Scaling beyond two nodes

- **Many collectors, one detector**: give each collector its own
  `transport.identity`/`listen`, and have each list the SAME detector host
  in `transport.peers`. Give each collector a DIFFERENT sink `name:`
  (`edge-raw-1`, `edge-raw-2`, ...) and add one matching `sentinel` input
  per name on the detector — one `queue_name` maps to exactly one registered
  reader (no fan-in on a single name).
- **One collector, many detectors**: not this pattern — a transport queue in
  `mode: send` targets exactly one `peer`. Use the scored-`ThreatEvent`
  variant (`mode: threat`, or omit `mode`) with per-severity routing at the
  collector's own detector chain instead, if you need fan-out.
