# Distributed Security Event Processing

> 🌐 [Українською](DISTRIBUTED.uk.md) | [По-русски](DISTRIBUTED.ru.md)

One ArxSentinel binary. Any number of nodes. Collect security events wherever
traffic lands, score them wherever compute lives, enforce wherever it hurts the
attacker most — with an end-to-end encrypted, mutually authenticated event mesh
built into the engine itself. No Redis, no Kafka, no log shipper, no VPN, no
central server.

This guide is for operators: what the distributed pipeline is, how the pieces
fit, and five typical infrastructures you can copy today. Every topology shown
here is validated in CI by real multi-container tests
([`tests/integration/distributed-ncs/`](../tests/integration/distributed-ncs/README.md)) —
the diagrams are not aspirational.

---

## Table of contents

- [The idea in 60 seconds](#the-idea-in-60-seconds)
- [Three roles, one binary](#three-roles-one-binary)
- [What travels over the wire](#what-travels-over-the-wire)
- [Transport security model](#transport-security-model)
- [Configuration surface](#configuration-surface)
- [How this compares](#how-this-compares)
- [Topology 1 — Two nodes: collect here, detect there](#topology-1--two-nodes-collect-here-detect-there)
- [Topology 2 — Edge fleet: many collectors, one brain](#topology-2--edge-fleet-many-collectors-one-brain)
- [Topology 3 — Mixed routing: different sources, different responses](#topology-3--mixed-routing-different-sources-different-responses)
- [Topology 4 — Homelab: Pi collectors, NAS brain, router bans](#topology-4--homelab-pi-collectors-nas-brain-router-bans)
- [Topology 5 — Enterprise: edge detection + SIEM feed](#topology-5--enterprise-edge-detection--siem-feed)
- [Operations](#operations)
- [Verifying a deployment](#verifying-a-deployment)

---

## The idea in 60 seconds

ArxSentinel has always had an internal event bus — the **Named Channel Switch
(NCS)**: one pipeline pushes events into a named queue, another pipeline (or an
executor) reads them back. Until now that queue lived inside one process.

**Distributed NCS** extends the same queue across the network. Add a
`queue: {type: transport}` block to a sink or source, and the named queue's
backend becomes a QUIC connection to another node — same config shape, same
pipeline semantics, but the two ends now run on different machines:

```
      NODE A                                       NODE B
 ┌────────────────┐                          ┌────────────────┐
 │ pipeline        │    queue "edge-raw"      │ pipeline        │
 │   sink ─────────┼── QUIC / TLS 1.3 ──────▶│   source        │
 │                 │    Ed25519 + TOFU        │                 │
 └────────────────┘                          └────────────────┘
```

The rest of the engine — parsers, detectors, scorer, whitelist, executors —
does not know or care that a network hop happened. That is the design rule
that makes every topology below a pure configuration exercise.

## Three roles, one binary

There are no special "agent", "server", or "manager" builds. Every node runs
the same binary and the same config format; its **role** is just which parts of
the pipeline you enable:

| Role | What it does | Key config |
|------|--------------|-----------|
| **Collector** | Tails/receives logs, parses them, forwards **unscored** entries. Cheap: no tracker state, no detector work. Runs happily on a Raspberry Pi or a 128 MB VPS. | `raw_forward: true` + transport sink (`mode: send`) |
| **Detector** | Receives entries from any number of collectors, runs the full detector chain (8 behavioural detectors, WAF rules, whitelist, scoring), forwards **scored verdicts** onward. One place to tune thresholds for the whole fleet. | transport source (`mode: raw`, queue `mode: recv`) + transport sink for verdicts |
| **Responder** | Receives scored verdicts and enforces: nginx blocklist, MikroTik address-list, OpenWrt ipset, Cloudflare WAF, or your own exec+JSON executor. Lives next to the enforcement point — credentials never leave that node. | `executors:` with a transport-backed source (queue `mode: recv`) |

Roles combine freely: a node can detect **and** respond, collect **and**
detect locally while forwarding only high-severity verdicts, and so on. A
2-node deployment and a 20-node deployment use the same three building blocks.

## What travels over the wire

Two payload shapes, chosen per queue:

**Raw entries** (`raw_forward: true` + `format: raw-line` on the sending sink,
`mode: raw` on the receiving source). The collector parses the line into a
structured entry (IP, method, path, status, UA, timestamp) but does **not**
score it. The detector node scores it exactly as if the line had been read
from a local file. Use when you want centralized detection with one shared
scoring policy and one shared per-IP state.

**Scored verdicts** (the default `sentinel-threat` payload — no extra flags).
A full ThreatEvent: IP, score, level, which detectors fired, human-readable
reason. Use when detection already happened and you only need to move the
verdict to where enforcement (or storage, or a SIEM) lives.

A single deployment typically uses both: raw entries flow inward from the
edge, scored verdicts flow outward to responders.

## Transport security model

The mesh is built on `arx-core/pkg/transport`:

- **QUIC over UDP** — one port per node (default `4097`), multiplexed streams,
  automatic reconnect with exponential backoff. Survives flaky links.
- **TLS 1.3 always** — there is no plaintext mode to misconfigure.
- **Ed25519 node identity** — each node generates a keypair on first start
  (`transport.identity`). No CA, no certificate expiry calendar.
- **Mesh-wide admission secret** (`transport.pairing_secret`) — the actual
  gate against strangers: an unrecognised node must prove knowledge of this
  shared, out-of-band-exchanged secret before it is ever trusted. Without
  it, TOFU alone only answers "same key as last time" — it says nothing
  about who authorized that key to join in the first place. Every node in
  the mesh sets the SAME value.
- **TOFU pinning + self-healing rotation** (`transport.known_nodes`) — once
  admitted, the peer's Ed25519 fingerprint is pinned; a second, independent
  secret then auto-rotates after every session (no operator action), so a
  historically-leaked config copy stops matching over time. For an even
  stricter per-peer guarantee on top of the mesh-wide secret, pre-pin an
  expected fingerprint in config (`peers[].fingerprint: "sha256:..."`) —
  checked before either the pairing secret or TOFU gets a say.
- **Mutual authentication** — both sides prove key ownership via a signed
  challenge before any event flows. A stranger who finds your UDP port
  without the mesh's `pairing_secret` gets nothing.

What it is **not**: a message broker with delivery guarantees. If a peer is
down, frames queued for it are dropped and counted (visible in logs and drop
counters) — the same "loss on overflow" posture as the in-memory queue. For
survive-restart buffering, compose with a bbolt queue on the receiving side
(see `arx-core/pkg/transport/OPERATIONS.md`).

## Configuration surface

Everything lives in the YAML you already know. Full reference:
[`cookbook/config.reference.yaml`](../cookbook/config.reference.yaml).

```yaml
# 1. Enable the mesh on every participating node — pairing_secret is the
#    SAME value everywhere, including nodes with no peers: of their own
#    (a recv-only node still checks its own secret against inbound callers).
transport:
  enabled: true
  identity: /etc/arxsentinel/node.key        # auto-generated on first start
  known_nodes: /etc/arxsentinel/known-nodes  # TOFU pin store + rotating secret
  listen: "0.0.0.0:4097"                     # QUIC/UDP
  pairing_secret: "..."                      # mesh-wide, exchanged out-of-band
  peers:                                     # outbound dial targets only;
    - host: "detector.example.net:4097"      # inbound connections are accepted
      fingerprint: ""                        # and TOFU-pinned regardless

# 2. Sending side — any sentinel-threat sink can point at a peer
outputs:
  - type: sentinel-threat
    name: edge-raw            # queue name — must match the receiver exactly
    format: raw-line          # only for raw entries; omit for scored verdicts
    queue:
      type: transport
      mode: send
      peer: "detector.example.net:4097"

# 3. Receiving side — a sentinel source or an executor source
inputs:
  - type: sentinel
    addr: ncs://edge-raw      # same queue name
    mode: raw                 # decode raw entries; omit for scored verdicts
    queue:
      type: transport
      mode: recv
```

`arxsentinel validate --config ...` checks the wiring statically on each node:
transport-backed queues require `transport.enabled`, send-mode queues require a
known peer, and cross-node queues are exempt from local reader/writer checks.

## How this compares

Distributed log-based defence is not new as a concept — CrowdSec's
agent/LAPI/bouncer model and Wazuh's agent/manager model both exist and work.
What is different here is the *shape* of the architecture:

| | CrowdSec | Wazuh / OSSEC | ArxSentinel |
|---|---|---|---|
| **Topology** | Hub-and-spoke: central LAPI (HTTP REST + a required database) | Agent → manager (full platform: manager, indexer, dashboard) | Symmetric peer mesh — no central server, no database |
| **Components** | Agent + LAPI + separate bouncer binaries per enforcement point | Manager stack + agents | One ~12 MB binary; the role (collector / detector / responder) is just YAML |
| **What crosses the network** | Alerts and decisions only — raw logs need a separate shipper (syslog, vector) to centralize detection | Agent events to the manager | Raw parsed entries **and** scored verdicts, over the same built-in transport |
| **Delivery model** | Pull: bouncers poll the LAPI for decisions | Push: agent → manager | Push over the QUIC mesh, automatic redial |
| **Authentication** | API keys / TLS certificates | Pre-shared keys | Ed25519 node identity + TOFU pinning, mutual — like SSH |
| **Footprint per node** | Agent + bouncer(s); LAPI node needs a DB | Manager measured in GB of RAM | ~12 MB static binary everywhere, incl. arm/v7 and riscv64 |

Both alternatives are solid projects with their own strengths (CrowdSec's
community blocklists in particular have no equivalent here). The claim this
guide makes is narrower and precise: **no other tool in this class ships a
peer-to-peer security event mesh inside the engine itself** — same binary on
every node, no agent-server hierarchy, no separate enforcement components,
and raw-entry forwarding to a remote detector over the engine's own
transport, which none of the above offer at all.

---

## Topology 1 — Two nodes: collect here, detect there

The minimal distributed setup and the base pattern for everything else. A web
server keeps a tiny collector next to its logs; all detection logic, tuning,
and state live on a second machine.

```
   web server (VPS, 12 MB for the collector)        detection box
 ┌──────────────────────────────┐            ┌──────────────────────────────┐
 │ nginx → access.log            │            │                                │
 │   │ tail                      │   QUIC     │  sentinel source (mode: raw)   │
 │   ▼                           │  ───────▶  │    │                           │
 │ collector pipeline            │ "edge-raw" │    ▼                           │
 │  parse only — raw_forward     │            │  8 detectors · WAF · whitelist │
 │  sink: transport, mode: send  │            │  scorer → threats.log / bans   │
 └──────────────────────────────┘            └──────────────────────────────┘
```

**When**: you don't want detector CPU/state on the web server; you want to
tune scoring in one place; you want the web box to stay minimal.

**Recipe**: [`cookbook/distributed-ncs/`](../cookbook/distributed-ncs/README.md)
(`collector.yaml` + `detector.yaml`, full walkthrough included).

## Topology 2 — Edge fleet: many collectors, one brain

Aggregation: any number of collectors forward onto the **same queue name**;
the detector's single registration accepts them all. One scoring policy, one
whitelist, one shared per-IP state — an attacker probing three of your
services accumulates one combined score and crosses the ban threshold sooner
than any single service would have caught alone.

```
 ┌────────────────┐
 │ nginx edge      │──┐
 └────────────────┘  │
 ┌────────────────┐  │  queue "edge-raw"    ┌──────────────┐   queue          ┌──────────────┐
 │ API gateway     │──┼───────────────────▶│   detector    │─────────────────▶│  responder    │
 └────────────────┘  │  (same name from    │  full chain,  │ "scored-events"  │ nginx executor │
 ┌────────────────┐  │   every collector)  │  shared state │                  │ blocklist file │
 │ auth service    │──┘                     └──────────────┘                  └──────────────┘
 └────────────────┘
```

**When**: heterogeneous sources (web tier + API + auth), cross-service attack
correlation, "add a collector" should be a 30-line YAML, not an infra project.

**Recipe**: [`cookbook/distributed-ncs/aggregation/`](../cookbook/distributed-ncs/aggregation/README.md).
**CI proof**: `docker-compose.aggregation.yml` — 5 real containers, every PR.

## Topology 3 — Mixed routing: different sources, different responses

One detector process, multiple pipelines — each pipeline receives its own
source's traffic and forwards verdicts to its own responder. Web-tier attacks
get banned at the web layer; auth/network attacks get banned at the router.
The routing decision is which pipeline the traffic entered — made at config
time, zero per-event routing logic.

```
 ┌────────────────┐  "edge-web"         ┌──────────────────┐  "scored-web"     ┌─────────────────┐
 │ collector-web  │────────────────────▶│ pipeline "web"   │──────────────────▶│ nginx responder │
 └────────────────┘                     │                  │                   │ blocklist file  │
 ┌────────────────┐  "edge-auth"        │     detector     │                   └─────────────────┘
 │ collector-auth │────────────────────▶│ pipeline "auth"  │  "scored-auth"    ┌──────────────┐
 └────────────────┘                     │                  │──────────────────▶│ MikroTik     │
                                        └──────────────────┘                   │ address-list │
                                                                               └──────────────┘
```

**When**: different traffic classes need different enforcement mechanisms or
different TTL/severity policies, but you want one detection box.

**Recipe**: [`cookbook/distributed-ncs/mixed-routing/`](../cookbook/distributed-ncs/mixed-routing/README.md).
**CI proof**: `docker-compose.mixed-routing.yml` — includes a real RouterOS
API mock and cross-checks that verdicts never leak between routes.

## Topology 4 — Homelab: Pi collectors, NAS brain, router bans

The whole fleet costs you ~40 MB of RAM total. Collectors run anywhere a
log is written — including arm/v7 and riscv64 boards. The brain runs on
whatever is always-on (NAS, mini-PC). Enforcement happens at your MikroTik —
attackers are dropped at the network edge before they touch any service.

```
 ┌───────────────────────────┐
 │ Raspberry Pi · proxy logs │──┐
 └───────────────────────────┘  │             ┌────────────────────┐               ┌────────────────────┐
 ┌───────────────────────────┐  │   "edge-raw"│   NAS / mini-PC    │  "scored"     │ MikroTik executor  │
 │ VPS · public web logs     │──┼────────────▶│ detector: 8 chains │──────────────▶│ (also on the NAS — │
 └───────────────────────────┘  │             │ + WAF + whitelist  │               │ RouterOS creds     │
 ┌───────────────────────────┐  │             └────────────────────┘               │ never leave home)  │
 │ NAS · local service logs  │──┘                                                  └────────────────────┘
 └───────────────────────────┘                                                                ▼
                                                                                  /ip/firewall/address-list
                                                                                   → dropped at the router
```

**When**: several boxes, one operator, zero appetite for running Kafka at
home. The transport is the VPN — the VPS leg is already TLS 1.3 encrypted
and pinned, so the public collector needs no tunnel back home. Only the
detector's UDP port must be reachable from the VPS (port-forward one UDP
port on the router).

**Start from**: Topology 2's recipe with one collector per box; swap the
responder executor for `type: mikrotik`
([`cookbook/mikrotik/`](../cookbook/mikrotik/) has the executor config).

## Topology 5 — Enterprise: edge detection + SIEM feed

Push detection to where traffic lands (branch offices, edge PoPs, DMZ
segments) and stream **structured, pre-scored events** — not gigabytes of raw
logs — into the corporate stack. Every node can emit both shapes at once:

- **Raw normalized entries** — every parsed request as structured JSON
  (`format: raw-line`, or a local `json` file/stdout sink): full-fidelity
  feed for threat hunting, forensics, and models that want everything.
- **Scored verdicts** — only what crossed the threshold, with score,
  detector list, and reason attached: the alert-grade feed your SOC actually
  reads, at a fraction of the ingest volume.

```
 ┌───────────────────────────┐  "edge-*" · QUIC     ┌───────────────────────────┐             ┌──────────────────┐
 │ collector · branch office │─────────────────────▶│     detection cluster     │  exec+JSON  │ SIEM / data lake │
 └───────────────────────────┘                      │   (per-site or central)   │────────────▶│ Splunk · Elastic │
                                                    │ raw JSON + scored ──────▶ │             │ QRadar · custom  │
 ┌───────────────────────────┐                      │                           │             └──────────────────┘
 │ collector · DMZ           │─────────────────────▶│ scored verdicts ────────▶ │             ┌───────────────────┐
 └───────────────────────────┘                      │                           │────────────▶│ enforcement       │
                                                    └───────────────────────────┘  QUIC mesh  │ CF WAF · MikroTik │
                                                                                              │ nginx · exec+JSON │
                                                                                              └───────────────────┘
```

Key properties for a corporate evaluation:

- **Ingest cost control.** Pre-filtering at the edge means the SIEM bill is
  driven by *threats*, not by *traffic*. Flip one sink to `raw-line` when an
  investigation needs the full stream — per pipeline, per site.
- **No inbound holes.** Collectors dial **out** to the detector; branch
  firewalls need zero inbound rules. Enforcement credentials (Cloudflare
  tokens, RouterOS passwords) live only on responder nodes.
- **Uniform agent.** The same ~12 MB static binary on every node — amd64,
  arm64, arm/v7, riscv64, i386, Linux and FreeBSD — one package to certify,
  one config format to review.
- **Audit-friendly.** `arxsentinel validate` proves the wiring offline;
  every topology in this guide is exercised by CI with real containers on
  every merge.

**Today's SIEM paths**: `exec+JSON` sink (any script/binary — HEC uploader,
Kafka producer, S3 writer), `file` sink in JSON format (picked up by any
existing forwarder), `stdout` JSON (container log pipelines). Native Splunk
HEC / Loki / Datadog sinks are on the [roadmap](https://mr-addams.github.io/arxsentinel/#roadmap).

## Operations

- **Start order**: irrelevant for correctness — dialers redial with backoff
  (1s → 30s, jittered). Starting receivers first just avoids the first-attempt
  backoff hit.
- **Queue names must match exactly** on both ends (`name:` on the sink,
  `ncs://<name>` on the source). A mismatch is not a startup error (the name
  only becomes meaningful when both nodes are up) — it surfaces as a growing
  drop counter and a rate-limited WARN on the receiver. Diagnosis procedure:
  `arx-core/pkg/transport/OPERATIONS.md` §4.
- **Firewall**: one UDP port per node (default `4097`), only in the
  collector→detector / detector→responder direction of each dial.
- **Key rotation / compromised node**: remove the node's line from every
  peer's `known_nodes` file, delete the node's `identity` file, restart — a
  fresh keypair is generated and re-pinned on next contact (it will need to
  pass the `pairing_secret` gate again, same as any new node). Pre-pinned
  fingerprints in config must be updated too.
- **The pairing-secret ratchet is automatic** — no operator action needed
  in normal operation; it rotates itself after every successful session. If
  you suspect the `pairing_secret` VALUE itself was exposed (not a single
  node's identity, the shared mesh secret), rotate it explicitly: generate
  a new one, update it on every node, restart all of them together (a node
  still on the old value cannot pass admission with nodes already on the
  new one).
- **Failure semantics**: a downed peer drops (and counts) frames sent to it;
  reconnection is automatic. Detection state lives on the detector, so a
  collector restart loses nothing but the lines written during the outage —
  the same window a `tail -F` restart would lose locally.

## Verifying a deployment

Append a probe burst to any collector's watched log (three hits — one hit
scores 25 against the default `probe` weight, under the default
`alert_threshold: 50`; a real scanner never sends just one request):

```bash
for i in 1 2 3; do
  echo '203.0.113.77 - - [04/Jul/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.77"' >> /var/log/nginx/access.log
  sleep 0.5
done
```

Within seconds the verdict should appear at the end of your chain — the
responder's blocklist file, the router's address-list, the SIEM index. If it
does not: check the receiver's log for unknown-queue WARNs (name mismatch),
and both nodes' logs for `[TRANSPORT]` lines confirming the QUIC session.

---

*The distributed pipeline shipped with arx-core v0.5.0/v0.6.0 and is covered
by three test layers: unit tests, in-process integration tests, and the
multi-container CI suite in
[`tests/integration/distributed-ncs/`](../tests/integration/distributed-ncs/README.md).*
