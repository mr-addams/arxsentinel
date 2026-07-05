# Distributed NCS — mixed-routing recipe

One detector process, two independent pipelines, two different executor
TYPES on two different nodes. Use this when different traffic sources need
different RESPONSE mechanisms — here: web-tier attacks get banned at the
nginx layer (a blocklist file), auth/network-tier attacks get banned at the
router layer (a MikroTik RouterOS address-list) — even though both are
scored by the same kind of detector chain.

```
 ┌───────────────────┐
 │  collector-web      │  queue_name: "edge-web"
 │  raw_forward: true  │───────────────────────────┐
 │  tails nginx log    │                             │
 └───────────────────┘                             ▼
                                        ┌─────────────────────────┐
                                        │        detector           │
                                        │                            │
                                        │  pipeline "web"  (own run) │
                                        │  pipeline "auth" (own run) │
                                        │                            │
                                        └─────────────────────────┘
 ┌───────────────────┐                             ▲
 │  collector-auth     │  queue_name: "edge-auth"    │
 │  raw_forward: true  │───────────────────────────┘
 │  tails auth log     │
 └───────────────────┘

 pipeline "web"  ──▶ queue_name: "scored-web"  ──▶  ┌───────────────────┐
                                                       │  nginx-executor     │
                                                       │  nginx blocklist    │
                                                       └─────────┬─────────┘
                                                                 ▼
                                       /etc/nginx/conf.d/arxsentinel_autoblock.list

 pipeline "auth" ──▶ queue_name: "scored-auth" ──▶  ┌───────────────────┐
                                                       │  mikrotik-executor  │
                                                       │  RouterOS REST API  │
                                                       └─────────┬─────────┘
                                                                 ▼
                                             RouterOS /ip/firewall/address-list
```

## Why two pipelines instead of one pipeline with two sinks

A pipeline's outputs all receive every event that pipeline scores — there is
no per-event conditional "send THIS threat to nginx, send THAT one to
MikroTik" inside a single pipeline. Routing by SOURCE (web traffic vs. auth
traffic) instead is what two separate pipelines buys you: each pipeline
scores its own traffic and forwards to its own executor, with its own
`queue_name` end to end. The routing decision is made once, at config time
(which pipeline this traffic entered through), not per-event at runtime.

If you need per-event conditional routing based on the SCORE or MODULES
that fired (not just the source), look at the WAF rule-engine's `tag:`
action (`cookbook/waf/README.md`) instead — tags can gate which detectors
run, but still flow to the SAME set of sinks for that pipeline.

## Files

| File | Role |
|------|------|
| [`collector-web.yaml`](collector-web.yaml) | Web-tier collector — feeds pipeline "web" via `edge-web` |
| [`collector-auth.yaml`](collector-auth.yaml) | Auth-tier collector — feeds pipeline "auth" via `edge-auth` |
| [`detector.yaml`](detector.yaml) | ONE process, two pipelines, two independent forwarding targets |
| [`nginx-executor.yaml`](nginx-executor.yaml) | Consumes `scored-web` only |
| [`mikrotik-executor.yaml`](mikrotik-executor.yaml) | Consumes `scored-auth` only |

## Setup

1. Replace every `*.example.net` placeholder with real host:port values.
2. `mikrotik-executor.yaml` needs real RouterOS REST API credentials
   (`host`/`username`/`password`) — see `config.reference.yaml`'s `transport:`
   section and `pkg/executorplugins/mikrotik`'s own docs for `tls_verify`/
   `ca_file` if your device uses an internal CA.
3. `transport.identity`/`known_nodes` need a writable parent directory on
   every node — generated automatically on first start.
4. `transport.pairing_secret` must be the SAME value on every node — both
   collectors, the detector, AND both executors (recv-only nodes need it
   too, not just ones with `peers:`). Replace the
   `CHANGE-ME-shared-mesh-secret` placeholder everywhere; see the top-level
   `cookbook/distributed-ncs/README.md` Setup step 4 for how to generate
   and exchange it.
5. Add a third (fourth, ...) pipeline/collector/executor triple the same
   way if you have more than two traffic classes needing different
   responses — nothing here caps it at two.

## Verifying it works — and that routes don't cross

Append a probe line 3 times to the web collector's log, then to the auth
collector's log (same threshold reasoning as the aggregation recipe — a
single hit scores 25, under the default `alert_threshold: 50`):

```bash
for i in 1 2 3; do
  echo '203.0.113.21 - - [04/Jul/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.21"' >> /var/log/nginx/access.log
  sleep 0.5
done
for i in 1 2 3; do
  echo '203.0.113.22 - - [04/Jul/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.22"' >> /var/log/auth-service/access.log
  sleep 0.5
done
```

- `203.0.113.21` should appear in the nginx executor's blocklist file — and
  NOT in the RouterOS address-list.
- `203.0.113.22` should appear in the RouterOS address-list — and NOT in the
  nginx blocklist file.

That cross-check (each IP reaches ONLY its intended executor) is what
proves mixed routing is genuinely independent per pipeline, not a fan-out
that happens to look selective.

## Tested by

This exact topology is validated end to end, with real containers on a real
Docker network (including a real RouterOS REST API mock for the MikroTik
leg), by
[`tests/integration/distributed-ncs/`](../../../tests/integration/distributed-ncs/README.md)
(`docker-compose.mixed-routing.yml`) — run in CI on every PR into `dev`.
