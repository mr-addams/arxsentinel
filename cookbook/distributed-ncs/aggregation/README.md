# Distributed NCS — aggregation recipe

Three collector nodes, one detector, one executor: many-to-one fan-in onto a
single detection point. Use this when you have several log sources (a web
tier, an API gateway, an auth service — anything with its own access log)
and want ONE shared detector process to score all of them consistently,
without replicating tracker/whitelist/detector configuration per source.

```
 ┌──────────────────────┐
 │ collector-nginx-edge  │──┐
 │ raw_forward: true     │  │
 │ tails /var/log/nginx/ │  │
 └──────────────────────┘  │
                            │        queue_name: "edge-raw"
 ┌──────────────────────┐  │        (SAME name from all three —
 │ collector-api-gateway │──┼───────▶ one inbound registration on
 │ raw_forward: true     │  │        the detector accepts all of them)
 │ tails api-gateway log │  │                    │
 └──────────────────────┘  │                    ▼
                            │         ┌─────────────────────┐
 ┌──────────────────────┐  │         │      detector        │
 │ collector-auth-service│──┘         │  real detector chain │
 │ raw_forward: true     │            │  (probe/bruteforce/  │
 │ tails auth-service log│            │   rate/badbot/...)   │
 └──────────────────────┘            └──────────┬───────────┘
                                                  │
                                     queue_name: "scored-events"
                                     (DIFFERENT name — routes the
                                      SCORED verdict onward)
                                                  ▼
                                       ┌─────────────────────┐
                                       │       executor        │
                                       │  nginx blocklist      │
                                       │  executor plugin      │
                                       └──────────┬───────────┘
                                                  ▼
                                    /etc/nginx/conf.d/arxsentinel_autoblock.list
```

## Why one shared detector instead of one detector per collector

- **Consistent policy.** One `scoring:`/`detectors:`/`whitelist:` configuration
  applies to every source — no drift between "the web tier's probe threshold"
  and "the API gateway's probe threshold" because there is only one.
- **Shared IP reputation.** An attacker probing the web tier AND the API
  gateway from the same IP accumulates score against ONE tracker, crossing
  `alert_threshold` faster than if each source scored independently — this
  is the whole point of aggregation, not an incidental side effect.
- **One place to tune.** Adding an 8th detector, adjusting `ban_threshold`,
  or updating the whitelist happens once, not N times across N collector
  configs.

## Files

| File | Role |
|------|------|
| [`collector-nginx-edge.yaml`](collector-nginx-edge.yaml) | Collector 1 — nginx access log |
| [`collector-api-gateway.yaml`](collector-api-gateway.yaml) | Collector 2 — API gateway log |
| [`collector-auth-service.yaml`](collector-auth-service.yaml) | Collector 3 — auth service log |
| [`detector.yaml`](detector.yaml) | Receives all three under `edge-raw`, scores for real, forwards under `scored-events` |
| [`executor.yaml`](executor.yaml) | nginx blocklist executor — the response |

## Setup

1. Copy the collector configs matching your real log sources (add a fourth,
   fifth, ... collector the same way — nothing here is capped at three; each
   new collector just needs a unique `identity`/`known_nodes` pair and the
   SAME `edge-raw` sink name and detector peer).
2. Replace every `*.example.net` placeholder with real host:port values.
3. `transport.identity`/`known_nodes` need a writable parent directory on
   each node — both files are generated automatically on first start.
4. Point `executor.yaml`'s `list_file`/`reload_cmd` at your real nginx
   blocklist path and reload command (or swap the executor `type:` for
   `mikrotik` / `cloudflare` — see the mixed-routing recipe for using a
   different executor type).

## Verifying it works

On any collector, append the same probe line 3 times (a single hit scores
25 against the `probe` detector's default weight — under the default
`scoring.alert_threshold: 50` — three hits from the same IP is what a real
scan looks like and crosses the threshold):

```bash
for i in 1 2 3; do
  echo '203.0.113.11 - - [04/Jul/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.11"' >> /var/log/nginx/access.log
  sleep 0.5
done
```

Within a second or two, the executor node's nginx blocklist file should
contain `203.0.113.11`. Repeat against the other two collectors' logs with
different IPs — all should reach the same blocklist file, proving the
aggregation (one inbound queue registration serving three independent
senders).

## Tested by

This exact topology (3 collectors → 1 detector → 1 executor) is validated
end to end, with real containers on a real Docker network, by
[`tests/integration/distributed-ncs/`](../../../tests/integration/distributed-ncs/README.md)
(`docker-compose.aggregation.yml`) — run in CI on every PR into `dev`.
