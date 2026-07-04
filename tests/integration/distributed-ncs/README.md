# Distributed NCS — container integration tests

Two fully-containerized multi-node scenarios exercising Distributed NCS
(arx-core/pkg/transport): every node in both scenarios runs the SAME
production image (`deploy/container/docker/Dockerfile`) on its own isolated
Docker network, resolving peers by Compose service name — the closest this
test suite gets to a real multi-host deployment without provisioning real
hosts.

This is the container-level counterpart to the fast Go subprocess tests in
`cmd/arxsentinel/distributed_ncs_*_test.go` (`-tags integration`): those
prove the wiring quickly on every change (a few seconds, no Docker); this
proves the actual product image behaves the same way when nodes are
genuinely isolated processes on a Docker-managed network rather than
subprocesses sharing one host's loopback interface.

## Run

```bash
bash tests/integration/distributed-ncs/run.sh
```

Runs both scenarios sequentially, prints `PASS`/`FAIL` lines (same
convention as `tests/integration/verify.sh`), tears down containers and
temp data on exit (including on failure — `trap cleanup EXIT`).

## Scenario 1 — aggregation (3 collectors → 1 detector → 1 executor)

```
collector-nginx-edge  ─┐
collector-api-gateway ─┼──▶ "edge-raw" ──▶ detector ──▶ "scored-events" ──▶ executor ──▶ blocklist.conf
collector-auth-service─┘
```

`docker-compose.aggregation.yml` — each collector `raw_forward`s parsed
(unscored) log lines onto the SAME `edge-raw` queue name on the detector;
the detector's real detector chain scores them and forwards verdicts under
a DIFFERENT queue name (`scored-events`) to the executor node, which runs
the `nginx` blocklist executor (writes a plain deny-list file, no external
dependency).

Proves: many-to-one fan-in is a property of the receiving side's single
`RegisterInboundQueue` call, not of how many remote peers dial in.

## Scenario 2 — mixed-routing (2 collectors → 1 detector, 2 pipelines → 2 executors)

```
collector-web  ──▶ "edge-web"  ──▶ detector pipeline "web"  ──▶ "scored-web"  ──▶ nginx-executor    ──▶ blocklist.conf
collector-auth ──▶ "edge-auth" ──▶ detector pipeline "auth" ──▶ "scored-auth" ──▶ mikrotik-executor ──▶ RouterOS API (ros-api-mock)
```

`docker-compose.mixed-routing.yml` — one detector process runs TWO
independent pipelines, each receiving from its own collector and routing to
a DIFFERENT executor TYPE on a different node. Reuses `ros-api-mock`
verbatim (same Dockerfile as `../docker-compose.yml`'s existing
`ros-executor` test) on host port `8095` (distinct from the main compose's
`8093`, so both can run concurrently without a port clash).

Proves: the two forwarding decisions are genuinely independent — the
cross-checks (`no-leak-auth-in-nginx`, `no-leak-web-in-mikrotik`) assert
each IP reaches ONLY its intended executor, not both.

## Why a single probe line isn't enough

Both scenarios append the same wp-login.php probe line 3 times per IP,
not once. A single hit scores 25 against the `probe` detector's default
per-hit weight — under the default `scoring.alert_threshold: 50` — so
nothing would reach the executor after only one request. Three hits from
the same IP (what a real scan looks like) is what crosses the threshold;
this was found empirically while writing the equivalent cookbook example
(`cookbook/distributed-ncs/README.md`) and both test suites encode the
same fix.

## Layout

| File | Role |
|------|------|
| `configs/agg-*.yaml` | Node configs for Scenario 1 |
| `configs/mixed-*.yaml` | Node configs for Scenario 2 |
| `docker-compose.aggregation.yml` | Scenario 1 topology |
| `docker-compose.mixed-routing.yml` | Scenario 2 topology (+ `ros-api-mock`) |
| `run.sh` | Orchestrates both scenarios, injects traffic, verifies, tears down |
| `data/` | Runtime-only bind-mount target (access.log, blocklist.conf, ...) — created and destroyed by `run.sh`, never committed (`.gitignore`) |

## Notes on the container environment

- Each node's `transport.identity`/`known_nodes` live at `/tmp/node.key` /
  `/tmp/known-nodes` inside the container — the distroless image's writable
  overlay handles this without a bind mount (Ed25519 key generated fresh on
  first start; TOFU-pinned on first contact between peers, same as any real
  deployment).
- Collectors' tailed `access.log` and executors' output files (`blocklist.conf`,
  `idle-out.log`) ARE bind-mounted (`./data/...:/data`) so `run.sh` can append
  traffic and read results directly from the host without `docker exec` — the
  base image is `distroless/static-debian12:nonroot` and has no shell to exec
  into.
- Pure-executor nodes (`executor`, `nginx-executor`, `mikrotik-executor`)
  carry a minimal unused `idle` stream/pipeline purely because `LoadConfig`
  always wants at least one stream — it never receives any traffic; the
  executor's real input is its `executors:` entry, which consumes from the
  Distributed NCS queue directly.
