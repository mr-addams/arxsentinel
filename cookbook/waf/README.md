# WAF cookbook

The WAF processor evaluates user-authored rules (boolean expressions over the
`http.*` namespace) against every event *before* the detector chain runs —
high-confidence attacks are gated out at line rate, never reaching scoring state.

## Two-pass evaluation

```
   Event in (nginx log / CF Logpush / syslog)
        |
        v
   +----------------+
   |  pass → gate   |   <-- WAF rule engine (first-match-wins)
   +----------------+
        |
        | event gated (drop) ─────► short-circuits pipeline
        |
        | event tagged (tag)  ─────► Level=THREAT:<rule_name>, flows on
        |
        | event passes (pass) ─────► flows on as INFO
        v
   +----------------+
   |  detector chain|   <-- scoring / ban logic
   +----------------+
        |
        v
   Executor (file sink, Cloudflare, etc.)
```

`pass` rules short-circuit other rules in the same stream (an explicit
allowlist entry wins over a later drop). `tag` rules mark an event with the
matched rule name and let it continue to scoring. `drop` rules stop the event
from reaching downstream stages.

## Recipes

| File | Demonstrates |
|------|--------------|
| [`waf-nginx.yaml`](waf-nginx.yaml) | Canonical recipe for a standalone nginx reverse proxy. `pass_healthcheck` → `block_sql_injection` → `block_path_traversal` → `block_scanner_ua` → `tag_4xx_flood`. Pass rules first, then high-confidence drops, then tag. |
| [`waf-cf-logpush.yaml`](waf-cf-logpush.yaml) | WAF recipe for Cloudflare Logpush ingestion. Cloudflare-specific notes for `http.real_ip` / `http.user_agent` / `http.bytes_sent`. Adds a `sentinel-threat` sink that forwards THREAT events to the Cloudflare IP Lists executor. |
| [`waf-custom-fields.yaml`](waf-custom-fields.yaml) | How to extend the field schema with a custom `http.tls_version` field — two Go changes (manifest Produces + resolver resolveHTTP case), no `ruleset.go` edit. Drop legacy TLS 1.0 / 1.1 at line rate. |
| [`waf-multi-profile.yaml`](waf-multi-profile.yaml) | Two streams, two ruleset profiles: `strict` for admin/API surface (broad patterns, zero tolerance) and `permissive` for public surface (high-confidence patterns only). Per-stream executors with different TTLs. |

Each YAML is self-contained: copy the `streams`, `processors:`, `scoring`,
`detectors`, `whitelist` (and optionally `executors`) blocks into your own
config and adjust the paths / tokens for your environment.

## How to use

Pick a recipe that matches your deployment. Drop the `processors:` block into
one of your streams:

```yaml
streams:
  - name: waf-gate
    inputs:
      - type: file
        path: /var/log/nginx/access.log
        parser: combined
    processors:
      - plugin: waf
        params:
          waf_config:
            rules:
              # ... paste rules here ...
outputs:
  - type: file
    path: /var/log/arxsentinel/threats.log
    format: fail2ban
```

The WAF processor sits between the input and the detector chain, so all events
that are not `drop`ped flow into the regular scoring and ban logic. `tag`ed
events carry the matched rule name in `Level` (e.g. `THREAT:block_sql_injection`)
so dashboards and executors can distinguish WAF-matched traffic from
detector-scored traffic.

## Full documentation

Field reference, expression grammar, lifecycle and custom-field extension
protocol live in:

```
pkg/processorplugins/waf/README.md
```
