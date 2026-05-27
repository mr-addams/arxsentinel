## JSON log format

By default ArxSentinel parses nginx combined log format (no profile needed) or the format defined by the active profile (apache, caddy, traefik, haproxy-http, or litespeed).  
It also supports JSON log format — switch via `config.yaml` without recompilation.

The examples below use nginx. For other servers, adapt the `log_format` directive to your server's equivalent.

### Step 1 — Configure your HTTP server (nginx example)

Add the appropriate `log_format` to your `nginx.conf` (`http {}` block).
Ready-to-use configs are also in [`deploy/examples/nginx-json-logformat.conf`](deploy/examples/nginx-json-logformat.conf).

**Direct nginx (no reverse proxy)** — `$remote_addr` is the real client IP:

```nginx
log_format sentinel_json_direct escape=json
    '{'
        '"remote_addr":"$remote_addr",'
        '"time_iso8601":"$time_iso8601",'
        '"request":"$request",'
        '"status":"$status",'
        '"bytes_sent":"$bytes_sent",'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent"'
    '}';

access_log /var/log/nginx/access.log sentinel_json_direct;
```

**Behind a reverse proxy** — configure `ngx_http_realip_module` (see
[Deployment behind a reverse proxy](#deployment-behind-a-reverse-proxy)).
After realip processing, `$remote_addr` already holds the real client IP,
so the same `sentinel_json_direct` format works unchanged — no separate proxy variant needed.

### Step 2 — Update sentinel config

```yaml
parser:
  log_format: "json"   # "combined" (default) | "json"
```

The change takes effect on the next **SIGHUP** — no restart needed:

```bash
kill -HUP $(cat /var/run/arxsentinel.pid)
```

### Custom field names

If your log format uses different key names, override the mapping:

```yaml
parser:
  log_format: "json"
  json_fields:
    remote_addr: "client"
    time:        "ts"
    request:     "req"
    status:      "code"
    bytes_sent:  "size"
    referer:     "ref"
    user_agent:  "ua"
    real_ip:     "ip"
```

Unknown fields in the JSON log line are silently ignored — only the mapped fields are consumed.

## Custom log format (regex)

Use any text log format by supplying a Go regex with named capture groups.

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
```

### Named groups

| Group | Required | Description |
|-------|----------|-------------|
| `remote_addr` | ✅ | Client or proxy IP address |
| `time` | ✅ | Request time (`02/Jan/2006:15:04:05 -0700` format) |
| `request` | ✅ | Full request line: `METHOD /path HTTP/x.x` |
| `status` | ✅ | HTTP response code |
| `bytes_sent` | ✅ | Response size in bytes |
| `http_referer` | optional | Referer header value |
| `http_user_agent` | optional | User-Agent header value |
| `real_ip` | optional | Real client IP from a trusted proxy header |

Missing optional groups produce empty fields in the parsed entry — sentinel still works, just without referer/UA/real-IP data.

### Example: HAProxy HTTP log

Use the built-in `haproxy-http` profile with a custom `log-format` that captures the User-Agent header. The required HAProxy configuration is in [`deploy/examples/haproxy/haproxy.cfg`](deploy/examples/haproxy/haproxy.cfg); the sentinel config needs only:

```yaml
parser:
  profile: "haproxy-http"
```

The `haproxy-http` profile matches lines produced by the log-format in the deploy example:

```
172.18.0.1:54321 [20/May/2026:12:34:56 +0000] http-in backend/server 0/0/2/8/10 200 1234 - - ---- 5/4/0/1/0 0/0 "GET /index.html HTTP/1.1" "Mozilla/5.0"
```

The trailing User-Agent field is optional — old-style logs without it are also accepted.

### Common mistakes

- **Missing mandatory group** — sentinel exits at startup with a clear error message listing the missing group name.
- **Unanchored pattern** — the regex is applied with `FindStringSubmatch`, so it matches anywhere in the line. Anchor with `^` / `$` if needed.
- **Wrong time format** — only `02/Jan/2006:15:04:05 -0700` (nginx `$time_local`) is parsed. ISO 8601 timestamps are not parsed; time-based features still work with zero time.
