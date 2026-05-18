# nginx-sentinel — Grafana Dashboard

## Requirements

- Prometheus ≥ 2.40
- Grafana ≥ 9.0

---

## Step 1 — Configure Prometheus scrape job

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "nginx-sentinel"
    static_configs:
      - targets: ["localhost:9117"]
    # If basic auth is enabled (see Step 2):
    # basic_auth:
    #   username: "prometheus"
    #   password: "your-plaintext-password"
```

Then reload Prometheus:

```bash
curl -X POST http://localhost:9090/-/reload
# or: systemctl reload prometheus
```

Verify the target is up: `http://localhost:9090/targets`

---

## Available endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `/metrics` | optional basic auth | Prometheus scrape endpoint |
| `/health` | none | Liveness probe — always returns `200 {"status":"ok"}` |

---

## Step 2 — Enable metrics in sentinel config (optional: basic auth)

In `config.yaml`:

```yaml
metrics:
  enabled: true
  listen_addr: ":9117"
  # Optional basic auth — leave username empty to disable
  username: ""
  password_hash: ""
```

### Generating a bcrypt password hash

Choose any of the following methods:

**Option A — htpasswd (apache2-utils / httpd-tools):**

```bash
htpasswd -nBC 12 prometheus | awk -F: '{print $2}'
# Enter password when prompted — copy the $2b$... hash from the output
```

**Option B — Python 3 (bcrypt library):**

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt(rounds=12)).decode())"
```

**Option C — online generator** (for non-production use only):  
Use any bcrypt generator with cost factor 12.

### Example config with auth enabled:

```yaml
metrics:
  enabled: true
  listen_addr: ":9117"
  username: "prometheus"
  password_hash: "$2b$12$eImiTXuWVxfM37uY4JANjQ.3Y9PnKr8xLWg5GI6pRlPGg/VzEa0Vy"
```

> **Note:** `password_hash` stores the bcrypt hash, never the plaintext password.  
> The hash above is an example — generate your own with the commands above.

---

## Step 3 — Import the dashboard into Grafana

### Via Grafana UI

1. Open Grafana → **Dashboards → Import**
2. Upload `nginx-sentinel-dashboard.json`
3. Select your Prometheus datasource when prompted
4. Click **Import**

### Via provisioning (recommended for automated setups)

Copy the dashboard file to Grafana's provisioning directory:

```bash
cp nginx-sentinel-dashboard.json /etc/grafana/provisioning/dashboards/
```

Create or update `/etc/grafana/provisioning/dashboards/nginx-sentinel.yaml`:

```yaml
apiVersion: 1
providers:
  - name: nginx-sentinel
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
```

Then restart Grafana:

```bash
systemctl restart grafana-server
```

---

## Dashboard panels

| Panel | Type | Metric |
|-------|------|--------|
| Tracked IPs / Suspicious IPs | Stat | `nginx_sentinel_tracked_ips`, `nginx_sentinel_suspicious_ips` |
| Threat Rate (THREAT/min) | Stat | `nginx_sentinel_threats_total{level="THREAT"}` |
| Lines/s | Stat | `nginx_sentinel_lines_processed_total` |
| Total THREATs | Stat | `nginx_sentinel_threats_total{level="THREAT"}` |
| Threat Rate over Time | Timeseries | `nginx_sentinel_threats_total` |
| Log Lines Processed | Timeseries | `nginx_sentinel_lines_processed_total` |
| Detector Hits | Bar chart | `nginx_sentinel_detector_hits_total` |
| WARN / THREAT Split | Pie chart | `nginx_sentinel_threats_total` |

The `$job` variable at the top filters by Prometheus job label — useful when running multiple sentinel instances.
