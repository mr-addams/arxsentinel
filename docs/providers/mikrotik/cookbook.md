# MikroTik Executor Cookbook

## Recipe 1: External Defender

ArxSentinel runs on a VPS and blocks malicious IPs on the MikroTik router via
the REST API.

### Minimal Configuration

```yaml
executors:
  - name: mikrotik-router
    type: mikrotik
    config:
      host: 192.168.88.1
      port: 443
      username: arxsentinel
      password: "${MIKROTIK_PASSWORD}"
      list_name: arxsentinel_blocklist
      sentinel_id: router1
      ttl: "24h"
      tls_verify: true
      min_level: THREAT
```

### RouterOS User Setup

Enable the REST API service and create a minimal-privilege user:

```
/ip/service/enable rest
/ip/service/set rest port=443 certificate=none

/user/group/add name=arxsentinel policy=read,write,api,rest-api
/user/add name=arxsentinel group=arxsentinel password="<secure-password>"
```

### Verification

```bash
curl -s -u "arxsentinel:<password>" \
  "https://192.168.88.1/rest/ip/firewall/address-list?list=arxsentinel_blocklist"
```

---

## Recipe 2: Embedded Container on CHR

ArxSentinel runs directly inside a CHR container, no external VPS required.

### Requirements

- CHR with at least 256 MB RAM (512 MB recommended)
- `/system/device-mode` set to allow containers
- `container` package installed (`/system/package/update` → check `container`)

### Steps

1. **Enable container mode:**

   ```
   /system/device-mode/update mode=container
   ```

2. **Create a veth interface and bridge:**

   ```
   /interface/veth/add name=veth-arx address=172.18.0.2/24 gateway=172.18.0.1
   /interface/bridge/add name=bridge-arx
   /interface/bridge/port/add bridge=bridge-arx interface=veth-arx
   /ip/address/add address=172.18.0.1/24 interface=bridge-arx
   ```

3. **NAT for internet access (if needed for updates):**

   ```
   /ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.18.0.0/24
   ```

4. **Create mount point for persistent config:**

   ```
   /container/mounts/add name=arx-config src=disk1/arx-config dst=/etc/arxsentinel
   ```

5. **Pull and start the container:**

   ```
   /container/add remote-image=ghcr.io/mr-addams/arxsentinel:latest \
     interface=veth-arx \
     root-dir=disk1/arxsentinel-root \
     mounts=arx-config \
     envlist=arx-env \
     command=""
   ```

6. **Create envlist file:**

   ```
   /container/envs/add name=arx-env key=ARXSENTINEL_CONFIG value=/etc/arxsentinel/config.yaml
   ```

### Configuration inside Container

Place `config.yaml` in the mounted directory (`disk1/arx-config`):

```yaml
executors:
  - name: local-router
    type: mikrotik
    config:
      host: 127.0.0.1
      port: 443
      username: arxsentinel
      password: "${MIKROTIK_PASSWORD}"
      list_name: arxsentinel_blocklist
      sentinel_id: chr-embedded
      ttl: "24h"
      tls_verify: false
      min_level: THREAT
```

> `tls_verify: false` is acceptable for loopback REST API on CHR.

---

## Recipe 3: ETL / Log Collector

ArxSentinel collects syslog or traffic flow data and writes to a file —
no address-list enforcement.

This pattern is useful for telemetry gathering, threat intelligence feeds,
or compliance auditing without blocking traffic.

### Configuration

```yaml
sources:
  - name: syslog-source
    type: exec
    config:
      command: "/usr/bin/logger-parser"
      args:
        - "--listen=0.0.0.0:514"
        - "--format=json"

executors:
  # No mikrotik executor — pure collection mode
  - name: file-sink
    type: file
    config:
      path: "/var/log/arxsentinel/events.ndjson"
      rotate:
        max_size: "100MB"
        max_age: "7d"
```

### Pipeline

```
Syslog / Traffic Flow → exec source → threat detection → file sink
```

### Use Cases

- Security audit: log all events without blocking
- Feed ML models with raw threat data
- Test and validate detection rules before enabling enforcement
- Compliance: retain block decision history with context

---

## Recipe 4: Troubleshooting

### Check Container Status

```
/container/print detail
```

Look for `status=running` and `root-dir` pointing to the correct mount.
If the container is `stopped` — check logs with `/container/print detail`
and inspect the envlist and mounts.

### Verify REST API

```bash
curl -s -u "arxsentinel:<password>" \
  "https://192.168.88.1/rest/ip/firewall/address-list/print"
```

Expected: `200 OK` with a JSON array of entries.
If authentication fails, verify the user has `api` and `rest-api` policies.

### List Banned IPs

```
/ip/firewall/address-list/print where list=arxsentinel_blocklist
```

### Clear Ban-List

Remove all entries tagged by a specific SentinelID:

```
/ip/firewall/address-list/remove [find comment=sentinel-router1]
```

To clear the entire blocklist:

```
/ip/firewall/address-list/remove [find list=arxsentinel_blocklist]
```

### Common Errors

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `401 Unauthorized` | Wrong credentials or missing `rest-api` policy | Verify user password and group policies (`read,write,api,rest-api`) |
| `404 Not Found` | Incorrect API path or RouterOS version < 7.18.2 | Check `/ip/service/print` for REST service; update RouterOS to 7.18.2+ |
| `TLS handshake error` | Certificate mismatch or `tls_verify: true` with self-signed cert | Set `tls_verify: false` for testing or install a valid cert on RouterOS |
| `connection refused` | REST service not enabled or wrong port | `/ip/service/enable rest` and verify port with `/ip/service/print` |
| Container exits immediately | Out of memory or missing envlist | Check RAM with `/system/resource/print`, verify envlist with `/container/envs/print` |