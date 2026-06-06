# HTTP Source Cookbook

## Overview

HTTP/HTTPS log receiver supporting push mode (listen for incoming POST requests)
and pull mode (poll a remote endpoint). Nine built-in protocol handlers decode
vendor-specific envelopes — Cloudflare Logpush, AWS Firehose, GCP Pub/Sub,
Loki push, OTLP HTTP logs, Azure Monitor, Splunk HEC, NDJSON with field extraction,
and plain HTTP body.

## Quick Start

### Plain HTTP push

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
```

Send a log line:
```bash
curl -X POST http://localhost:8888/ \
  -H "Content-Type: text/plain" \
  -d '192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234'
```

### Cloudflare Logpush

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8889"
    protocol: cloudflare
```

Cloudflare sends gzip-compressed NDJSON with ownership challenge.
Simulate with curl (requires gzip + ndjson payload):
```bash
# Step 1: ownership challenge (server responds with the challenge token)
curl -X GET "http://localhost:8889/?validate=true" \
  -H "Ownership-Challenge: cf-challenge-token"

# Step 2: push gzip NDJSON
echo '{"EdgeStartTimestamp":1720000000000000000,"ClientIP":"203.0.113.1","ClientRequestPath":"/wp-admin"}' | \
  gzip | curl -X POST http://localhost:8889/ \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @-
```

### AWS Firehose

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8890"
    protocol: firehose
```

Firehose sends base64-encoded records in a JSON wrapper:
```bash
# Encode log line
DATA=$(echo -n '192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] "GET /admin" 404 123' | base64)

curl -X POST http://localhost:8890/ \
  -H "X-Amz-Firehose-Request-Id: $(uuidgen)" \
  -H "X-Amz-Firehose-Access-Key: your-access-key" \
  -H "X-Amz-Firehose-Protocol-Version: 1.0" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$(uuidgen)\",\"timestamp\":1720000000,\"records\":[{\"data\":\"$DATA\"}]}"
```

### GCP Pub/Sub push

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8891"
    protocol: pubsub
```

Pub/Sub wraps the log in `message.data` (base64):
```bash
DATA=$(echo -n '192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] "GET /wp-login.php" 200 456' | base64)

curl -X POST http://localhost:8891/ \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": {
      \"data\": \"$DATA\",
      \"messageId\": \"12345\",
      \"publishTime\": \"2026-06-03T12:00:00.000Z\"
    },
    \"subscription\": \"projects/my-project/subscriptions/my-sub\"
  }"
```

### Loki push

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8892"
    protocol: loki
```

Loki sends streams with timestamped values:
```bash
curl -X POST http://localhost:8892/loki/api/v1/push \
  -H "Content-Type: application/json" \
  -H "X-Scope-OrgID: tenant1" \
  -d '{
    "streams": [
      {
        "stream": {"job": "nginx", "instance": "web-1"},
        "values": [
          ["1720000000000000000", "192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] \"GET /admin\" 404 123"]
        ]
      }
    ]
  }'
```

### OTLP HTTP logs

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8893"
    protocol: otlp
```

OTLP wraps log records in resourceLogs → scopeLogs → logRecords hierarchy:
```bash
curl -X POST http://localhost:8893/v1/logs \
  -H "Content-Type: application/json" \
  -d '{
    "resourceLogs": [
      {
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "nginx"}}]},
        "scopeLogs": [
          {
            "scope": {"name": "access-logger"},
            "logRecords": [
              {
                "timeUnixNano": "1720000000000000000",
                "severityNumber": 9,
                "severityText": "INFO",
                "body": {"stringValue": "192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] \"GET /.env\" 404 123"},
                "attributes": [
                  {"key": "http.status_code", "value": {"intValue": 404}}
                ]
              }
            ]
          }
        ]
      }
    ]
  }'
```

### Azure Monitor export

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8894"
    protocol: azure
```

Azure sends a JSON array of records:
```bash
curl -X POST http://localhost:8894/ \
  -H "Content-Type: application/json" \
  -d '[
    {
      "time": "2026-06-03T12:00:00Z",
      "message": "192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] \"GET /wp-login.php\" 200 456",
      "level": "INFO",
      "service": "nginx"
    }
  ]'
```

### Splunk HEC

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8895"
    protocol: splunk
```

Splunk HEC wraps the log in an `event` field:
```bash
curl -X POST http://localhost:8895/services/collector/event \
  -H "Authorization: Splunk your-hec-token" \
  -H "Content-Type: application/json" \
  -d '{
    "event": "192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] \"GET /.env\" 404 123",
    "host": "web-1",
    "sourcetype": "nginx:access",
    "time": 1720000000.123
  }'
```

### NDJSON with field extraction

Config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8896"
    protocol: ndjson
    envelope_field: message
    token: "your-secret-token"
```

NDJSON — each line is a JSON object, extract the log string from `envelope_field`:
```bash
curl -X POST http://localhost:8896/ \
  -H "Content-Type: application/x-ndjson" \
  -H "Authorization: Bearer your-secret-token" \
  -d '{"timestamp":"2026-06-03T12:00:00Z","message":"192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] \"GET /admin\" 404 123","level":"info","source":"nginx"}
{"timestamp":"2026-06-03T12:00:01Z","message":"10.0.0.1 - - [03/Jun/2026:12:00:01 +0000] \"POST /wp-login.php\" 200 456","level":"info","source":"nginx"}'
```

### Pull mode

Config:
```yaml
inputs:
  - type: http
    mode: pull
    url: "http://log-aggregator:9000/export"
    protocol: plain
    pull_interval: 30s
```

ArxSentinel polls the URL every `pull_interval`, reads the HTTP response body,
and processes each line as a separate log entry. Use when a remote endpoint
exposes logs over HTTP but cannot push to ArxSentinel.

### HTTPS with TLS

Config:
```yaml
inputs:
  - type: http
    addr: "https://0.0.0.0:8443"
    protocol: plain
    tls_cert: /etc/arxsentinel/tls/server.crt
    tls_key: /etc/arxsentinel/tls/server.key
```

## Authentication

Bearer token authentication — add `token` to the config:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
    token: "your-secret-token"
```

Clients must send `Authorization: Bearer your-secret-token` header.

## Body Size Limits

Default max body size is 10 MB. Override with `max_body_bytes`:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
    max_body_bytes: 20971520  # 20 MB
```