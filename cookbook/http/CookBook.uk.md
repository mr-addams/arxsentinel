# HTTP Source Cookbook

## Огляд

HTTP/HTTPS приймач логів з підтримкою push-режиму (прослуховування вхідних POST-запитів)
та pull-режиму (опитування віддаленого endpoint'а). Дев'ять вбудованих обробників протоколів
декодують вендорні конверти — Cloudflare Logpush, AWS Firehose, GCP Pub/Sub,
Loki push, OTLP HTTP, Azure Monitor, Splunk HEC, NDJSON з вилученням полів
та plain HTTP body.

## Швидкий старт

### Plain HTTP push

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
```

Відправка рядка логу:
```bash
curl -X POST http://localhost:8888/ \
  -H "Content-Type: text/plain" \
  -d '192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234'
```

### Cloudflare Logpush

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8889"
    protocol: cloudflare
```

Cloudflare надсилає gzip-стиснений NDJSON з ownership challenge.
Симуляція через curl:
```bash
# Крок 1: ownership challenge (сервер відповідає токеном)
curl -X GET "http://localhost:8889/?validate=true" \
  -H "Ownership-Challenge: cf-challenge-token"

# Крок 2: відправка gzip NDJSON
echo '{"EdgeStartTimestamp":1720000000000000000,"ClientIP":"203.0.113.1","ClientRequestPath":"/wp-admin"}' | \
  gzip | curl -X POST http://localhost:8889/ \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @-
```

### AWS Firehose

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8890"
    protocol: firehose
```

Firehose надсилає base64-кодовані записи в JSON-обгортці:
```bash
DATA=$(echo -n '192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] "GET /admin" 404 123' | base64)

curl -X POST http://localhost:8890/ \
  -H "X-Amz-Firehose-Request-Id: $(uuidgen)" \
  -H "X-Amz-Firehose-Access-Key: your-access-key" \
  -H "X-Amz-Firehose-Protocol-Version: 1.0" \
  -H "Content-Type: application/json" \
  -d "{\"requestId\":\"$(uuidgen)\",\"timestamp\":1720000000,\"records\":[{\"data\":\"$DATA\"}]}"
```

### GCP Pub/Sub push

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8891"
    protocol: pubsub
```

Pub/Sub загортає лог у `message.data` (base64):
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

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8892"
    protocol: loki
```

Loki надсилає streams з timestamp-значеннями:
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

### OTLP HTTP

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8893"
    protocol: otlp
```

OTLP загортає записи в resourceLogs → scopeLogs → logRecords:
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

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8894"
    protocol: azure
```

Azure надсилає JSON-масив записів:
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

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8895"
    protocol: splunk
```

Splunk HEC загортає лог у поле `event`:
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

### NDJSON з вилученням полів

Конфіг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8896"
    protocol: ndjson
    envelope_field: message
    token: "your-secret-token"
```

Кожен рядок — JSON-об'єкт, лог вилучається з поля `envelope_field`:
```bash
curl -X POST http://localhost:8896/ \
  -H "Content-Type: application/x-ndjson" \
  -H "Authorization: Bearer your-secret-token" \
  -d '{"timestamp":"2026-06-03T12:00:00Z","message":"192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] \"GET /admin\" 404 123","level":"info","source":"nginx"}
{"timestamp":"2026-06-03T12:00:01Z","message":"10.0.0.1 - - [03/Jun/2026:12:00:01 +0000] \"POST /wp-login.php\" 200 456","level":"info","source":"nginx"}'
```

### Pull-режим

Конфіг:
```yaml
inputs:
  - type: http
    mode: pull
    url: "http://log-aggregator:9000/export"
    protocol: plain
    pull_interval: 30s
```

ArxSentinel опитує URL кожні `pull_interval`, читає тіло HTTP-відповіді
та обробляє кожен рядок як окремий запис. Використовуйте, коли віддалений
endpoint віддає логи через HTTP, але не може надсилати їх до ArxSentinel.

### HTTPS з TLS

Конфіг:
```yaml
inputs:
  - type: http
    addr: "https://0.0.0.0:8443"
    protocol: plain
    tls_cert: /etc/arxsentinel/tls/server.crt
    tls_key: /etc/arxsentinel/tls/server.key
```

## Аутентифікація

Bearer token — додайте `token` до конфігу:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
    token: "your-secret-token"
```

Клієнти повинні надсилати заголовок `Authorization: Bearer your-secret-token`.

## Обмеження розміру тіла

Максимальний розмір тіла за замовчуванням — 10 MB. Перевизначається `max_body_bytes`:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
    max_body_bytes: 20971520  # 20 MB
```