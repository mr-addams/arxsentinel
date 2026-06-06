# HTTP Source Cookbook

## Обзор

HTTP/HTTPS приёмник логов с поддержкой push-режима (прослушивание входящих POST-запросов)
и pull-режима (опрос удалённого endpoint'а). Девять встроенных обработчиков протоколов
декодируют вендорные конверты — Cloudflare Logpush, AWS Firehose, GCP Pub/Sub,
Loki push, OTLP HTTP, Azure Monitor, Splunk HEC, NDJSON с извлечением полей
и plain HTTP body.

## Быстрый старт

### Plain HTTP push

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
```

Отправка строки лога:
```bash
curl -X POST http://localhost:8888/ \
  -H "Content-Type: text/plain" \
  -d '192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234'
```

### Cloudflare Logpush

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8889"
    protocol: cloudflare
```

Cloudflare отправляет gzip-сжатый NDJSON с ownership challenge.
Симуляция через curl:
```bash
# Шаг 1: ownership challenge (сервер отвечает токеном)
curl -X GET "http://localhost:8889/?validate=true" \
  -H "Ownership-Challenge: cf-challenge-token"

# Шаг 2: отправка gzip NDJSON
echo '{"EdgeStartTimestamp":1720000000000000000,"ClientIP":"203.0.113.1","ClientRequestPath":"/wp-admin"}' | \
  gzip | curl -X POST http://localhost:8889/ \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @-
```

### AWS Firehose

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8890"
    protocol: firehose
```

Firehose отправляет base64-кодированные записи в JSON-обёртке:
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

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8891"
    protocol: pubsub
```

Pub/Sub оборачивает лог в `message.data` (base64):
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

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8892"
    protocol: loki
```

Loki отправляет streams с timestamp-значениями:
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

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8893"
    protocol: otlp
```

OTLP оборачивает записи в resourceLogs → scopeLogs → logRecords:
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

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8894"
    protocol: azure
```

Azure отправляет JSON-массив записей:
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

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8895"
    protocol: splunk
```

Splunk HEC оборачивает лог в поле `event`:
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

### NDJSON с извлечением полей

Конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8896"
    protocol: ndjson
    envelope_field: message
    token: "your-secret-token"
```

Каждая строка — JSON-объект, лог извлекается из поля `envelope_field`:
```bash
curl -X POST http://localhost:8896/ \
  -H "Content-Type: application/x-ndjson" \
  -H "Authorization: Bearer your-secret-token" \
  -d '{"timestamp":"2026-06-03T12:00:00Z","message":"192.168.1.1 - - [03/Jun/2026:12:00:00 +0000] \"GET /admin\" 404 123","level":"info","source":"nginx"}
{"timestamp":"2026-06-03T12:00:01Z","message":"10.0.0.1 - - [03/Jun/2026:12:00:01 +0000] \"POST /wp-login.php\" 200 456","level":"info","source":"nginx"}'
```

### Pull-режим

Конфиг:
```yaml
inputs:
  - type: http
    mode: pull
    url: "http://log-aggregator:9000/export"
    protocol: plain
    pull_interval: 30s
```

ArxSentinel опрашивает URL каждые `pull_interval`, читает тело HTTP-ответа
и обрабатывает каждую строку как отдельную запись. Используйте, когда удалённый
endpoint отдаёт логи по HTTP, но не может отправлять их в ArxSentinel.

### HTTPS с TLS

Конфиг:
```yaml
inputs:
  - type: http
    addr: "https://0.0.0.0:8443"
    protocol: plain
    tls_cert: /etc/arxsentinel/tls/server.crt
    tls_key: /etc/arxsentinel/tls/server.key
```

## Аутентификация

Bearer token — добавьте `token` в конфиг:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
    token: "your-secret-token"
```

Клиенты должны отправлять заголовок `Authorization: Bearer your-secret-token`.

## Ограничения размера тела

Максимальный размер тела по умолчанию — 10 MB. Переопределяется `max_body_bytes`:
```yaml
inputs:
  - type: http
    addr: "http://0.0.0.0:8888"
    protocol: plain
    max_body_bytes: 20971520  # 20 MB
```