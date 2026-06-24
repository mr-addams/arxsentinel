# ArxSentinel — Дашборд Grafana

## Вимоги

- Prometheus ≥ 2.40
- Grafana ≥ 9.0

---

## Крок 1 — Увімкнути метрики в конфізі sentinel (опційно: basic auth)

У `config.yaml`:

```yaml
metrics:
  enabled: true
  listen_addr: ":9117"
  # Опційна basic auth — залиште username порожнім для вимкнення
  username: ""
  password_hash: ""
```

### Генерація bcrypt-хеша пароля

Виберіть один з наступних способів:

**Варіант A — htpasswd (apache2-utils / httpd-tools):**

```bash
htpasswd -nBC 12 prometheus | awk -F: '{print $2}'
# Введіть пароль за запитом — скопіюйте хеш $2b$... з виводу
```

**Варіант B — Python 3 (bcrypt бібліотека):**

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt(rounds=12)).decode())"
```

**Варіант C — онлайн-генератор** (лише для non-production):  
Використовуйте будь-який bcrypt-генератор з фактором вартості 12.

### Приклад конфігу з увімкненою авторизацією:

```yaml
metrics:
  enabled: true
  listen_addr: ":9117"
  username: "prometheus"
  password_hash: "$2b$12$eImiTXuWVxfM37uY4JANjQ.3Y9PnKr8xLWg5GI6pRlPGg/VzEa0Vy"
```

> **Примітка:** `password_hash` зберігає bcrypt-хеш, ніколи не відкритий пароль.  
> Хеш вище — приклад; генеруйте свій командами вище.

---

## Крок 2 — Доступні ендпоінти

| Ендпоінт | Авторизація | Опис |
|----------|-------------|------|
| `/metrics` | опційна basic auth | Scrape-ендпоінт Prometheus |
| `/health` | нема | Liveness probe — завжди повертає `200 {"status":"ok"}` |

---

## Крок 3 — Доступні метрики

| Метрика | Тип | Опис |
|---------|-----|------|
| `arx_sentinel_lines_processed_total` | Counter | Оброблено рядків лога |
| `arx_sentinel_threats_total{level}` | Counter | Загрози за рівнем (`THREAT` / `WARN`) |
| `arx_sentinel_detector_hits_total{detector}` | Counter | Спрацювання за детектором |
| `arx_sentinel_tracked_ips` | Gauge | Поточна кількість відстежуваних IP |
| `arx_sentinel_suspicious_ips` | Gauge | IP зі score вище alert threshold |

---

## Крок 4 — Налаштувати scrape-завдання в Prometheus

Додайте до `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "arxsentinel"
    static_configs:
      - targets: ["localhost:9117"]
    # Якщо увімкнено basic auth (див. Крок 1):
    # basic_auth:
    #   username: "prometheus"
    #   password: "ваш-пароль-відкритим-текстом"
```

Потім перезавантажте Prometheus:

```bash
curl -X POST http://localhost:9090/-/reload
# або: systemctl reload prometheus
```

Перевірте, що target у статусі "up": `http://localhost:9090/targets`

---

## Крок 5 — Імпортувати дашборд у Grafana

### Через веб-інтерфейс Grafana

1. Відкрийте Grafana → **Dashboards → Import**
2. Завантажте файл `arxsentinel-dashboard.json`
3. Виберіть datasource Prometheus за запитом
4. Натисніть **Import**

### Через provisioning (рекомендовано для автоматизованих систем)

Скопіюйте файл дашборда в директорію provisioning Grafana:

```bash
cp arxsentinel-dashboard.json /etc/grafana/provisioning/dashboards/
```

Створіть або оновіть `/etc/grafana/provisioning/dashboards/arxsentinel.yaml`:

```yaml
apiVersion: 1
providers:
  - name: arxsentinel
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
```

Потім перезавантажте Grafana:

```bash
systemctl restart grafana-server
```

---

## Панелі дашборда

| Панель | Тип | Метрика |
|--------|-----|----------|
| Tracked IPs / Suspicious IPs | Stat | `arx_sentinel_tracked_ips`, `arx_sentinel_suspicious_ips` |
| Threat Rate (THREAT/min) | Stat | `arx_sentinel_threats_total{level="THREAT"}` |
| Lines/s | Stat | `arx_sentinel_lines_processed_total` |
| Total THREATs | Stat | `arx_sentinel_threats_total{level="THREAT"}` |
| Threat Rate over Time | Timeseries | `arx_sentinel_threats_total` |
| Log Lines Processed | Timeseries | `arx_sentinel_lines_processed_total` |
| Detector Hits | Bar chart | `arx_sentinel_detector_hits_total` |
| WARN / THREAT Split | Pie chart | `arx_sentinel_threats_total` |

Змінна `$job` у верхній частині дозволяє фільтрувати за Prometheus job label — корисно при запуску кількох instances sentinel.

---

## Міграція з nginx-sentinel

Легатський дашборд (`nginx-sentinel-dashboard-legacy.json`) збережений для довідки.
Він запитує старі `nginx_sentinel_*` метрики і може використовуватись під час перехідного періоду.

Після оновлення на ArxSentinel імпортуйте `arxsentinel-dashboard.json`, який запитує `arx_sentinel_*` метрики.
