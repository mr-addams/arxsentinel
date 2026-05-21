# ArxSentinel — Дашборд Grafana

## Требования

- Prometheus ≥ 2.40
- Grafana ≥ 9.0

---

## Шаг 1 — Включить метрики в конфиге sentinel (опционально: basic auth)

В `config.yaml`:

```yaml
metrics:
  enabled: true
  listen_addr: ":9117"
  # Опциональная basic auth — оставьте username пустым для отключения
  username: ""
  password_hash: ""
```

### Генерация bcrypt-хеша пароля

Выберите один из следующих способов:

**Вариант A — htpasswd (apache2-utils / httpd-tools):**

```bash
htpasswd -nBC 12 prometheus | awk -F: '{print $2}'
# Введите пароль по запросу — скопируйте хеш $2b$... из вывода
```

**Вариант B — Python 3 (bcrypt библиотека):**

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt(rounds=12)).decode())"
```

**Вариант C — онлайн-генератор** (только для non-production):  
Используйте любой bcrypt-генератор с фактором стоимости 12.

### Пример конфига с включённой авторизацией:

```yaml
metrics:
  enabled: true
  listen_addr: ":9117"
  username: "prometheus"
  password_hash: "$2b$12$eImiTXuWVxfM37uY4JANjQ.3Y9PnKr8xLWg5GI6pRlPGg/VzEa0Vy"
```

> **Примечание:** `password_hash` хранит bcrypt-хеш, никогда не открытый пароль.  
> Хеш выше — пример; генерируйте свой командами выше.

---

## Шаг 2 — Доступные эндпоинты

| Эндпоинт | Авторизация | Описание |
|----------|-------------|----------|
| `/metrics` | опциональная basic auth | Scrape-эндпоинт Prometheus |
| `/health` | нет | Liveness probe — всегда возвращает `200 {"status":"ok"}` |

---

## Шаг 3 — Доступные метрики

| Метрика | Тип | Описание |
|---------|-----|----------|
| `arxsentinel_lines_processed_total` | Counter | Обработано строк лога |
| `arxsentinel_threats_total{level}` | Counter | Угрозы по уровню (`THREAT` / `WARN`) |
| `arxsentinel_detector_hits_total{detector}` | Counter | Срабатывания по детектору |
| `arxsentinel_tracked_ips` | Gauge | Текущее количество отслеживаемых IP |
| `arxsentinel_suspicious_ips` | Gauge | IP с score выше alert threshold |

---

## Шаг 4 — Настроить scrape-задачу в Prometheus

Добавьте в `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "arxsentinel"
    static_configs:
      - targets: ["localhost:9117"]
    # Если включена basic auth (см. Шаг 1):
    # basic_auth:
    #   username: "prometheus"
    #   password: "ваш-пароль-открытым-текстом"
```

Затем перезагрузите Prometheus:

```bash
curl -X POST http://localhost:9090/-/reload
# или: systemctl reload prometheus
```

Проверьте, что target в статусе "up": `http://localhost:9090/targets`

---

## Шаг 5 — Импортировать дашборд в Grafana

### Через веб-интерфейс Grafana

1. Откройте Grafana → **Dashboards → Import**
2. Загрузите файл `arxsentinel-dashboard.json`
3. Выберите datasource Prometheus по запросу
4. Нажмите **Import**

### Через provisioning (рекомендуется для автоматизированных систем)

Скопируйте файл дашборда в директорию provisioning Grafana:

```bash
cp arxsentinel-dashboard.json /etc/grafana/provisioning/dashboards/
```

Создайте или обновите `/etc/grafana/provisioning/dashboards/arxsentinel.yaml`:

```yaml
apiVersion: 1
providers:
  - name: arxsentinel
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
```

Затем перезагрузите Grafana:

```bash
systemctl restart grafana-server
```

---

## Панели дашборда

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

Переменная `$job` в верхней части позволяет фильтровать по Prometheus job label — полезно при запуске нескольких instances sentinel.

---

## Миграция из nginx-sentinel

Легатский дашборд (`nginx-sentinel-dashboard-legacy.json`) сохранён для справки.
Он запрашивает старые `nginx_sentinel_*` метрики и может использоваться во время переходного периода.

После обновления на ArxSentinel импортируйте `arxsentinel-dashboard.json`, который запрашивает `arx_sentinel_*` метрики.
