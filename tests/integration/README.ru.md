# Integration Tests — arxsentinel

---

## High-Level Overview

### Purpose

Интеграционный тестовый набор проверяет, что arxsentinel корректно обнаруживает угрозы на множестве backend-серверов, цепочек прокси и сценариев Cloudflare. Запускается end-to-end с использованием Docker-контейнеров: каждый сервер атакуется специально сформированными HTTP-запросами, и проверяется, что лог угроз sentinel'а записывает IP атакующего (НЕ IP прокси).

### Infrastructure

```
Docker network: integration_default (172.16.0.0/12)
External network: integration_cf_ext_net (10.88.0.0/24) — IP атакующего изолирован от доверенных прокси
```

**Контейнеры:**

- Атакующие: `curlimages/curl` (Alpine‑based, один контейнер на сценарий)
- Backend'ы: nginx, apache, traefik, caddy, haproxy, litespeed
- Прокси: traefik:80, caddy:80, haproxy:80, nginx-rp:80
- Симуляторы: `cloudflare-sim`, `bogon-injector`

---

### Matrix — 110 Checks

| Category | Formula | Count | Invariant Verified |
|---|---|---|---|
| DIRECT | 6 серверов × 7 детекторов | 42 | Каждый детектор срабатывает на каждом сервере |
| BADBOT | 6 серверов (все логируют UA) | 6 | UA blocklist срабатывает на каждом сервере |
| BLOCKLIST | 6 серверов (автомат загружен) | 6 | Manager строит автомат из source blocklist |
| PROXY-CHAIN | 4 прокси × 6 backends | 24 | Лог угроз показывает IP атакующего, НЕ IP прокси |
| CF-DIRECT | 6 backends | 6 | Лог угроз показывает real IP, НЕ IP CF‑sim |
| CF-CHAIN | 4 прокси × 6 backends | 24 | Real IP сохраняется через two‑hop CF→proxy→backend |
| CHAIN-GUARD | 2 предупреждения | 2 | cf‑broken и bogon‑victim пишут warnings |

Все 6 серверов логируют User-Agent: nginx/apache/caddy/litespeed нативно;
traefik через `fields.headers.names.User-Agent: keep`;
haproxy через `http-request capture req.hdr(user-agent)` + кастомный log-format.

---

## Deep Dive

### 1. Direct Tests (Scenario 1–8)

Каждый сценарий запускает один контейнер-атакующий в сети `integration_default`. Все 6 backend'ов последовательно атакуются через helper `attack_all`.

#### 1.1 probe — Sensitive Path Detection
**Что отправляется (на сервер, 7 curl-команд):**
```bash
curl http://<srv>/wp-login.php
curl http://<srv>/.env
curl http://<srv>/.git/config
curl http://<srv>/admin/config.php
curl http://<srv>/etc/passwd
curl http://<srv>/.aws/credentials
curl http://<srv>/xmlrpc.php
```

**Ожидается в логе угроз:** THREAT-запись с `class=probe` для каждого сервера.

**Зачем `-sf`:** При 404/403 curl завершается молча (без вывода), чтобы контейнер атакующего не засорял stdout. `|| true` гарантирует продолжение скрипта, даже если все curl'ы завершились неудачей.

---

#### 1.2 ua — Scanner User-Agent Detection
**Что отправляется (на сервер, 5 curl-команд):**
```bash
curl -A "sqlmap/1.7.11" http://<srv>/
curl -A "sqlmap/1.7.11" http://<srv>/
curl -A "Nuclei/3.0"    http://<srv>/
curl -A "masscan/1.3"   http://<srv>/
curl -A "zgrab/0.x"     http://<srv>/
```

**Ожидается:** THREAT с `class=ua`, subtype со ссылкой на matched UA string.

---

#### 1.3 bruteforce — 404 Ratio > 60%
**Паттерн на сервер (15 запросов):**
```bash
3 × GET / (200 OK)
12 × GET /missing-page-N (404)
```
После 10+ запросов с > 60% 404 детектор `bruteforce` срабатывает. 12/15 = 80 % ratio.

**Ожидается:** THREAT с `class=bruteforce`.

---

#### 1.4 crawler — Sequential Numeric URLs
**Паттерн на сервер (6 запросов):**
```bash
GET /items/1
GET /items/2
GET /items/3
GET /items/4
GET /items/5
GET /items/6
```
Порог: `min_sequential=5`. Пять последовательных числовых URL под одним path prefix триггерят детекцию.

**Ожидается:** THREAT с `class=crawler`.

---

#### 1.5 noasset — Page Requests Without Assets
**Паттерн на сервер (8 запросов):**
```bash
8 × GET / (или /info.php) — запросы HTML-страниц, без CSS/JS
```
`assetRatio = 0% < 10%` threshold. Срабатывает после `min_page_requests=3`.

**Ожидается:** THREAT с `class=noasset`.

---

#### 1.6 rate — High Request Rate
**Паттерн на сервер (60 запросов):**
```bash
30 × GET / (burst 1)
sleep 1
30 × GET / (burst 2)
```
ApproxRate ≈ 30 req/s >> threshold (100/60 ≈ 1.67 req/s).

**Ожидается:** THREAT с `class=rate`.

---

#### 1.7 overflow — URL Path > 2048 Bytes
**Что отправляется (на сервер, 1 запрос):**
```bash
LONG_PATH="/$(head -c 20000 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 2200)"
curl "http://<srv>${LONG_PATH}"
```
Длина path > 2048 bytes триггерит детектор `overflow`.

**Ожидается:** THREAT с `class=overflow`.

---

#### 1.8 badbot — Community Blocklist UA
**Что отправляется (на сервер, 2 запроса):**
```bash
UA read from blocklist/test-ua.txt (fetched from blocklist-server:8090)
2 × curl -A "<badbot-ua>/1.0" http://<srv>/
```

**Ожидается:** THREAT с `class=badbot` на всех 6 серверах.

---

#### 1.9 blocklist — Automaton Loaded

**Что проверяется (на сервер, 1 проверка):**
```
assert_blocklist_loaded "$srv"
```

**Назначение:** Это НЕ тест детектора — он валидирует, что **Manager** успешно загрузил
паттерны blocklist с локального `blocklist-server:8090`, пересобрал Aho-Corasick-автомат
и загрузил N>0 паттернов в память. Без этого детектор `badbot` не имел бы паттернов для
сравнения.

**Верификация:** `verify.sh` проверяет operational log каждого сервера на наличие строки
`automaton rebuilt (N patterns)` с N>0.

**Ожидается:** PASS с отображением количества паттернов.

**6 проверок** (одна на сервер).

---

### 2. Infrastructure Tests

#### 2.1 Proxy‑Chain Tests (Scenario 9)

**Топология:**
```
attacker (integration_default)
     ↓
traefik:80 / caddy:80 / haproxy:80 / nginx-rp:80
     ↓
nginx / apache / traefik / caddy / haproxy / litespeed
```

**Что отправляется (на пару proxy × backend, 5 curl-команд):**
```bash
curl http://<proxy>:80/backend-<backend>/wp-login.php
curl http://<proxy>:80/backend-<backend>/.env
curl http://<proxy>:80/backend-<backend>/.git/config
curl http://<proxy>:80/backend-<backend>/admin/login.php
curl http://<proxy>:80/backend-<backend>/xmlrpc.php
```

**Инвариант:** Лог угроз должен показывать IP атакующего (из `X-Forwarded-For`), НЕ IP прокси-контейнера. Если IP прокси появляется в THREAT‑строке → FAIL.

**24 комбинации:** 4 прокси × 6 backends.

---

#### 2.2 Cloudflare Cases

Все CF-сценарии используют `integration_cf_ext_net` (10.88.0.0/24) — IP атакующего находится за пределами доверенного proxy CIDR (`172.16.0.0/12`). Это вынуждает backend'ы извлекать real IP из `CF-Connecting-IP` / `X-Forwarded‑For`.

---

##### Case 1 — CF-Direct: cloudflare-sim → product (Scenario 10)

**Топология:**
```
attacker (10.88.0.x) → cloudflare-sim → nginx/apache/traefik/caddy/haproxy/litespeed
```

`cloudflare-sim` переписывает `X-Forwarded-For` в `$remote_addr` и добавляет заголовок `CF-Connecting-IP`.

**5 paths на backend:** `/wp-login.php`, `.env`, `.git/config`, `/admin/login.php`, `/xmlrpc.php`.

**Инвариант:** Лог угроз показывает IP атакующего, НЕ IP контейнера cloudflare-sim. Если появляется IP CF‑sim → FAIL (class=cf-ip-leak).

---

##### Case 2 — CF-Chain: cloudflare-sim → our proxy → product (Scenario 11)

**Топология:**
```
attacker (10.88.0.x) → cloudflare-sim → traefik/caddy/haproxy/nginx-rp → backend
```

Two‑hop цепочка: CF-заголовки устанавливаются `cloudflare-sim`, затем прокси forwarded к backend.

**3 paths на пару (proxy, backend):** `/wp-login.php`, `.env`, `/xmlrpc.php`.

**Инвариант:** Тот же, что в Case 1 — лог угроз показывает IP атакующего. **24 проверки** (4 прокси × 6 backends — 3 probe paths per pair, single assertion per pair).

---

##### Case 3A — CF‑Broken: cloudflare-sim → nginx-bare (Scenario 12A)

`nginx-bare` НЕ имеет настроенного `real_ip_header`. Он логирует TCP peer (`IP cloudflare-sim` контейнера) как клиента.

**2 запроса:** `curl /wp-login.php` и `curl /.env` через `cloudflare-sim:80/cf-bare/`.

**Ответ Chain‑Guard:** sentinel должен обнаружить IP из диапазона Cloudflare → пишет `cloudflare-ip-as-client` в `warnings/cf-broken.log`.

---

##### Case 3B — Bogon Injection (Scenario 12B)

`bogon-injector` добавляет `X-Forwarded-For: 10.0.0.1` перед форвардом к `nginx-bogon-victim`.

`nginx-bogon-victim` доверяет XFF, логирует `10.0.0.1` как клиента.

**Ответ Chain‑Guard:** sentinel должен обнаружить private IP RFC 1918 → пишет `bogon-ip-as-client` в `warnings/bogon-victim.log`.

---

### 3. Safety Guards — Chain Guard

Chain Guard — это компонент sentinel'а, который мониторит логи backend'ов на предмет IP, которые никогда не должны появляться как client IP:

| Warning Type | Condition                              | Log File                     |
|---|---|---|
| `cloudflare-ip-as-client` | Backend логирует IP из диапазона Cloudflare как клиента | `warnings/cf-broken.log`   |
| `bogon-ip-as-client`     | Backend логирует private IP RFC 1918 как клиента | `warnings/bogon-victim.log`|

**Верификация:** `verify.sh` проверяет, что каждый warning-файл содержит ожидаемую строку. Отсутствие = FAIL.

---

## Developer's Guide

### Adding a New Backend Server

1. **Добавить сервер в массивы в `scenarios.sh` и `verify.sh`:**
   ```bash
   # scenarios.sh
   SERVERS=(nginx apache traefik caddy haproxy litespeed <NEW_SERVER>)
   
   # verify.sh
   SERVERS=(nginx apache traefik caddy haproxy litespeed <NEW_SERVER>)
   ```

2. **Создать sentinel config:** `arxsentinel/<NEW_SERVER>.yaml`
   - Настроить `real_ip_header` и `trusted_proxies`, если сервер находится за прокси
   - Установить соответствующий `log_format` / `log_path` для парсинга access log

3. **Добавить в docker‑compose.yml:** определить контейнер `<NEW_SERVER>` с образом и сетями

4. **Обновить BADBOT_SERVERS в `verify.sh`, если новый сервер логирует User-Agent:**
    ```bash
    BADBOT_SERVERS=(nginx apache traefik caddy haproxy litespeed <UA_LOGGING_SERVER>)
    ```
    *Все 6 серверов в тестовом наборе логируют UA — добавляй новый, если он тоже это делает.*

5. **Добавить в proxy‑chain**, если новый сервер будет backend за прокси:
   - Изменения кода не нужны — `CHAIN_BACKENDS` итерирует по всем серверам
   - Убедиться, что прокси маршрутизирует `/backend-<server>/` к правильному контейнеру

6. **Добавить в CF-сценарии**, если сервер должен тестироваться в CF‑direct и CF‑chain:
   - Изменения кода не нужны — `CHAIN_BACKENDS` покрывает все серверы
   - Настроить размещение в сети соответственно

### Adding a New Detector

1. **Добавить сценарий в `scenarios.sh`:**
   ```bash
   run_scenario "<detector_name>" "$(attack_all '
   <curl commands using __SRV__ placeholder>
   ')"
   ```

2. **Добавить в массив MODULES в `verify.sh`:**
   ```bash
   MODULES=(probe ua bruteforce crawler noasset rate overflow <NEW_DETECTOR>)
   ```

3. **Настроить детектор** в каждом `arxsentinel/<SERVER>.yaml`:
   - Установить соответствующие пороги (`min_requests`, `threshold` и т.д.)
   - Убедиться, что формат лога включает поля, нужные детектору

4. **Обновить ожидаемое количество в документации** (этот README и матрица)

### Adding a New Proxy

1. **Добавить в `CHAIN_PROXIES` в `scenarios.sh`:**
   ```bash
   CHAIN_PROXIES=(
       "traefik:80"
       "caddy:80"
       "haproxy:80"
       "nginx-rp:80"
       "<NEW_PROXY>:80"
   )
   ```

2. **Добавить в `CF_CHAIN_PROXIES`** для CF Case 2:
   ```bash
   CF_CHAIN_PROXIES=(traefik caddy haproxy nginx-rp <NEW_PROXY>)
   ```

3. **Добавить конфигурацию прокси** в `configs/` (например, `nginx-rp.conf` для nginx reverse proxy)

4. **Добавить в docker‑compose.yml:** определить контейнер `<NEW_PROXY>` с сетями

5. **Убедиться, что маршруты настроены** так, чтобы `/backend-<SERVER>/` проксировало к правильному backend-контейнеру

### Key Arrays Reference

```bash
# scenarios.sh
SERVERS=(nginx apache traefik caddy haproxy litespeed)   # backends
CHAIN_PROXIES=(traefik:80 caddy:80 haproxy:80 nginx-rp:80)
CHAIN_BACKENDS=(nginx apache traefik caddy haproxy litespeed)

# verify.sh
SERVERS=(nginx apache traefik caddy haproxy litespeed)   # backends
MODULES=(probe ua bruteforce crawler noasset rate overflow)  # core 7
BADBOT_SERVERS=(nginx apache traefik caddy haproxy litespeed)  # 6 (все серверы логируют UA)
```

### Network Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ integration_default (172.16.0.0/12)                                  │
│                                                                      │
│   attacker-probe  ──→  nginx  apache  traefik  caddy  haproxy  lite│
│   attacker-ua          (all direct tests)                            │
│   attacker-bruteforce                                                │
│   attacker-crawler                                                    │
│   attacker-noasset                                                    │
│   attacker-rate                                                       │
│   attacker-overflow                                                  │
│   attacker-badbot                                                     │
│   attacker-bogon-injection ──→ bogon‑injector ──→ nginx-bogon-victim│
└────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ integration_cf_ext_net (10.88.0.0/24)                              │
│   attacker-cf-direct ──→ cloudflare-sim ──→ nginx  apache …       │
│   attacker-cf-chain  ──→ cloudflare-sim ──→ traefik ──→ nginx     │
│   attacker-cf-broken ──→ cloudflare-sim ──→ nginx‑bare           │
└─────────────────────────────────────────────────────────────────────┘

Why two networks?
- Attacker on `integration_default` (172.16.x.x) shares the proxy CIDR range
- If attacker were on same network as proxies, `real_ip_recursive` would exhaust trusted IPs
  and fall back to cloudflare‑sim container IP
- By placing attacker on `10.88.0.0/24`, attacker IP is always treated as untrusted,
  forcing proper header extraction
```

(End of file)
