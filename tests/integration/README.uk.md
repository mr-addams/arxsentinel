# Integration Tests — arxsentinel

---

## High-Level Overview

### Purpose

Інтеграційний тестовий набір перевіряє, що arxsentinel коректно виявляє загрози на множині backend-серверів, ланцюжків проксі та сценаріїв Cloudflare. Запускається end-to-end з використанням Docker-контейнерів: кожен сервер атакується спеціально сформованими HTTP-запитами, і перевіряється, що лог загроз sentinel'а записує IP атакуючого (НЕ IP проксі).

### Infrastructure

```
Docker network: integration_default (172.16.0.0/12)
External network: integration_cf_ext_net (10.88.0.0/24) — IP атакуючого ізольований від довірених проксі
```

**Контейнери:**

- Атакуючі: `curlimages/curl` (Alpine‑based, один контейнер на сценарій)
- Backend'и: nginx, apache, traefik, caddy, haproxy, litespeed
- Проксі: traefik:80, caddy:80, haproxy:80, nginx-rp:80
- Симулятори: `cloudflare-sim`, `bogon-injector`

---

### Matrix — 110 Checks

| Category | Formula | Count | Invariant Verified |
|---|---|---|---|
| DIRECT | 6 серверів × 7 детекторів | 42 | Кожен детектор спрацьовує на кожному сервері |
| BADBOT | 6 серверів (всі логують UA) | 6 | UA blocklist спрацьовує на кожному сервері |
| BLOCKLIST | 6 серверів (автомат завантажено) | 6 | Manager будує автомат із source blocklist |
| PROXY-CHAIN | 4 проксі × 6 backends | 24 | Лог загроз показує IP атакуючого, НЕ IP проксі |
| CF-DIRECT | 6 backends | 6 | Лог загроз показує real IP, НЕ IP CF‑sim |
| CF-CHAIN | 4 проксі × 6 backends | 24 | Real IP зберігається через two‑hop CF→proxy→backend |
| CHAIN-GUARD | 2 попередження | 2 | cf‑broken і bogon‑victim записують warnings |

Всі 6 серверів логують User-Agent: nginx/apache/caddy/litespeed нативно;
traefik через `fields.headers.names.User-Agent: keep`;
haproxy через `http-request capture req.hdr(user-agent)` + кастомний log-format.

---

## Deep Dive

### 1. Direct Tests (Scenario 1–8)

Кожен сценарій запускає один контейнер-атакуючий у мережі `integration_default`. Всі 6 backend'ів послідовно атакуються через helper `attack_all`.

#### 1.1 probe — Sensitive Path Detection
**Що надсилається (на сервер, 7 curl-команд):**
```bash
curl http://<srv>/wp-login.php
curl http://<srv>/.env
curl http://<srv>/.git/config
curl http://<srv>/admin/config.php
curl http://<srv>/etc/passwd
curl http://<srv>/.aws/credentials
curl http://<srv>/xmlrpc.php
```

**Очікується в лозі загроз:** THREAT-запис з `class=probe` для кожного сервера.

**Навіщо `-sf`:** При 404/403 curl завершується мовчки (без виводу), щоб контейнер атакуючого не засмічував stdout. `|| true` гарантує продовження скрипта, навіть якщо всі curl'и завершилися невдало.

---

#### 1.2 ua — Scanner User-Agent Detection
**Що надсилається (на сервер, 5 curl-команд):**
```bash
curl -A "sqlmap/1.7.11" http://<srv>/
curl -A "sqlmap/1.7.11" http://<srv>/
curl -A "Nuclei/3.0"    http://<srv>/
curl -A "masscan/1.3"   http://<srv>/
curl -A "zgrab/0.x"     http://<srv>/
```

**Очікується:** THREAT з `class=ua`, subtype із посиланням на matched UA string.

---

#### 1.3 bruteforce — 404 Ratio > 60%
**Паттерн на сервер (15 запитів):**
```bash
3 × GET / (200 OK)
12 × GET /missing-page-N (404)
```
Після 10+ запитів з > 60% 404 детектор `bruteforce` спрацьовує. 12/15 = 80 % ratio.

**Очікується:** THREAT з `class=bruteforce`.

---

#### 1.4 crawler — Sequential Numeric URLs
**Паттерн на сервер (6 запитів):**
```bash
GET /items/1
GET /items/2
GET /items/3
GET /items/4
GET /items/5
GET /items/6
```
Поріг: `min_sequential=5`. П'ять послідовних числових URL під одним path prefix тригерять детекцію.

**Очікується:** THREAT з `class=crawler`.

---

#### 1.5 noasset — Page Requests Without Assets
**Паттерн на сервер (8 запитів):**
```bash
8 × GET / (або /info.php) — запити HTML-сторінок, без CSS/JS
```
`assetRatio = 0% < 10%` threshold. Спрацьовує після `min_page_requests=3`.

**Очікується:** THREAT з `class=noasset`.

---

#### 1.6 rate — High Request Rate
**Паттерн на сервер (60 запитів):**
```bash
30 × GET / (burst 1)
sleep 1
30 × GET / (burst 2)
```
ApproxRate ≈ 30 req/s >> threshold (100/60 ≈ 1.67 req/s).

**Очікується:** THREAT з `class=rate`.

---

#### 1.7 overflow — URL Path > 2048 Bytes
**Що надсилається (на сервер, 1 запит):**
```bash
LONG_PATH="/$(head -c 20000 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 2200)"
curl "http://<srv>${LONG_PATH}"
```
Довжина path > 2048 bytes тригерить детектор `overflow`.

**Очікується:** THREAT з `class=overflow`.

---

#### 1.8 badbot — Community Blocklist UA
**Що надсилається (на сервер, 2 запити):**
```bash
UA read from blocklist/test-ua.txt (fetched from blocklist-server:8090)
2 × curl -A "<badbot-ua>/1.0" http://<srv>/
```

**Очікується:** THREAT з `class=badbot` на всіх 6 серверах.

---

#### 1.9 blocklist — Automaton Loaded

**Що перевіряється (на сервер, 1 перевірка):**
```
assert_blocklist_loaded "$srv"
```

**Призначення:** Це НЕ тест детектора — він валідує, що **Manager** успішно завантажив
патерни blocklist з локального `blocklist-server:8090`, пересклав Aho-Corasick-автомат
і завантажив N>0 патернів у пам'ять. Без цього детектор `badbot` не мав би патернів для
порівняння.

**Верифікація:** `verify.sh` перевіряє operational log кожного сервера на наявність рядка
`automaton rebuilt (N patterns)` з N>0.

**Очікується:** PASS з відображенням кількості патернів.

**6 перевірок** (одна на сервер).

---

### 2. Infrastructure Tests

#### 2.1 Proxy‑Chain Tests (Scenario 9)

**Топологія:**
```
attacker (integration_default)
     ↓
traefik:80 / caddy:80 / haproxy:80 / nginx-rp:80
     ↓
nginx / apache / traefik / caddy / haproxy / litespeed
```

**Що надсилається (на пару proxy × backend, 5 curl-команд):**
```bash
curl http://<proxy>:80/backend-<backend>/wp-login.php
curl http://<proxy>:80/backend-<backend>/.env
curl http://<proxy>:80/backend-<backend>/.git/config
curl http://<proxy>:80/backend-<backend>/admin/login.php
curl http://<proxy>:80/backend-<backend>/xmlrpc.php
```

**Інваріант:** Лог загроз повинен показувати IP атакуючого (з `X-Forwarded-For`), НЕ IP проксі-контейнера. Якщо IP проксі з'являється в THREAT‑рядку → FAIL.

**24 комбінації:** 4 проксі × 6 backends.

---

#### 2.2 Cloudflare Cases

Всі CF-сценарії використовують `integration_cf_ext_net` (10.88.0.0/24) — IP атакуючого знаходиться за межами довіреного proxy CIDR (`172.16.0.0/12`). Це змушує backend'и витягувати real IP із `CF-Connecting-IP` / `X-Forwarded‑For`.

---

##### Case 1 — CF-Direct: cloudflare-sim → product (Scenario 10)

**Топологія:**
```
attacker (10.88.0.x) → cloudflare-sim → nginx/apache/traefik/caddy/haproxy/litespeed
```

`cloudflare-sim` переписує `X-Forwarded-For` у `$remote_addr` і додає заголовок `CF-Connecting-IP`.

**5 paths на backend:** `/wp-login.php`, `.env`, `.git/config`, `/admin/login.php`, `/xmlrpc.php`.

**Інваріант:** Лог загроз показує IP атакуючого, НЕ IP контейнера cloudflare-sim. Якщо з'являється IP CF‑sim → FAIL (class=cf-ip-leak).

---

##### Case 2 — CF-Chain: cloudflare-sim → our proxy → product (Scenario 11)

**Топологія:**
```
attacker (10.88.0.x) → cloudflare-sim → traefik/caddy/haproxy/nginx-rp → backend
```

Two‑hop ланцюжок: CF-заголовки встановлюються `cloudflare-sim`, потім проксі forwarding до backend.

**3 paths на пару (proxy, backend):** `/wp-login.php`, `.env`, `/xmlrpc.php`.

**Інваріант:** Той самий, що в Case 1 — лог загроз показує IP атакуючого. **72 перевірки** (4 проксі × 6 backends × 3 paths).

---

##### Case 3A — CF‑Broken: cloudflare-sim → nginx-bare (Scenario 12A)

`nginx-bare` НЕ має налаштованого `real_ip_header`. Він логує TCP peer (`IP cloudflare-sim` контейнера) як клієнта.

**2 запити:** `curl /wp-login.php` і `curl /.env` через `cloudflare-sim:80/cf-bare/`.

**Відповідь Chain‑Guard:** sentinel повинен виявити IP з діапазону Cloudflare → записує `cloudflare-ip-as-client` у `warnings/cf-broken.log`.

---

##### Case 3B — Bogon Injection (Scenario 12B)

`bogon-injector` додає `X-Forwarded-For: 10.0.0.1` перед forwarding до `nginx-bogon-victim`.

`nginx-bogon-victim` довіряє XFF, логує `10.0.0.1` як клієнта.

**Відповідь Chain‑Guard:** sentinel повинен виявити private IP RFC 1918 → записує `bogon-ip-as-client` у `warnings/bogon-victim.log`.

---

### 3. Safety Guards — Chain Guard

Chain Guard — це компонент sentinel'а, який моніторить логи backend'ів на предмет IP, які ніколи не повинні з'являтися як client IP:

| Warning Type | Condition                              | Log File                     |
|---|---|---|
| `cloudflare-ip-as-client` | Backend логує IP з діапазону Cloudflare як клієнта | `warnings/cf-broken.log`   |
| `bogon-ip-as-client`     | Backend логує private IP RFC 1918 як клієнта | `warnings/bogon-victim.log`|

**Верифікація:** `verify.sh` перевіряє, що кожен warning-файл містить очікуваний рядок. Відсутність = FAIL.

---

## Developer's Guide

### Adding a New Backend Server

1. **Додати сервер до масивів у `scenarios.sh` та `verify.sh`:**
   ```bash
   # scenarios.sh
   SERVERS=(nginx apache traefik caddy haproxy litespeed <NEW_SERVER>)
   
   # verify.sh
   SERVERS=(nginx apache traefik caddy haproxy litespeed <NEW_SERVER>)
   ```

2. **Створити sentinel config:** `arxsentinel/<NEW_SERVER>.yaml`
   - Налаштувати `real_ip_header` та `trusted_proxies`, якщо сервер знаходиться за проксі
   - Встановити відповідний `log_format` / `log_path` для парсингу access log

3. **Додати до docker‑compose.yml:** визначити контейнер `<NEW_SERVER>` з образом і мережами

4. **Оновити BADBOT_SERVERS у `verify.sh`, якщо новий сервер логує User-Agent:**
   ```bash
   BADBOT_SERVERS=(nginx apache traefik caddy haproxy litespeed <UA_LOGGING_SERVER>)
   ```
    *Всі 6 серверів у тестовому наборі логують UA — додавай новий, якщо він теж це робить.*

5. **Додати до proxy‑chain**, якщо новий сервер буде backend за проксі:
   - Зміни коду не потрібні — `CHAIN_BACKENDS` ітерує по всіх серверах
   - Переконатися, що проксі маршрутизує `/backend-<server>/` до правильного контейнера

6. **Додати до CF-сценаріїв**, якщо сервер повинен тестуватися в CF‑direct та CF‑chain:
   - Зміни коду не потрібні — `CHAIN_BACKENDS` покриває всі сервери
   - Налаштувати розміщення в мережі відповідно

### Adding a New Detector

1. **Додати сценарій до `scenarios.sh`:**
   ```bash
   run_scenario "<detector_name>" "$(attack_all '
   <curl commands using __SRV__ placeholder>
   ')"
   ```

2. **Додати до масиву MODULES у `verify.sh`:**
   ```bash
   MODULES=(probe ua bruteforce crawler noasset rate overflow <NEW_DETECTOR>)
   ```

3. **Налаштувати детектор** у кожному `arxsentinel/<SERVER>.yaml`:
   - Встановити відповідні пороги (`min_requests`, `threshold` тощо)
   - Переконатися, що формат лога включає поля, потрібні детектору

4. **Оновити очікувану кількість у документації** (цей README і матриця)

### Adding a New Proxy

1. **Додати до `CHAIN_PROXIES` у `scenarios.sh`:**
   ```bash
   CHAIN_PROXIES=(
       "traefik:80"
       "caddy:80"
       "haproxy:80"
       "nginx-rp:80"
       "<NEW_PROXY>:80"
   )
   ```

2. **Додати до `CF_CHAIN_PROXIES`** для CF Case 2:
   ```bash
   CF_CHAIN_PROXIES=(traefik caddy haproxy nginx-rp <NEW_PROXY>)
   ```

3. **Додати конфігурацію проксі** до `configs/` (наприклад, `nginx-rp.conf` для nginx reverse proxy)

4. **Додати до docker‑compose.yml:** визначити контейнер `<NEW_PROXY>` з мережами

5. **Переконатися, що маршрути налаштовані** так, щоб `/backend-<SERVER>/` проксувало до правильного backend-контейнера

### Key Arrays Reference

```bash
# scenarios.sh
SERVERS=(nginx apache traefik caddy haproxy litespeed)   # backends
CHAIN_PROXIES=(traefik:80 caddy:80 haproxy:80 nginx-rp:80)
CHAIN_BACKENDS=(nginx apache traefik caddy haproxy litespeed)

# verify.sh
SERVERS=(nginx apache traefik caddy haproxy litespeed)   # backends
MODULES=(probe ua bruteforce crawler noasset rate overflow)  # core 7
BADBOT_SERVERS=(nginx apache traefik caddy haproxy litespeed)  # 6 (всі сервери логують UA)
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
