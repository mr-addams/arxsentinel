# Оновлення ArxSentinel

## Перш ніж почати

- Цей посібник охоплює оновлення з v1.x до v2.x (поточна версія розробки: v2.x).
- v2.x є зворотно сумісною — наявні файли `config.yaml` продовжать працювати без змін.
- Прочитайте повний [реліз-ноут v2.0.0](https://github.com/mr-addams/arxsentinel/releases/tag/v2.0.0) для повного списку змін.

---

## v1.x → v2.x

### Що змінилося

| Зміна | v1.x | v2.x |
|---|---|---|
| **Executors** (stateful action плагіни) | Недоступно | Новий тип плагінів — див. [docs/executors.md](executors.md) |
| **Інтеграція з Cloudflare WAF** | Недоступно | CloudflareExecutor з управлінням IP-списком — див. [docs/executor-cloudflare.md](executor-cloudflare.md) |
| **Секція конфігурації** | Немає ключа `executors:` | Нова секція верхнього рівня `executors:` (необов'язкова, зворотно сумісна) |
| **Шлях до бінарного файлу** | `/usr/local/bin/arxsentinel` | `/usr/bin/arxsentinel` (стандартизовано в пакунковій інсталяції) |
| **Команда `check-config`** | Недоступно | `arxsentinel check-config <path>` — перевіряє конфіг на сумісність з v2 без запуску демона |
| **Витягування IP клієнта** | Статичне налаштування `real_ip` | ChainGuard автоматично виявляє некоректно налаштовані proxy-ланцюги |
| **Шлях до конфігурації** | `/etc/arxsentinel/config.yaml` | `/etc/arxsentinel/config.yaml` (без змін) |

**Нотатки щодо зворотної сумісності:**

- Конфігурації з v1.x працюють у v2.x без жодних змін — секція `executors:` є повністю необов'язковою.
- Наявні Sinks (`output.threat_log`, Fail2Ban) продовжують працювати поряд з Executors або замість них.
- Systemd-юніт сервісу оновлюється відповідно до нового шляху бінарного файлу. Менеджери пакунків обробляють це автоматично під час оновлення.

### Кроки оновлення

#### 1. Зробіть резервну копію конфігурації

```bash
sudo cp /etc/arxsentinel/config.yaml ~/arxsentinel-config-backup.yaml
sudo cp -r /etc/arxsentinel/ ~/arxsentinel-backup/
```

#### 2. Встановіть пакунок v2.x

**Варіант A — Швидкий інсталятор (рекомендовано, будь-який дистрибутив):**

Інсталятор автоматично визначає ваш дистрибутив та архітектуру, завантажує відповідний пакунок з GitHub Releases і виконує оновлення на місці.

```bash
# Останній стабільний реліз
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash

# Останній dev пре-реліз
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash -s -- --dev

# Конкретна версія/тег
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash -s -- --version <latest>
```

**Варіант B — Debian / Ubuntu (вручну):**

Завантажте пакунок `.deb` для вашої архітектури зі сторінки [Releases](https://github.com/mr-addams/arxsentinel/releases) та встановіть його:

```bash
sudo apt install ./arxsentinel_<version>_linux_amd64.deb
```

Приклад виводу:

```
Selecting previously unselected package arxsentinel.
(Reading database… 817847 files and directories currently installed.)
Preparing to unpack arxsentinel_<version>_linux_amd64.deb…
Unpacking arxsentinel (<version>)…
Processing triggers for kali-menu (2026.2.5)…
```

**Варіант C — Fedora / RHEL / AlmaLinux / Rocky Linux:**

```bash
sudo dnf install ./arxsentinel_<version>_linux_amd64.rpm
```

**Варіант D — Arch Linux / Manjaro:**

```bash
sudo pacman -U arxsentinel_<version>_linux_amd64.pkg.tar.zst
```

> Пакунок v2 **не перезаписує** вашу наявну конфігурацію. Менеджери пакунків зберігають `/etc/arxsentinel/config.yaml` під час оновлення.

#### 3. Перевірте сумісність конфігурації

v2.x представляє нову підкоманду `check-config`, яка перевіряє вашу конфігурацію за схемою v2:

```bash
sudo arxsentinel check-config /etc/arxsentinel/config.yaml
```

Якщо вивід не показує помилок, ваша конфігурація повністю сумісна з v2.x.

> **Що перевіряється:** обов'язкові поля, структура YAML, повнота конфігурації детекторів (обмеження yaml.v3 — всі поля мають бути присутні в секції, якщо секція існує), та опціональний синтаксис `executors:` (якщо присутній).

#### 4. Перезапустіть сервіс

```bash
sudo systemctl daemon-reload    # перезавантажити оновлений systemd-юніт
sudo systemctl restart arxsentinel
```

Перевірте, що сервіс запустився коректно:

```bash
sudo systemctl status arxsentinel
```

Очікуваний вивід (здоровий стан):

```
● arxsentinel.service - ArxSentinel — threat detector for nginx access logs
     Loaded: loaded (/usr/lib/systemd/system/arxsentinel.service; enabled; preset: enabled)
     Active: active (running) since Thu 2026-05-28 16:55:07 IST; 31ms ago
   Main PID: 1768456 (arxsentinel)
      Tasks: 6 (limit: 23195)
     Memory: 12.5M
        CPU: 18ms
      CGroup: /system.slice/arxsentinel.service
             └─1768456 /usr/bin/arxsentinel
```

Перевірте банер запуску в операційному журналі:

```bash
tail -f /var/log/arxsentinel/sentinel.log
```

Очікувано:

```
2026-05-28 16:55:07 [STARTUP] arxsentinel v2.x started
2026-05-28 16:55:07 [STATS] processed=0 tracked=0 threats=0 suspicious=0
```

#### 5. (Необов'язково) Увімкніть CloudflareExecutor

Якщо ваше розгортання працює за Cloudflare CDN, додайте секцію `executors:` до вашої конфігурації:

```yaml
executors:
  - name: cloudflare-blocklist
    type: cloudflare
    config:
      api_token: "YOUR_CF_API_TOKEN"
      account_id: "YOUR_CF_ACCOUNT_ID"
      list_name: "arxsentinel_blocklist"
      min_level: "THREAT"
      ttl: "24h"
```

Потім перевірте та перезавантажте:

```bash
sudo arxsentinel check-config /etc/arxsentinel/config.yaml
sudo systemctl kill -s HUP arxsentinel   # перезавантажити без перезапуску
```

Див. [docs/executor-cloudflare.md](executor-cloudflare.md) для:
- Необхідних дозволів Cloudflare API токена
- Налаштування WAF-правил для використання IP-списку
- Тюнінгу `min_level` та `ttl` під ваше середовище
- Вирішення типових проблем

#### 6. Перевірте пайплайн виявлення

Після оновлення переконайтеся, що виявлення загроз працює, за допомогою швидкого тесту-проби:

```bash
# Симулюйте запит-пробу (відкоригуйте шлях під ваш сервер)
curl -s -o /dev/null -w "%{http_code}" http://your-server.com/.env

# Перевірте, що ArxSentinel залогував це
sudo journalctl -u arxsentinel --since "1 min ago" | grep -i threat
```

Очікувано: тест-проба має з'явитися як запис `THREAT` в операційному журналі протягом вікна спостереження.

#### 7. Перевірте метрики Prometheus (якщо увімкнено)

```bash
curl -s http://127.0.0.1:9117/metrics | grep arx_sentinel
```

Очікувано: вектори метрик містять нові мітки `executor`, якщо налаштовано будь-які executors.

---

## Відкат

Якщо оновлення v2.x спричиняє проблеми, відкотиться до останнього відомого робочого релізу v1.x.

#### 1. Зупиніть сервіс v2.x

```bash
sudo systemctl stop arxsentinel
```

#### 2. Відкотити пакунок

**Debian / Ubuntu:**

```bash
# Завантажте останній пакунок v1.x (відкоригуйте версію за потребою)
wget https://github.com/mr-addams/arxsentinel/releases/download/v1.3.9/arxsentinel_1.3.9_linux_amd64.deb
sudo apt install ./arxsentinel_1.3.9_linux_amd64.deb
```

**Fedora / RHEL / AlmaLinux / Rocky Linux:**

```bash
sudo dnf install ./arxsentinel_1.3.9_linux_amd64.rpm --oldpackage
```

**Arch Linux / Manjaro:**

```bash
# Відкат через кеш pacman або старіший файл пакунка
sudo pacman -U /var/cache/pacman/pkg/arxsentinel-1.3.9-1-x86_64.pkg.tar.zst
```

#### 3. Відновіть конфігурацію v1.x (якщо потрібно)

Менеджер пакунків зберігає ваш файл конфігурації під час оновлення та відкату. Якщо конфігурація v2.x має несумісні зміни, відновіть вашу резервну копію:

```bash
sudo cp ~/arxsentinel-config-backup.yaml /etc/arxsentinel/config.yaml
```

#### 4. Видаліть будь-яку секцію `executors:` з конфігурації

v1.x не розпізнає ключ `executors:`. Якщо ви додали його під час тестування v2.x, видаліть або закоментуйте секцію:

```bash
sudo nano /etc/arxsentinel/config.yaml
# Видаліть або закоментуйте блок executors:
```

#### 5. Перезапустіть сервіс v1.x

```bash
sudo systemctl daemon-reload
sudo systemctl restart arxsentinel
```

Перевірте, що сервіс запустився з версією v1.x:

```bash
sudo journalctl -u arxsentinel --since "1 min ago" | grep STARTUP
```

Очікувано:

```
2026-05-28 17:00:00 [STARTUP] arxsentinel v1.3.9 started
```

#### 6. (Якщо застосовно) Очистіть записи IP-списку Cloudflare

Якщо ви використовували CloudflareExecutor під час тестування v2.x, записи IP-списку, створені v2.x, залишаються у вашому обліковому записі Cloudflare після відкату. Видаліть їх вручну з дашборду Cloudflare або через API:

```bash
curl -X DELETE "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/rules/lists/YOUR_LIST_ID/items" \
  -H "Authorization: Bearer YOUR_CF_API_TOKEN" \
  -H "Content-Type: application/json"
```

> Сам IP-список можна залишити — він ні на що не впливатиме, якщо на нього не посилається WAF-правило.

---

## Довідник сумісності версій

| Версія ArxSentinel | Шлях до бінарного файлу | Шлях до конфігурації | Підтримка Executors | Нотатки |
|---|---|---|---|---|
| v1.3.9 (остання v1.x) | `/usr/local/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | Ні | Останній реліз v1.x з усіма можливостями v1 |
| v2.0.0 | `/usr/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | Так | Перший стабільний реліз v2.x |
| latest dev | `/usr/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | Так | Активна розробка — див. [Releases](https://github.com/mr-addams/arxsentinel/releases) |

---

## Усунення проблем

### Сервіс не запускається з `exit-code 217/USER`

Системний користувач `arxsentinel` не був створений або відсутній під час оновлення.

**Виправлення:**

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin arxsentinel
sudo systemctl restart arxsentinel
```

### `arxsentinel check-config` повертає помилки валідації

**Типові причини:**

1. **Неповні секції** — присутня секція повинна включати **всі** свої поля (обмеження yaml.v3). Додайте відсутні поля з конфігурації за замовчуванням.
2. **Невідомі ключі** — v2.x не розпізнає ключі з дуже старих конфігурацій v1.x. Видаліть або перейменуйте їх.
3. **Помилки конфігурації Executor** — якщо секція `executors:` присутня, всі специфічні для executor поля мають бути валідними (див. [docs/executor-cloudflare.md](executor-cloudflare.md)).

Перевірте конкретне повідомлення про помилку та відкоригуйте відповідну секцію.

### Fail2Ban припиняє блокування після оновлення

Формат журналу загроз не змінився — failregex `THREAT <HOST>` все ще працює. Перевірте:

```bash
fail2ban-regex /var/log/arxsentinel/threats.log /etc/fail2ban/filter.d/arxsentinel.conf
```

Якщо пакунок Fail2Ban був перевстановлений під час оновлення, повторно увімкніть jail arxsentinel:

```bash
sudo fail2ban-client reload
sudo fail2ban-client status arxsentinel
```

---

## Додаткові ресурси

- [docs/executors.md](executors.md) — Огляд фреймворку Executors та розробка власних executor
- [docs/executor-cloudflare.md](executor-cloudflare.md) — Повний посібник з налаштування CloudflareExecutor
- [README.md](../README.md) — Головна документація проєкту
- [GitHub Releases](https://github.com/mr-addams/arxsentinel/releases) — Нотатки до релізів та завантаження пакунків