# Обновление ArxSentinel

## Перед началом

- Это руководство охватывает обновление с v1.x на v2.x (текущая версия разработки: v2.x).
- v2.x обратно совместима — существующие файлы `config.yaml` продолжат работать без изменений.
- Прочитайте полный [релиз-ноут v2.0.0](https://github.com/mr-addams/arxsentinel/releases/tag/v2.0.0) для полного списка изменений.

---

## v1.x → v2.x

### Что изменилось

| Изменение | v1.x | v2.x |
|---|---|---|
| **Executors** (плагины с состоянием) | Недоступны | Новый тип плагина — см. [docs/executors.md](executors.md) |
| **Интеграция Cloudflare WAF** | Недоступна | CloudflareExecutor с управлением IP-списками — см. [docs/executor-cloudflare.md](executor-cloudflare.md) |
| **Секция конфига** | Нет ключа `executors:` | Новая секция верхнего уровня `executors:` (опциональна, обратно совместима) |
| **Путь к бинарнику** | `/usr/local/bin/arxsentinel` | `/usr/bin/arxsentinel` (стандартизирован в упакованной установке) |
| **Команда `check-config`** | Недоступна | `arxsentinel check-config <path>` — проверяет конфиг на совместимость с v2 без запуска daemon |
| **Извлечение IP клиента** | Статическая настройка `real_ip` | ChainGuard автоматически обнаруживает неправильно настроенные цепочки прокси |
| **Путь к конфигу** | `/etc/arxsentinel/config.yaml` | `/etc/arxsentinel/config.yaml` (не изменился) |

**Замечания по обратной совместимости:**

- Конфиги из v1.x работают в v2.x без каких-либо изменений — секция `executors:` полностью опциональна.
- Существующие Sinks (`output.threat_log`, Fail2Ban) продолжают работать параллельно или вместо Executors.
- Блок systemd-сервиса обновляется для отражения нового пути к бинарнику. Пакетные менеджеры обрабатывают это автоматически при обновлении.

### Шаги обновления

#### 1. Создайте резервную копию конфига

```bash
sudo cp /etc/arxsentinel/config.yaml ~/arxsentinel-config-backup.yaml
sudo cp -r /etc/arxsentinel/ ~/arxsentinel-backup/
```

#### 2. Установите пакет v2.x

**Вариант A — Быстрый установщик (рекомендуется, любой дистрибутив):**

Установщик автоматически определяет ваш дистрибутив и архитектуру, загружает правильный пакет из GitHub Releases и выполняет обновление на месте.

```bash
# Последний стабильный релиз
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash

# Последний dev pre-release
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash -s -- --dev

# Конкретная версия/тег
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash -s -- --version <latest>
```

**Вариант B — Debian / Ubuntu (ручной):**

Загрузите пакет `.deb` для вашей архитектуры со страницы [Releases](https://github.com/mr-addams/arxsentinel/releases) и установите его:

```bash
sudo apt install ./arxsentinel_<version>_linux_amd64.deb
```

Пример вывода:

```
Selecting previously unselected package arxsentinel.
(Reading database… 817847 files and directories currently installed.)
Preparing to unpack arxsentinel_<version>_linux_amd64.deb…
Unpacking arxsentinel (<version>)…
Processing triggers for kali-menu (2026.2.5)…
```

**Вариант C — Fedora / RHEL / AlmaLinux / Rocky Linux:**

```bash
sudo dnf install ./arxsentinel_<version>_linux_amd64.rpm
```

**Вариант D — Arch Linux / Manjaro:**

```bash
sudo pacman -U arxsentinel_<version>_linux_amd64.pkg.tar.zst
```

> Пакет v2 **не перезаписывает** ваш существующий конфиг. Пакетные менеджеры сохраняют `/etc/arxsentinel/config.yaml` при обновлении.

#### 3. Проверьте совместимость конфига

v2.x представляет новую подкоманду `check-config`, которая проверяет ваш конфиг соответственно схеме v2:

```bash
sudo arxsentinel check-config /etc/arxsentinel/config.yaml
```

Если вывод не показывает ошибок, ваш конфиг полностью совместим с v2.x.

> **Что проверяется:** обязательные поля, структура YAML, полнота конфигурации детектора (ограничение yaml.v3 — все поля должны присутствовать в секции, если секция существует) и опциональный синтаксис `executors:` (если присутствует).

#### 4. Перезагрузите сервис

```bash
sudo systemctl daemon-reload    # перезагрузить обновленный блок systemd
sudo systemctl restart arxsentinel
```

Проверьте, что сервис запустился корректно:

```bash
sudo systemctl status arxsentinel
```

Ожидаемый вывод (здоровое состояние):

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

Проверьте операционный лог для баннера запуска:

```bash
tail -f /var/log/arxsentinel/sentinel.log
```

Ожидается:

```
2026-05-28 16:55:07 [STARTUP] arxsentinel v2.x started
2026-05-28 16:55:07 [STATS] processed=0 tracked=0 threats=0 suspicious=0
```

#### 5. (Опционально) Включите CloudflareExecutor

Если ваше развертывание использует Cloudflare CDN, добавьте секцию `executors:` в ваш конфиг:

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

Затем проверьте и перезагрузите:

```bash
sudo arxsentinel check-config /etc/arxsentinel/config.yaml
sudo systemctl kill -s HUP arxsentinel   # перезагрузить без перезагрузки
```

См. [docs/executor-cloudflare.md](executor-cloudflare.md) для:
- Требуемых разрешений API-токена Cloudflare
- Настройки правил WAF для использования IP-списка
- Настройки `min_level` и `ttl` для вашей среды
- Решение типичных проблем

#### 6. Проверьте pipeline обнаружения угроз

После обновления подтвердите, что обнаружение угроз работает с быстрым тестом зонда:

```bash
# Имитировать запрос-зонд (настройте путь, чтобы соответствовать вашему серверу)
curl -s -o /dev/null -w "%{http_code}" http://your-server.com/.env

# Проверьте, что ArxSentinel его зафиксировал
sudo journalctl -u arxsentinel --since "1 min ago" | grep -i threat
```

Ожидается: тест зонда должен появиться как запись `THREAT` в операционном логе в окне наблюдения.

#### 7. Проверьте метрики Prometheus (если включены)

```bash
curl -s http://127.0.0.1:9117/metrics | grep arx_sentinel
```

Ожидается: векторы метрик включают новые метки `executor`, если настроены какие-либо executors.

---

## Откат

Если обновление v2.x вызывает проблемы, выполните откат на последний известный хороший релиз v1.x.

#### 1. Остановите сервис v2.x

```bash
sudo systemctl stop arxsentinel
```

#### 2. Понизьте версию пакета

**Debian / Ubuntu:**

```bash
# Загрузите последний пакет v1.x (при необходимости отрегулируйте версию)
wget https://github.com/mr-addams/arxsentinel/releases/download/v1.3.9/arxsentinel_1.3.9_linux_amd64.deb
sudo apt install ./arxsentinel_1.3.9_linux_amd64.deb
```

**Fedora / RHEL / AlmaLinux / Rocky Linux:**

```bash
sudo dnf install ./arxsentinel_1.3.9_linux_amd64.rpm --oldpackage
```

**Arch Linux / Manjaro:**

```bash
# Понизьте версию через кэш pacman или из старого файла пакета
sudo pacman -U /var/cache/pacman/pkg/arxsentinel-1.3.9-1-x86_64.pkg.tar.zst
```

#### 3. Восстановите конфиг v1.x (если требуется)

Пакетный менеджер сохраняет ваш файл конфига при обновлении и откате. Если конфиг v2.x имеет несовместимые изменения, восстановите вашу резервную копию:

```bash
sudo cp ~/arxsentinel-config-backup.yaml /etc/arxsentinel/config.yaml
```

#### 4. Удалите любую секцию `executors:` из конфига

v1.x не распознает ключ `executors:`. Если вы добавили его при пробе v2.x, удалите или закомментируйте секцию:

```bash
sudo nano /etc/arxsentinel/config.yaml
# Удалите или закомментируйте блок executors:
```

#### 5. Перезагрузите сервис v1.x

```bash
sudo systemctl daemon-reload
sudo systemctl restart arxsentinel
```

Проверьте, что сервис запустился с версией v1.x:

```bash
sudo journalctl -u arxsentinel --since "1 min ago" | grep STARTUP
```

Ожидается:

```
2026-05-28 17:00:00 [STARTUP] arxsentinel v1.3.9 started
```

#### 6. (При необходимости) Очистите записи IP-списка Cloudflare

Если вы использовали CloudflareExecutor при пробе v2.x, записи IP-списка, созданные v2.x, останутся в вашем аккаунте Cloudflare после отката. Удалите их вручную из панели управления Cloudflare или через API:

```bash
curl -X DELETE "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/rules/lists/YOUR_LIST_ID/items" \
  -H "Authorization: Bearer YOUR_CF_API_TOKEN" \
  -H "Content-Type: application/json"
```

> Сам IP-список можно оставить на месте — он не повлияет ни на что, пока на него не ссылается правило WAF.

---

## Справочник совместимости версий

| Версия ArxSentinel | Путь к бинарнику | Путь к конфигу | Поддержка Executors | Замечания |
|---|---|---|---|---|
| v1.3.9 (последний v1.x) | `/usr/local/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | Нет | Последний релиз v1.x со всеми функциями v1 |
| v2.0.0 | `/usr/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | Да | Первый стабильный релиз v2.x |
| latest dev | `/usr/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | Да | Активная разработка — см. [Releases](https://github.com/mr-addams/arxsentinel/releases) |

---

## Решение проблем

### Сервис не запускается с `exit-code 217/USER`

Системный пользователь `arxsentinel` не был создан или отсутствует при обновлении.

**Решение:**

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin arxsentinel
sudo systemctl restart arxsentinel
```

### `arxsentinel check-config` возвращает ошибки валидации

**Частые причины:**

1. **Неполные секции** — присутствующая секция должна включать **все** свои поля (ограничение yaml.v3). Добавьте отсутствующие поля из конфига по умолчанию.
2. **Неизвестные ключи** — v2.x не распознает ключи из очень старых конфигов v1.x. Удалите или переименуйте их.
3. **Ошибки конфига executor** — если секция `executors:` присутствует, все поля, специфичные для executor, должны быть действительными (см. [docs/executor-cloudflare.md](executor-cloudflare.md)).

Проверьте конкретное сообщение об ошибке и отрегулируйте соответствующую секцию.

### Fail2Ban перестает банить после обновления

Формат лога угроз не изменился — failregex `THREAT <HOST>` все еще работает. Проверьте:

```bash
fail2ban-regex /var/log/arxsentinel/threats.log /etc/fail2ban/filter.d/arxsentinel.conf
```

Если пакет Fail2Ban был переустановлен при обновлении, заново включите jail arxsentinel:

```bash
sudo fail2ban-client reload
sudo fail2ban-client status arxsentinel
```

---

## Дополнительные ресурсы

- [docs/executors.md](executors.md) — Обзор framework Executor и разработка пользовательского executor
- [docs/executor-cloudflare.md](executor-cloudflare.md) — Полное руководство настройки CloudflareExecutor
- [README.md](../README.md) — Основная документация проекта
- [GitHub Releases](https://github.com/mr-addams/arxsentinel/releases) — Релиз-ноуты и загрузка пакетов
