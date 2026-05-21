# Деплой за обратным прокси

> **Внимание:** если HTTP-сервер стоит за прокси и реальный IP клиента настроен некорректно,
> ArxSentinel будет выставлять score **IP-адресу прокси**, а не реальному атакующему.
> Fail2Ban заблокирует ваш же прокси — сайт упадёт для всех.

## Как это работает

```
[Клиент 1.2.3.4] → [Прокси] → X-Forwarded-For: 1.2.3.4 → [HTTP-сервер]
                                                                   ↓
                                ngx_http_realip_module заменяет $remote_addr
                                первым не-доверенным IP из цепочки XFF
                                                                   ↓
                                                             access.log
                                                                   ↓
                                                            ArxSentinel
```

Модуль nginx `ngx_http_realip_module` читает `X-Forwarded-For` от доверенного прокси
и заменяет `$remote_addr` реальным IP клиента до того, как строка пишется в лог.
ArxSentinel читает `$remote_addr` из access.log — никакой дополнительной переменной не нужно.

## Готовые конфиги

Полные рабочие примеры для каждого прокси находятся в этой директории:

| Прокси | Файлы |
|--------|-------|
| **HAProxy** | [`haproxy/haproxy.cfg`](haproxy/haproxy.cfg), [`nginx.conf`](haproxy/nginx.conf) |
| **Traefik** | [`traefik/traefik.yml`](traefik/traefik.yml), [`nginx.conf`](traefik/nginx.conf) |
| **Caddy** | [`caddy/Caddyfile`](caddy/Caddyfile), [`nginx.conf`](caddy/nginx.conf) |
| **nginx как RP** | [`nginx-rp/nginx-upstream.conf`](nginx-rp/nginx-upstream.conf), [`nginx-origin.conf`](nginx-rp/nginx-origin.conf) |

Каждый пример содержит конфиг прокси и конфиг origin-nginx с `set_real_ip_from`,
`real_ip_header X-Forwarded-For`, `real_ip_recursive on` и форматом лога `combined_realip`,
в котором `$remote_addr` используется как поле реального IP.

## Минимальный конфиг nginx (для любого прокси)

```nginx
http {
    # Укажите реальный IP или CIDR вашего прокси.
    # Docker Compose: 172.16.0.0/12    Один хост: 127.0.0.1
    set_real_ip_from  <ip-или-cidr-прокси>;

    # Все основные прокси (HAProxy, Traefik, Caddy, nginx) выставляют X-Forwarded-For.
    real_ip_header    X-Forwarded-For;

    # Проходим по цепочке XFF — берём первый не-доверенный IP как реальный клиент.
    real_ip_recursive on;

    # После обработки realip $remote_addr — это и есть реальный IP клиента.
    log_format combined_realip
        '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent" "$remote_addr"';

    server {
        access_log /var/log/nginx/access.log combined_realip;
        ...
    }
}
```

## Cloudflare

Если nginx стоит напрямую за Cloudflare — используйте `CF-Connecting-IP` вместо `X-Real-IP`
(Cloudflare проставляет этот заголовок на своём edge; `X-Forwarded-For` может быть подделан клиентом).

Сгенерируйте директивы `set_real_ip_from` для всех CIDR-диапазонов Cloudflare:

```bash
sudo scripts/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf
```

Добавьте в `nginx.conf`:

```nginx
http {
    include /etc/nginx/cloudflare-real-ip.conf;  # set_real_ip_from для всех CF-диапазонов
    real_ip_header CF-Connecting-IP;
    ...
}
```

**Автообновление диапазонов** (Cloudflare обновляет их периодически):

```bash
# Добавить в cron — каждый понедельник в 03:00
0 3 * * 1 /path/to/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf && nginx -t && nginx -s reload
```

## Chain Guard — обнаружение сломанной цепочки IP

ArxSentinel непрерывно проверяет, является ли client IP в каждой записи лога реальным
маршрутизируемым адресом. Если обнаружен IP Cloudflare/CDN или bogon/CGNAT в позиции
клиента — записывает `CHAIN_WARN` в `warnings.log`.

**Почему это важно:** когда IP прокси фигурирует как client, все детекторы ArxSentinel
оценивают не тот адрес — они фактически слепые. Fail2Ban может заблокировать ваш
собственный Cloudflare edge вместо атакующего, положив сайт для всех посетителей.
Это ошибка конфигурации, а не атака.

**Что вызывает предупреждение:**

| Условие | Предупреждение | Исправление |
|---------|----------------|-------------|
| IP Cloudflare в позиции client | `cloudflare-ip-as-client` | Настройте `real_ip_header CF-Connecting-IP` (nginx), `RemoteIPHeader CF-Connecting-IP` (Apache), `trustedProxies` (Traefik/Caddy) |
| Bogon / RFC 1918 в позиции client | `bogon-ip-as-client` | Вышестоящий прокси инжектирует приватные IP в XFF; проверьте цепочку прокси и добавьте его IP в `set_real_ip_from` |
| CGNAT (100.64.0.0/10) в позиции client | `bogon-ip-as-client` | Carrier-grade NAT выше по цепочке — настройте `real_ip_header` для извлечения реального IP из XFF |

**Конфигурация:**

```yaml
chain_guard:
  enabled: true
  warnings_log: /var/log/arxsentinel/warnings.log
  cloudflare:
    enabled: true
    refresh_interval: 24h     # автоматически перезагружает CIDR-листы Cloudflare
    sources:
      - https://www.cloudflare.com/ips-v4/
      - https://www.cloudflare.com/ips-v6/
  bogon:
    enabled: true             # RFC 1918, CGNAT, loopback, link-local, документационные диапазоны
```

**Мониторинг warnings log:**

```bash
# Проверить наличие предупреждений chain guard
grep CHAIN_WARN /var/log/arxsentinel/warnings.log

# Подсчитать по типу
grep -c cloudflare-ip-as-client /var/log/arxsentinel/warnings.log
grep -c bogon-ip-as-client /var/log/arxsentinel/warnings.log
```
