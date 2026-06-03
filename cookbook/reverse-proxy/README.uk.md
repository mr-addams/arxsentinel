# Деплой за зворотним проксі

> **Увага:** якщо HTTP-сервер стоїть за проксі і реальний IP клієнта налаштований некоректно,
> ArxSentinel виставлятиме score **IP-адресі проксі**, а не реальному зловмиснику.
> Fail2Ban заблокує ваш же проксі — сайт впаде для всіх.

> **Примітка:** ArxSentinel читає access-логи там, де веб-сервер уже вилучив реальний IP клієнта.
> У конфігу sentinel не потрібні ніякі `trusted_proxies` чи специфічні для проксі налаштування —
> це повністю відповідальність веб-сервера.

## Як це працює

```
[Клієнт 1.2.3.4] → [Проксі] → X-Forwarded-For: 1.2.3.4 → [HTTP-сервер]
                                                                  ↓
                               ngx_http_realip_module замінює $remote_addr
                               першим не-довіреним IP з ланцюжка XFF
                                                                  ↓
                                                            access.log
                                                                  ↓
                                                           ArxSentinel
```

Модуль nginx `ngx_http_realip_module` читає `X-Forwarded-For` від довіреного проксі
та замінює `$remote_addr` реальним IP клієнта до того, як рядок записується в лог.
ArxSentinel читає `$remote_addr` з access.log — жодної додаткової змінної не потрібно.

## Готові конфіги

Повні робочі приклади для кожного проксі знаходяться в цій директорії:

| Проксі | Файли |
|--------|-------|
| **HAProxy** | [`haproxy/haproxy.cfg`](haproxy/haproxy.cfg), [`nginx.conf`](haproxy/nginx.conf) |
| **Traefik** | [`traefik/traefik.yml`](traefik/traefik.yml), [`nginx.conf`](traefik/nginx.conf) |
| **Caddy** | [`caddy/Caddyfile`](caddy/Caddyfile), [`nginx.conf`](caddy/nginx.conf) |
| **nginx як RP** | [`nginx-rp/nginx-upstream.conf`](nginx-rp/nginx-upstream.conf), [`nginx-origin.conf`](nginx-rp/nginx-origin.conf) |

Кожен приклад містить конфіг проксі та конфіг origin-nginx з `set_real_ip_from`,
`real_ip_header X-Forwarded-For`, `real_ip_recursive on` і форматом лога `combined_realip`,
в якому `$remote_addr` використовується як поле реального IP.

## Мінімальний конфіг nginx (для будь-якого проксі)

```nginx
http {
    # Вкажіть реальний IP або CIDR вашого проксі.
    # Docker Compose: 172.16.0.0/12    Один хост: 127.0.0.1
    set_real_ip_from  <ip-або-cidr-проксі>;

    # Всі основні проксі (HAProxy, Traefik, Caddy, nginx) виставляють X-Forwarded-For.
    real_ip_header    X-Forwarded-For;

    # Проходимо по ланцюжку XFF — беремо перший не-довірений IP як реального клієнта.
    real_ip_recursive on;

    # Після обробки realip $remote_addr — це і є реальний IP клієнта.
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

Якщо nginx стоїть напряму за Cloudflare — використовуйте `CF-Connecting-IP`
(Cloudflare проставляє цей заголовок на своєму edge; `X-Forwarded-For` може бути підроблений клієнтом).

Згенеруйте директиви `set_real_ip_from` для всіх CIDR-діапазонів Cloudflare:

```bash
sudo scripts/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf
```

Додайте до `nginx.conf`:

```nginx
http {
    include /etc/nginx/cloudflare-real-ip.conf;  # set_real_ip_from для всіх CF-діапазонів
    real_ip_header CF-Connecting-IP;
    real_ip_recursive on;  # ОБОВ'ЯЗКОВИЙ при CF → proxy → origin
    ...
}
```

**Чому `real_ip_recursive on` обов'язковий для ланцюжка CF → proxy → origin:**

Коли Cloudflare на краю, трафік йде: `[Клієнт] → [CF edge] → [Ваш проксі] → [nginx origin]`.

XFF-ланцюжок приходить у nginx як:
```
X-Forwarded-For: <attacker-ip>, <cloudflare-edge-ip>, <your-proxy-ip>, ...
```

Без `real_ip_recursive on` nginx використовує `CF-Connecting-IP` для вилучення CF-IP
і видаляє її з ланцюжка. Але **на цьому зупиняється** — розглядаючи перше залишкове
значення в XFF (IP вашого проксі) як не-доверене й залишаючи його як `$remote_addr`.
Результат: ArxSentinel бачить IP проксі, а не зловмисника.

З `real_ip_recursive on` nginx продовжує проходити XFF-ланцюжком: бачить, що IP проксі
теж у `set_real_ip_from`, видаляє його, і продовжує, поки не знайде перший не-доверений IP
(справжнього зловмисника). Приклад:

```
X-Forwarded-For: 203.0.113.50, 104.16.0.1, 192.168.1.100
                 ↑attacker     ↑CF edge       ↑your proxy
                                                         ↓
real_ip_recursive проходить ланцюжок: CF edge — доверений (видалений),
IP проксі — доверений (видалений), IP зловмисника залишився → $remote_addr = 203.0.113.50
```

Без рекурсії nginx зупинився б після видалення CF edge, залишивши IP проксі як `$remote_addr`.

**Автооновлення діапазонів** (Cloudflare оновлює їх периодично):

```bash
# Додати в cron — кожен понеділок о 03:00
0 3 * * 1 /path/to/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf && nginx -t && nginx -s reload
```

## Origin-сервери не-nginx за проксі

Якщо origin-сервер **не nginx** — HAProxy, Traefik, Caddy, Apache або LiteSpeed —
діє той же принцип: origin має **логувати справжній IP клієнта** (з `X-Forwarded-For`
або еквівалента), і ArxSentinel читає цей лог. Ось мінімальні конфіги для кожного:

### HAProxy

```haproxy
frontend http-in
    bind *:80
    http-request set-var(txn.client_ip) req.hdr_ip(X-Forwarded-For,1)
    log-format "%[var(txn.client_ip)]:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %{+Q}r"
```

`req.hdr_ip(X-Forwarded-For,1)` вилучає перший IP з XFF-ланцюжка — справжнього клієнта.
Логування цього замість `%ci` (прямого пірного IP) гарантує, що ArxSentinel оцінить
зловмисника, а не вищестоящий проксі.

### Traefik

```yaml
entryPoints:
  web:
    address: ":80"
    forwardedHeaders:
      trustedIPs:
        - "172.16.0.0/12"  # Docker-підмережа або CIDR вашого проксі
```

Параметр `trustedIPs` наказує Traefik довіряти `X-Forwarded-For` з цієї підмережі.
Без цього Traefik ігнорує вхідний XFF і логує IP проксі.

### Caddy

```caddy
:80 {
    reverse_proxy upstream-server:80
    log {
        output file /var/log/caddy/access.log
        format transform `{request>headers>X-Forwarded-For>[0]:request>remote_ip} - - [{ts}] "{request>method} {request>uri} {request>proto}" {status} {size} "{request>headers>Referer>[0]}" "{request>headers>User-Agent>[0]}"` {
            time_format "02/Jan/2006:15:04:05 -0700"
        }
    }
}
```

Формат логу transform читає `X-Forwarded-For[0]` (справжній IP клієнта) і виводить
його як поле remote_ip в Apache CLF — сумісно з парсерами ArxSentinel.

### LiteSpeed

```python
# У patch-ols-logformat.py (запустити на етапі build контейнера):
LOG_FORMAT_LINE = '    logFormat             "%{X-Forwarded-For}i %l %u %t \\"%r\\" %>s %b"\n'
```

У LiteSpeed формат логу використовує Apache-стиль `%{X-Forwarded-For}i` для логування
значення XFF-заголовка як IP клієнта. Цей формат відповідає профілю `litespeed` ArxSentinel.

## Chain Guard — виявлення зламаного ланцюжка IP

ArxSentinel безперервно перевіряє, чи є client IP у кожному записі логу справжньою
маршрутизованою адресою. Якщо виявлено IP Cloudflare/CDN або bogon/CGNAT у позиції
клієнта — записує `CHAIN_WARN` до `warnings.log`.

**Чому це важливо:** коли IP проксі фігурує як client, всі детектори ArxSentinel
оцінюють не ту адресу — вони фактично сліпі. Fail2Ban може заблокувати ваш власний
Cloudflare edge замість зловмисника, поклавши сайт для всіх відвідувачів.
Це помилка конфігурації, а не атака.

**Що викликає попередження:**

| Умова | Попередження | Виправлення |
|-------|--------------|-------------|
| IP Cloudflare у позиції client | `cloudflare-ip-as-client` | Налаштуйте `real_ip_header CF-Connecting-IP` (nginx), `RemoteIPHeader CF-Connecting-IP` (Apache), `trustedProxies` (Traefik/Caddy) |
| Bogon / RFC 1918 у позиції client | `bogon-ip-as-client` | Вищестоящий проксі інжектує приватні IP у XFF; перевірте ланцюжок проксі та додайте його IP до `set_real_ip_from` |
| CGNAT (100.64.0.0/10) у позиції client | `bogon-ip-as-client` | Carrier-grade NAT вище по ланцюжку — налаштуйте `real_ip_header` для вилучення справжнього IP з XFF |

**Конфігурація:**

```yaml
chain_guard:
  enabled: true
  warnings_log: /var/log/arxsentinel/warnings.log
  cloudflare:
    enabled: true
    refresh_interval: 24h     # автоматично перезавантажує CIDR-листи Cloudflare
    sources:
      - https://www.cloudflare.com/ips-v4/
      - https://www.cloudflare.com/ips-v6/
  bogon:
    enabled: true             # RFC 1918, CGNAT, loopback, link-local, документаційні діапазони
```

**Моніторинг warnings log:**

```bash
# Перевірити наявність попереджень chain guard
grep CHAIN_WARN /var/log/arxsentinel/warnings.log

# Підрахувати за типом
grep -c cloudflare-ip-as-client /var/log/arxsentinel/warnings.log
grep -c bogon-ip-as-client /var/log/arxsentinel/warnings.log
```
