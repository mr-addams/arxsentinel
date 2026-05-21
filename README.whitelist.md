# Whitelist

The whitelist tells ArxSentinel: "these are friendly — skip them entirely." There are two independent mechanisms: **automatic bot verification** (search engines) and **custom exclusions** (your own IPs, subnets, tools).

## Automatic bot verification (Googlebot, Bingbot, Yandex, etc.)

ArxSentinel knows the User-Agent strings of all major search bots. When a bot arrives, it performs a DNS check to confirm the bot is genuine:

1. Reverse-DNS lookup on the IP → gets a hostname (e.g. `crawl-66-249-66-1.googlebot.com`)
2. Forward-DNS on that hostname → must resolve back to the same IP
3. The hostname must end with one of Google's known domains (`.googlebot.com`, `.google.com`)

If both checks pass → the bot is legitimate → skipped, no score added.  
If the checks fail → the UA claims to be Googlebot but the IP is not Google → `fake_bot_score` penalty (default 35) is added instead.

Built-in verified bots: Google, Bing, Yandex, DuckDuckBot, Baidu, Apple, GPTBot, ClaudeBot, and others — see the `whitelist.bots` section in `config.yaml`.

**No configuration needed** — verification is automatic. DNS results are cached (`dns_cache.positive_ttl: 24h`) so it doesn't slow down processing.

## Custom whitelist

Add your own IPs, subnets, and tools to the `whitelist.custom` section:

```yaml
whitelist:
  custom:
    ips:           []
    cidrs:         []
    ua_substrings: []
```

Requests matching any entry are skipped **before** any detector runs — no score is ever added.

---

### `ips` — specific IP addresses

List individual IP addresses that should never be checked.

```yaml
whitelist:
  custom:
    ips:
      - "192.168.1.50"    # office workstation
      - "10.99.99.1"      # internal monitoring server
      - "203.0.113.42"    # your home IP
```

Use this for: your own servers, known partners, office machines, developer laptops.

---

### `cidrs` — IP ranges (subnets)

A CIDR is a compact way to write a range of IP addresses. Instead of listing hundreds of IPs, you write one line.

How to read it: `192.168.1.0/24` means "all addresses from `192.168.1.0` to `192.168.1.255`" — an entire block of 256 addresses. The number after `/` tells how many addresses are in the block:

| Notation | Range | Addresses |
|----------|-------|-----------|
| `10.0.0.1/32` | exactly `10.0.0.1` | 1 (single IP) |
| `192.168.1.0/24` | `192.168.1.0` – `192.168.1.255` | 256 |
| `10.0.0.0/8` | `10.0.0.0` – `10.255.255.255` | ~16 million |

```yaml
whitelist:
  custom:
    cidrs:
      - "192.168.0.0/16"    # entire office/VPN network
      - "10.0.0.0/8"        # all private 10.x.x.x addresses
      - "172.16.0.0/12"     # Docker / internal network
```

> **How to find your subnet?** Ask your system administrator, or check the network settings of your server. Hosting providers often give you a block like `185.220.100.0/22` for your cluster.

Use this for: office networks, VPN subnets, Cloudflare IP ranges, CDN edge nodes, your hosting cluster.

---

### `ua_substrings` — User-Agent substrings

If a request contains this string anywhere in its User-Agent header, it is whitelisted. Matching is **case-insensitive**.

```yaml
whitelist:
  custom:
    ua_substrings:
      - "UptimeRobot"          # uptime monitoring service
      - "internal-healthcheck" # your own monitoring script
      - "MySEOCrawler/"        # your SEO tool
      - "Screaming Frog SEO"   # Screaming Frog crawler
      - "Ahrefs"               # Ahrefs bot
      - "Semrush"              # SEMrush crawler
```

> **For SEO tools:** if your SEO crawler is getting flagged (it sends many requests quickly, or has a suspicious UA), add its name here. Check the exact UA string in your access log:
> ```bash
> grep -i "screaming\|ahrefs\|semrush\|moz\|sitebulb" /var/log/nginx/access.log | awk -F'"' '{print $6}' | sort -u
> ```

**A substring is enough** — you don't need the full string. `"Ahrefs"` will match `"AhrefsBot/7.0"` and any future version.

---

## Applying changes

All whitelist changes apply **without restarting the daemon** — send a reload signal:

```bash
# Reload config (whitelist, detectors, thresholds — everything except log file path)
systemctl kill -s HUP arxsentinel

# Or via PID file
kill -HUP $(cat /var/run/arxsentinel.pid)
```

Changes take effect within seconds. The operational log will show:

```
[CONFIG] reloaded: whitelist updated
```

## Full example

```yaml
whitelist:
  fake_bot_score: 35        # penalty for fake Googlebot/Bingbot impersonation
  dns_verify_timeout: "2s"  # DNS verification timeout

  custom:
    ips:
      - "203.0.113.42"      # developer's home IP
      - "10.99.99.1"        # Zabbix monitoring

    cidrs:
      - "192.168.0.0/16"    # office and VPN
      - "10.0.0.0/8"        # private network

    ua_substrings:
      - "UptimeRobot"
      - "Screaming Frog SEO Spider"
      - "AhrefsBot"
      - "SemrushBot"
      - "MJ12bot"           # Majestic crawler
```
