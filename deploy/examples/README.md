# Deployment Examples

This directory contains configuration examples for running ArxSentinel in different environments.

## Categories

### Standalone Server

ArxSentinel listening directly for HTTP requests from clients.

| Example | Platform | Files |
|---------|----------|-------|
| **Nginx** | Nginx | `nginx-json-logformat.conf` — log format snippets for direct nginx + JSON parsing |
| **Apache** | Apache 2.4+ | `apache/httpd.conf`, `apache/sentinel-config.yaml` |
| **Caddy** | Caddy 2.x | `caddy/Caddyfile`, `caddy/sentinel-config.yaml` |
| **HAProxy** | HAProxy 2.x+ | `haproxy/haproxy.cfg`, `haproxy/sentinel-config.yaml` |
| **Traefik** | Traefik 2.x+ | `traefik/traefik.yml`, `traefik/sentinel-config.yaml` |
| **LiteSpeed** | LiteSpeed 5.4+ | `litespeed/httpd_config.conf`, `litespeed/sentinel-config.yaml` |

**When to use:** Direct client connection, single-layer architecture, or gateway appliance role.

### Reverse Proxy Mode

ArxSentinel deployed behind a reverse proxy (nginx, Caddy, HAProxy, or Traefik)
that forwards log entries for analysis.

See [reverse-proxy/README.md](reverse-proxy/README.md) for full proxy setup guide,
IP chain integrity, and Cloudflare guard configuration.

| Example | Proxy + ArxSentinel | Files |
|---------|---------------------|-------|
| **Nginx** | nginx → ArxSentinel | `reverse-proxy/nginx-rp/` — nginx.conf + sentinel-config |
| **Caddy** | Caddy → ArxSentinel | `reverse-proxy/caddy/` — Caddyfile + sentinel-config |
| **HAProxy** | HAProxy → ArxSentinel | `reverse-proxy/haproxy/` — haproxy.cfg + sentinel-config |
| **Traefik** | Traefik → ArxSentinel | `reverse-proxy/traefik/` — traefik.yml + sentinel-config |

**When to use:** Multi-layer architecture, load balancing, Kubernetes ingress, or behind an existing reverse proxy.

### CMS Integrations

Pre-configured examples for common content management systems.

| Platform | Examples | Location |
|----------|----------|----------|
| **WordPress** | Generic WordPress + Multisite | `cms/wordpress.yaml` |
| **Drupal** | Drupal 9, 10 | `cms/drupal.yaml` |
| **Joomla** | Joomla 3, 4 | `cms/joomla.yaml` |
| **Laravel** | Laravel 9+ | `cms/laravel.yaml` |
| **Generic PHP** | Any PHP framework | `cms/generic-php.yaml` |

## Quick Start

1. Choose your scenario above (standalone or reverse proxy).
2. Copy the corresponding `sentinel-config.yaml` to your deployment environment.
3. Customize ports, log paths, and rules as needed.
4. See `../../README.md` for full integration guide and `deploy/docker/` for containerized deployment.

## Log Format Configuration

For Nginx with direct connection, use `nginx-json-logformat.conf` to set up
the proper log format for JSON parsing. Nginx reverse proxy examples already
include the necessary log format directives.

## More Information

- **Whitelist Rules:** [../../README.whitelist.md](../../README.whitelist.md)
- **Chain Guard & IP Validation:** [reverse-proxy/README.md](reverse-proxy/README.md)
- **Metrics & Monitoring:** [../../deploy/grafana/README.md](../../deploy/grafana/README.md)
- **Custom Log Formats:** [../../README.log-formats.md](../../README.log-formats.md)
