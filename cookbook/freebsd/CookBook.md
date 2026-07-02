# FreeBSD Deployment Cookbook

## Overview

ArxSentinel ships a native FreeBSD binary (`freebsd/{386,amd64,arm,arm64}`)
via goreleaser, plus a dedicated installer and rc.d service script. The
recommended architecture is **ArxSentinel runs natively on the FreeBSD
host** — it is not containerized. If your web server (nginx, Caddy,
Traefik, HAProxy, Apache, LiteSpeed...) runs in a `podman` container on
the same FreeBSD host, ArxSentinel tails the container's access log via
a bind-mounted host path or a network source (syslog/HTTP), exactly like
any other recipe in this cookbook.

Why native, not containerized: FreeBSD has no Linux-kernel-native
container runtime — `podman` on FreeBSD runs Linux containers through an
experimental Linux-compatibility/emulation layer (`ocijail` +
`linprocfs`/`linsysfs`). That emulation layer is good enough for running
a web server, but running ArxSentinel itself there gains nothing and
adds a translation layer between the binary and the OS it needs to
introspect (file watching, signal handling). Running natively sidesteps
that entirely — this is also the exact architecture this project's own
FreeBSD CI suite validates (`tests/integration-freebsd/`).

## Quick Start

Download the `freebsd_<arch>` archive from the
[releases page](https://github.com/mr-addams/arxsentinel/releases),
extract it, and run the installer as root:

```sh
fetch https://github.com/mr-addams/arxsentinel/releases/latest/download/arxsentinel_<version>_freebsd_<arch>.tar.gz
tar xzf arxsentinel_<version>_freebsd_<arch>.tar.gz
cd arxsentinel_<version>_freebsd_<arch>
sudo sh install.sh
```

The installer (`packaging/freebsd/install.sh` in the source tree) is
idempotent — safe to re-run on upgrade. It:

1. Creates a dedicated `arxsentinel` system user/group (no login shell)
2. Prepares `/var/log/arxsentinel` (0750, owned by the service user)
3. Installs the binary to `/usr/local/bin/arxsentinel` (0555, non-writable)
4. Installs the rc.d script to `/usr/local/etc/rc.d/arxsentinel`
5. Copies `config.yaml.example` + `config.reference.yaml` into
   `/usr/local/etc/arxsentinel/`
6. Seeds `config.yaml` from the example **only if absent** — re-running
   the installer never clobbers your tuning

It does **not** start the service automatically — review the config
first (executors can hit real WAF/Cloudflare/MikroTik backends on first
launch).

### FreeBSD path layout

Different from the Linux packaging (`/etc/arxsentinel/`,
systemd `RuntimeDirectory=`) — FreeBSD follows the third-party-software
convention (`/usr/local/`):

| Purpose | Path |
|---|---|
| Binary | `/usr/local/bin/arxsentinel` |
| rc.d script | `/usr/local/etc/rc.d/arxsentinel` |
| Config directory | `/usr/local/etc/arxsentinel/` |
| Active config | `/usr/local/etc/arxsentinel/config.yaml` |
| State dir (service user's `$HOME`) | `/var/db/arxsentinel/` |
| Logs | `/var/log/arxsentinel/` |
| Pidfile | `/var/run/arxsentinel/arxsentinel.pid` |

**One thing to know if you build/run the binary manually** (not via the
installer): the daemon's compiled-in default config path
(`cmd/arxsentinel/main.go`) is `/etc/arxsentinel/config.yaml` — a
Linux-specific default. On FreeBSD you must always pass `-config=` (or
`--config=`, both accepted) explicitly. The installer's rc.d script
already does this for you via `command_args`.

### Service management

```sh
sysrc arxsentinel_enable=YES       # persist across reboots (/etc/rc.conf)
service arxsentinel start
service arxsentinel status
service arxsentinel stop
```

Standard `rc.subr` plumbing — `arxsentinel_user`/`arxsentinel_group` are
pre-set in the rc.d script (privilege drop to the `arxsentinel` system
user before exec), and a `start_precmd` hook creates
`/var/run/arxsentinel/` on first start (FreeBSD's rc.d has no
`RuntimeDirectory=` equivalent, unlike systemd).

### Uninstall (manual — no `pkg`/uninstaller yet)

```sh
service arxsentinel stop
sysrc arxsentinel_enable=NO
rm /usr/local/bin/arxsentinel /usr/local/etc/rc.d/arxsentinel
rm -rf /usr/local/etc/arxsentinel /var/log/arxsentinel
pw userdel arxsentinel
```

---

## Running web servers under podman on FreeBSD

If your web server runs in a `podman` container on the same FreeBSD
host (rather than natively, or on a separate Linux/Docker host),
`sysutils/podman` on FreeBSD has real, sharp-edged differences from
Docker/Linux podman. This section is a curated, deployment-focused
subset of what this project's own FreeBSD CI suite
(`tests/integration-freebsd/`) had to work through across ~130 live
CI dispatches — the full internal gotchas list (CI-script-specific
material included) lives in that suite's `DECISIONS.md` files if you
need more detail than what's below.

### One-time podman setup

```sh
pkg install sysutils/podman
```

1. **Storage driver — switch `zfs` → `vfs`.** `sysutils/podman`'s
   default `storage.conf` driver is `zfs`, which does not work
   out-of-the-box on most FreeBSD installs (no zpool configured for
   podman's storage root). Edit
   `/usr/local/etc/containers/storage.conf`:
   ```
   [storage]
   driver = "vfs"
   ```
2. **pf firewall — required for any podman network.** podman's CNI
   bridge networking needs `pf` active with local-traffic filtering
   enabled:
   ```sh
   kldload pf
   sysrc pf_enable=YES
   echo 'pass all' >> /etc/pf.conf   # or a real ruleset
   service pf start
   sysctl net.pf.filter_local=1
   ```
3. **Linux compatibility layer** (best-effort, needed for any Linux
   container):
   ```sh
   sysrc linux_enable=YES
   service linux start
   ```

### Pulling and running Linux images

- **Always use fully-qualified image names.** `nginx:alpine` fails
  with *"did not resolve to an alias and no unqualified-search
  registries are defined"* — FreeBSD podman's default
  `registries.conf` has no `unqualified-search-registries` entry.
  Use `docker.io/library/nginx:alpine` instead.
- **`--os=linux` on every `podman run`/`pull` of a Linux image.**
  Without it, podman looks for a `freebsd` OS variant in the image
  index and fails with *"no image found in image index for
  architecture amd64 ... OS freebsd"*.
- **`--platform linux/amd64` on `podman build`** (different flag from
  the two above — `build` doesn't accept `--os`).
- **No container-name DNS resolution.** FreeBSD's
  `containernetworking-plugins` package ships the basic CNI bridge
  plugin only — no `dnsname` plugin (the thing that gives Docker/Linux
  podman "resolve other containers by `--name`" for free via
  netavark+aardvark-dns). If one container needs to reach another by
  name, resolve its CNI-assigned IP explicitly instead:
  ```sh
  podman inspect <container> --format '{{(index .NetworkSettings.Networks "<network>").IPAddress}}'
  ```
  (Use Go template's `index` function for network names containing a
  hyphen — dot-notation like `.Networks.my-net` parses the hyphen as
  subtraction and fails.)

### `podman pod` / `podman-compose` — don't

**Multi-container orchestration via `podman pod` (and therefore
`podman-compose`, which uses pods as its underlying mechanism) does
not work reliably on FreeBSD podman + `ocijail`.** A container that
runs stably standalone (`podman run --network X --os=linux ...`)
breaks when placed inside a pod (`podman run --pod <name> ...`) with
an identical command — confirmed via direct A/B testing: the same
nginx image crashes on startup with `io_setup() failed (38: Function
not implemented)` only when pod-wrapped, never standalone. This is an
upstream limitation in the current pod implementation on
podman-on-FreeBSD/ocijail, not a configuration mistake — `podman` on
FreeBSD is explicitly marked experimental by its own maintainers.

**Practical implication:** if you need multiple containers on one
network (e.g. a reverse proxy + backend), start each with a plain
standalone `podman run --network <shared-network> ...` — never
`podman pod create` + `--pod`, and don't reach for `podman-compose`
on FreeBSD at all. This project's own multi-container FreeBSD tests
(reverse-proxy-chain scenarios) use exactly this standalone-container
pattern.

### If a container's log output silently goes missing

Two independent causes, easy to conflate:

1. **Bind-mounting a log directory hides the image's default
   `error_log -> /dev/stderr` symlink.** Most official web-server
   images symlink their error log to `/dev/stderr` so `podman logs`
   captures it. Bind-mounting your own directory over that log path
   (e.g. `-v $HOST_DIR:/var/log/nginx`) replaces the symlink with a
   real file — `podman logs <container>` then shows nothing, even
   though the server started fine and is writing logs to the
   bind-mounted file itself. Fix: explicitly redirect error output
   back to stderr in your config (e.g. nginx's `error_log
   /dev/stderr;`, Apache's `ErrorLog /dev/stderr`) — don't rely on the
   image's default symlink surviving a mount over its parent
   directory.
2. **`/proc/1/fd/N` procfs-symlink-to-stdout tricks fail outright.**
   Some official images configure logging via a symlink through
   `/proc/1/fd/1` or `/proc/1/fd/2` instead of a plain `/dev/stdout`
   device node. FreeBSD's `linprocfs` (the Linux `/proc` emulation)
   does not populate `/proc/1/fd/` the way a native Linux kernel
   does — the container fails its own config check at startup with
   an error like *"Cannot access directory '/proc/1/fd/' for main
   error log"*. Point logging directives at `/dev/stderr`/`/dev/stdout`
   directly instead.

### Building a custom image (e.g. Caddy with a non-default plugin)

If you need a custom-built image (a Caddy build with the
`transform-encoder` plugin for Apache-CLF-formatted logs, for
example), **build it on a native Linux/Docker host, not via `podman
build` on the FreeBSD host itself.** `podman build` under FreeBSD's
Linux emulation hits a cluster of toolchain-specific failures — a
statically-linked Go binary can't self-locate `GOROOT` via
`readlink /proc/self/exe` under `linprocfs`, and DNS resolution to
module proxies (`proxy.golang.org` etc.) can time out from inside the
build container even though the same network path works fine for a
plain `podman pull`. Build the image elsewhere, `docker save` it to a
tar, copy the tar to the FreeBSD host, and `podman load -i` it there —
a pure local import with no network/toolchain dependency.

### Reverse-proxy real-IP: verify the mechanism per backend, don't assume it transfers

If your web server sits behind a reverse proxy and you want the
*backend's own access log* (not just ArxSentinel's [Reverse Proxy /
Real-IP](../CookBook.md#reverse-proxy) recipes) to show the real
client IP instead of the proxy's, the exact mechanism is
backend-specific — don't assume nginx's `real_ip_module` pattern
(`set_real_ip_from` + `real_ip_header`) transfers to every other
server. Caddy in particular is a trap: `trusted_proxies` does **not**
rewrite the raw `{request>remote_ip}` value the `transform-encoder`
plugin logs — you need to change the *log format string itself* to a
fallback expression:
`{request>headers>X-Forwarded-For>[0]:request>remote_ip}` ("use XFF
if present, else remote_ip"). Traefik, on the other hand,
`forwardedHeaders.trustedIPs` genuinely does work as expected.
Apache's `mod_remoteip` (`RemoteIPHeader` + `RemoteIPInternalProxy`)
also works as expected and is bundled in the stock `httpd:latest`
image (no custom build needed). When wiring this up, verify the
actual logged output changes — don't assume config acceptance means
behavioral correctness.

---

## See also

- [config.reference.yaml](../config.reference.yaml) — full config reference
- [Reverse Proxy / Real-IP](../CookBook.md#reverse-proxy) — ArxSentinel-side real-IP recipes (nginx/Caddy/HAProxy/Traefik in front of nginx)
- [Server Configs](../CookBook.md#server-configs) — log-format snippets for each web server
