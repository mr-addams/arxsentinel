# Upgrading ArxSentinel

## Before you begin

- This guide covers upgrading from v1.x to v2.x (current development version: v2.x).
- v2.x is backward-compatible — existing `config.yaml` files continue to work without changes.
- Read the full [v2.0.0 release notes](https://github.com/mr-addams/arxsentinel/releases/tag/v2.0.0) for the complete changelog.

---

## v1.x → v2.x

### What changed

| Change | v1.x | v2.x |
|---|---|---|
| **Executors** (stateful action plugins) | Not available | New plugin type — see [docs/executors.md](executors.md) |
| **Cloudflare WAF integration** | Not available | CloudflareExecutor with IP list management — see [docs/executor-cloudflare.md](executor-cloudflare.md) |
| **Config section** | No `executors:` key | New top-level `executors:` section (optional, backward-compatible) |
| **Binary path** | `/usr/local/bin/arxsentinel` | `/usr/bin/arxsentinel` (standardized in packaged install) |
| **`check-config` command** | Not available | `arxsentinel check-config <path>` — validates config for v2 compatibility without starting the daemon |
| **Client IP extraction** | Static `real_ip` setup | ChainGuard detects misconfigured proxy chains automatically |
| **Config path** | `/etc/arxsentinel/config.yaml` | `/etc/arxsentinel/config.yaml` (unchanged) |

**Backward compatibility notes:**

- Configs from v1.x work in v2.x without any changes — the `executors:` section is entirely optional.
- Existing Sinks (`output.threat_log`, Fail2Ban) continue to operate alongside or instead of Executors.
- The systemd service unit is updated to reflect the new binary path. Package managers handle this automatically during upgrade.

### Upgrade steps

#### 1. Back up your config

```bash
sudo cp /etc/arxsentinel/config.yaml ~/arxsentinel-config-backup.yaml
sudo cp -r /etc/arxsentinel/ ~/arxsentinel-backup/
```

#### 2. Install the v2.x package

**Option A — Quick installer (recommended, any distro):**

The installer auto-detects your distro and architecture, downloads the correct package from GitHub Releases, and upgrades in place.

```bash
# Latest stable release
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash

# Latest dev pre-release
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash -s -- --dev

# Specific version/tag
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash -s -- --version <latest>
```

**Option B — Debian / Ubuntu (manual):**

Download the `.deb` package for your architecture from the [Releases page](https://github.com/mr-addams/arxsentinel/releases) and install it:

```bash
sudo apt install ./arxsentinel_<version>_linux_amd64.deb
```

Example output:

```
Selecting previously unselected package arxsentinel.
(Reading database… 817847 files and directories currently installed.)
Preparing to unpack arxsentinel_<version>_linux_amd64.deb…
Unpacking arxsentinel (<version>)…
Processing triggers for kali-menu (2026.2.5)…
```

**Option C — Fedora / RHEL / AlmaLinux / Rocky Linux:**

```bash
sudo dnf install ./arxsentinel_<version>_linux_amd64.rpm
```

**Option D — Arch Linux / Manjaro:**

```bash
sudo pacman -U arxsentinel_<version>_linux_amd64.pkg.tar.zst
```

> The v2 package **does not overwrite** your existing config. Package managers preserve `/etc/arxsentinel/config.yaml` during upgrade.

#### 3. Verify config compatibility

v2.x introduces a new `check-config` subcommand that validates your config against the v2 schema:

```bash
sudo arxsentinel check-config /etc/arxsentinel/config.yaml
```

If the output shows no errors, your config is fully compatible with v2.x.

> **What it checks:** required fields, YAML structure, detector configuration completeness (yaml.v3 constraint — all fields must be present in a section if the section exists), and optional `executors:` syntax (if present).

#### 4. Restart the service

```bash
sudo systemctl daemon-reload    # reload updated systemd unit
sudo systemctl restart arxsentinel
```

Verify the service started correctly:

```bash
sudo systemctl status arxsentinel
```

Expected output (healthy):

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

Check the operational log for the startup banner:

```bash
tail -f /var/log/arxsentinel/sentinel.log
```

Expected:

```
2026-05-28 16:55:07 [STARTUP] arxsentinel v2.x started
2026-05-28 16:55:07 [STATS] processed=0 tracked=0 threats=0 suspicious=0
```

#### 5. (Optional) Enable CloudflareExecutor

If your deployment is fronted by Cloudflare CDN, add the `executors:` section to your config:

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

Then validate and reload:

```bash
sudo arxsentinel check-config /etc/arxsentinel/config.yaml
sudo systemctl kill -s HUP arxsentinel   # reload without restart
```

See [docs/executor-cloudflare.md](executor-cloudflare.md) for:
- Required Cloudflare API token permissions
- WAF rule setup to use the IP list
- Tuning `min_level` and `ttl` for your environment
- Troubleshooting common issues

#### 6. Verify detection pipeline

After the upgrade, confirm that threat detection is working with a quick probe test:

```bash
# Simulate a probe request (adjust the path to match your server)
curl -s -o /dev/null -w "%{http_code}" http://your-server.com/.env

# Check that ArxSentinel logged it
sudo journalctl -u arxsentinel --since "1 min ago" | grep -i threat
```

Expected: the probe test should appear as a `THREAT` entry in the operational log within the observation window.

#### 7. Verify Prometheus metrics (if enabled)

```bash
curl -s http://127.0.0.1:9117/metrics | grep arx_sentinel
```

Expected: metrics vectors include the new `executor` labels if any executors are configured.

---

## Rolling back

If the v2.x upgrade causes issues, roll back to the last known-good v1.x release.

#### 1. Stop the v2.x service

```bash
sudo systemctl stop arxsentinel
```

#### 2. Downgrade the package

**Debian / Ubuntu:**

```bash
# Download the last v1.x package (adjust version as needed)
wget https://github.com/mr-addams/arxsentinel/releases/download/v1.3.9/arxsentinel_1.3.9_linux_amd64.deb
sudo apt install ./arxsentinel_1.3.9_linux_amd64.deb
```

**Fedora / RHEL / AlmaLinux / Rocky Linux:**

```bash
sudo dnf install ./arxsentinel_1.3.9_linux_amd64.rpm --oldpackage
```

**Arch Linux / Manjaro:**

```bash
# Downgrade via the pacman cache or an older package file
sudo pacman -U /var/cache/pacman/pkg/arxsentinel-1.3.9-1-x86_64.pkg.tar.zst
```

#### 3. Restore the v1.x config (if needed)

The package manager preserves your config file during upgrade and downgrade. If the v2.x config has incompatible changes, restore your backup:

```bash
sudo cp ~/arxsentinel-config-backup.yaml /etc/arxsentinel/config.yaml
```

#### 4. Remove any `executors:` section from config

v1.x does not recognise the `executors:` key. If you added it during the v2.x trial, remove or comment out the section:

```bash
sudo nano /etc/arxsentinel/config.yaml
# Remove or comment out the executors: block
```

#### 5. Restart the v1.x service

```bash
sudo systemctl daemon-reload
sudo systemctl restart arxsentinel
```

Verify the service started with the v1.x version:

```bash
sudo journalctl -u arxsentinel --since "1 min ago" | grep STARTUP
```

Expected:

```
2026-05-28 17:00:00 [STARTUP] arxsentinel v1.3.9 started
```

#### 6. (If applicable) Clean up Cloudflare IP list entries

If you used the CloudflareExecutor during the v2.x trial, the IP list entries created by v2.x remain in your Cloudflare account after downgrade. Remove them manually from the Cloudflare dashboard or via the API:

```bash
curl -X DELETE "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/rules/lists/YOUR_LIST_ID/items" \
  -H "Authorization: Bearer YOUR_CF_API_TOKEN" \
  -H "Content-Type: application/json"
```

> The IP list itself can be left in place — it will not affect anything unless referenced by a WAF rule.

---

## Version compatibility reference

| ArxSentinel version | Binary path | Config path | Executors support | Notes |
|---|---|---|---|---|
| v1.3.9 (latest v1.x) | `/usr/local/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | No | Last v1.x release with all v1 features |
| v2.0.0 | `/usr/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | Yes | First v2.x stable release |
| latest dev | `/usr/bin/arxsentinel` | `/etc/arxsentinel/config.yaml` | Yes | Active development — see [Releases](https://github.com/mr-addams/arxsentinel/releases) |

---

## Troubleshooting

### Service fails to start with `exit-code 217/USER`

The `arxsentinel` system user was not created or is missing during the upgrade.

**Fix:**

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin arxsentinel
sudo systemctl restart arxsentinel
```

### `arxsentinel check-config` returns validation errors

**Common causes:**

1. **Incomplete sections** — a present section must include **all** its fields (yaml.v3 limitation). Add missing fields from the default config.
2. **Unknown keys** — v2.x does not recognise keys from very old v1.x configs. Remove or rename them.
3. **Executor config errors** — if the `executors:` section is present, all executor-specific fields must be valid (see [docs/executor-cloudflare.md](executor-cloudflare.md)).

Check the specific error message and adjust the corresponding section.

### Fail2Ban stops banning after upgrade

The threat log format has not changed — failregex `THREAT <HOST>` still works. Verify:

```bash
fail2ban-regex /var/log/arxsentinel/threats.log /etc/fail2ban/filter.d/arxsentinel.conf
```

If the Fail2Ban package was re-installed during the upgrade, re-enable the arxsentinel jail:

```bash
sudo fail2ban-client reload
sudo fail2ban-client status arxsentinel
```

---

## Additional resources

- [docs/executors.md](executors.md) — Executor framework overview and custom executor development
- [docs/executor-cloudflare.md](executor-cloudflare.md) — CloudflareExecutor full setup guide
- [README.md](../README.md) — Main project documentation
- [GitHub Releases](https://github.com/mr-addams/arxsentinel/releases) — Release notes and package downloads
