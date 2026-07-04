# Security Policy

ArxSentinel parses untrusted input (access logs written by anonymous clients) and
holds credentials for external APIs (Cloudflare, MikroTik). We treat every report
in that surface seriously.

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✓ |
| older   | security fixes backported on request |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Preferred channel — GitHub private vulnerability reporting:

1. Go to the [Security tab](https://github.com/mr-addams/arxsentinel/security) of this repository
2. Click **Report a vulnerability** and fill in the advisory form

Alternatively, report by email: **mr.addams@gmail.com** with `[arxsentinel security]` in the subject.

Include in your report:

- Description of the vulnerability and its potential impact
- ArxSentinel version and deployment method (package / Docker / K8s / source build)
- Steps to reproduce — a config snippet and, if relevant, the exact log line(s) that trigger the problem
- Suggested fix (if any)

## What to Expect

- A response within **48 hours**
- A status assessment (accepted / needs more info / declined with reasoning) within 7 days
- Coordinated disclosure: we ask that you keep details private until a fix is released;
  in return the fix is prioritized ahead of all other work and you will be credited in
  the release notes (unless you prefer to remain anonymous)

## Scope Notes

In scope (examples):

- Crashes, memory exhaustion, or detection bypass triggered by crafted log lines
- Path traversal or file overwrite via configuration values
- Leaking executor credentials (Cloudflare token, MikroTik password) to logs or metrics
- Ban evasion or spoofing that defeats bot DNS verification by design

Out of scope:

- Vulnerabilities in third-party blocklist *content* (report upstream to the list maintainer)
- Deployments that ignore documented hardening (e.g. running as root where the packaged
  systemd unit / container already provides an unprivileged user)
- Denial of service that requires prior root access to the host
