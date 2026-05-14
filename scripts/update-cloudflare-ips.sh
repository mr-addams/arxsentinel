#!/bin/bash
# Downloads current Cloudflare IP ranges and generates an nginx real_ip fragment.
#
# Usage:
#   ./update-cloudflare-ips.sh                        # stdout
#   ./update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf  # to file
#
# Include in nginx.conf:
#   http { include /etc/nginx/cloudflare-real-ip.conf; }
#
# Recommended to run from cron weekly — Cloudflare periodically updates its ranges.
# Make sure to configure MAILTO to receive error notifications:
#   MAILTO=admin@example.com
#   0 3 * * 1 /usr/local/bin/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf && nginx -t && nginx -s reload

set -euo pipefail

CF_IPS_V4_URL="https://www.cloudflare.com/ips-v4"
CF_IPS_V6_URL="https://www.cloudflare.com/ips-v6"
# Minimum expected number of ranges — protection against an HTML response instead of an IP list.
MIN_V4=5
MIN_V6=3
OUTPUT="${1:-}"

# Download ranges
v4=$(curl -fsSL --max-time 10 "$CF_IPS_V4_URL") || {
    echo "[ERROR] failed to download IPv4 ranges: $CF_IPS_V4_URL" >&2
    exit 1
}
v6=$(curl -fsSL --max-time 10 "$CF_IPS_V6_URL") || {
    echo "[ERROR] failed to download IPv6 ranges: $CF_IPS_V6_URL" >&2
    exit 1
}

# Validation: filter only CIDR-like lines and check the minimum count.
# Protects against receiving an error HTML page instead of an IP list.
v4_cidrs=$(echo "$v4" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' || true)
v6_cidrs=$(echo "$v6" | grep -E '^[0-9a-fA-F:]+/[0-9]{1,3}$' || true)

v4_count=$(echo "$v4_cidrs" | grep -c . || true)
v6_count=$(echo "$v6_cidrs" | grep -c . || true)

if [ "$v4_count" -lt "$MIN_V4" ]; then
    echo "[ERROR] received only $v4_count IPv4 CIDRs (expected >=$MIN_V4) — response may be invalid" >&2
    exit 1
fi
if [ "$v6_count" -lt "$MIN_V6" ]; then
    echo "[ERROR] received only $v6_count IPv6 CIDRs (expected >=$MIN_V6) — response may be invalid" >&2
    exit 1
fi

# Generate nginx fragment
generate() {
    echo "# Cloudflare real_ip — generated $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "# Source: $CF_IPS_V4_URL + $CF_IPS_V6_URL"
    echo "# Include in the nginx http {} or server {} block:"
    echo "#   include /etc/nginx/cloudflare-real-ip.conf;"
    echo ""

    while IFS= read -r cidr; do
        [ -n "$cidr" ] && echo "set_real_ip_from $cidr;"
    done <<< "$v4_cidrs"

    echo ""
    while IFS= read -r cidr; do
        [ -n "$cidr" ] && echo "set_real_ip_from $cidr;"
    done <<< "$v6_cidrs"

    echo ""
    # CF-Connecting-IP contains the original client IP — more reliable than X-Forwarded-For
    # (cannot be forged by the client, as it is set by Cloudflare itself).
    echo "real_ip_header    CF-Connecting-IP;"
    echo "real_ip_recursive on;"
}

if [ -n "$OUTPUT" ]; then
    # Check that the parent directory exists
    out_dir="$(dirname "$OUTPUT")"
    if [ ! -d "$out_dir" ]; then
        echo "[ERROR] directory does not exist: $out_dir" >&2
        exit 1
    fi

    # Atomic write: first to a temp file on the same filesystem, then mv.
    # If generate fails halfway — the target file remains untouched.
    tmp=$(mktemp "$out_dir/.cloudflare-real-ip.XXXXXX")
    if generate > "$tmp"; then
        mv "$tmp" "$OUTPUT"
    else
        rm -f "$tmp"
        exit 1
    fi

    echo "[OK] written $OUTPUT (IPv4: $v4_count, IPv6: $v6_count)" >&2
else
    generate
fi
