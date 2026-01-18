#!/bin/bash

set -euo pipefail

API_KEY=""
PD_HOST="pd.broda.io"

# DO NOT EDIT BELOW THIS LINE

DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [--dry-run]"
            exit 1
            ;;
    esac
done

die() {
    echo "Molasses Masses setup issue: $1" >&2
    exit 1
}

step() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "DRY RUN: $1"
    else
        echo "$1"
    fi
}

resolve_cmd() {
    local explicit_path=$1
    local fallback_name=$2

    if [ -x "$explicit_path" ]; then
        echo "$explicit_path"
        return 0
    fi

    if command -v "$fallback_name" >/dev/null 2>&1; then
        command -v "$fallback_name"
        return 0
    fi

    echo ""
    return 0
}

require_blacklist_enabled() {
    local conf_file=$1
    local label=$2
    local value

    if [ ! -r "$conf_file" ]; then
        die "$label config file is not readable at $conf_file. Ensure Shorewall is installed and configured."
    fi

    value=$(awk -F= '/^[[:space:]]*BLACKLIST[[:space:]]*=/{print $2; exit}' "$conf_file" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    if [ -z "$value" ] || [ "$value" = "no" ] || [ "$value" = "off" ] || [ "$value" = "0" ] || [ "$value" = "false" ] || [ "$value" = "none" ]; then
        die "$label blacklist is disabled. Enable BLACKLIST in $conf_file and try again."
    fi
}

check_ipv6_available() {
    if [ ! -f /proc/net/if_inet6 ]; then
        die "IPv6 stack is not available on this host (/proc/net/if_inet6 missing)."
    fi

    if [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
        if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = "1" ]; then
            die "IPv6 is disabled on this host (net.ipv6.conf.all.disable_ipv6=1)."
        fi
    fi

    if ! awk '$6 != "lo" { found=1 } END { exit found?0:1 }' /proc/net/if_inet6; then
        die "IPv6 is enabled but no non-loopback IPv6 interfaces are up."
    fi
}

validate_subnet_list() {
    local input_file=$1
    local ip_version=$2

    if [ ! -s "$input_file" ]; then
        die "Downloaded $ip_version list is empty. Check API key and try again."
    fi

    if [ "$ip_version" = "ipv4" ]; then
        if ! awk '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                split($1, parts, "/")
                ip = parts[1]
                prefix = parts[2]
                n = split(ip, octets, ".")
                if (n != 4) { bad=1; exit 1 }
                for (i = 1; i <= 4; i++) {
                    if (octets[i] !~ /^[0-9]+$/) { bad=1; exit 1 }
                    if (octets[i] < 0 || octets[i] > 255) { bad=1; exit 1 }
                }
                if (prefix != "" && (prefix !~ /^[0-9]+$/ || prefix < 0 || prefix > 32)) { bad=1; exit 1 }
            }
            END { exit bad ? 1 : 0 }
        ' "$input_file"; then
            die "IPv4 list contains unexpected content. This usually means the API key is invalid."
        fi
    else
        if ! awk '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                split($1, parts, "/")
                ip = parts[1]
                prefix = parts[2]
                if (ip !~ /:/) { bad=1; exit 1 }
                if (ip !~ /^[0-9A-Fa-f:]+$/) { bad=1; exit 1 }
                if (prefix != "" && (prefix !~ /^[0-9]+$/ || prefix < 0 || prefix > 128)) { bad=1; exit 1 }
            }
            END { exit bad ? 1 : 0 }
        ' "$input_file"; then
            die "IPv6 list contains unexpected content. This usually means the API key is invalid."
        fi
    fi
}

if [ -z "${API_KEY// }" ]; then
    die "API_KEY is not set. Edit molasses-masses-shorewall.sh and set API_KEY to your key."
fi


# URLs
IPV4_URL="https://${PD_HOST}/mm/combined-v4.txt"
IPV6_URL="https://${PD_HOST}/mm/combined-v6.txt"

# Temporary download files
TMP_IPV4="/tmp/combined-v4.txt"
TMP_IPV6="/tmp/combined-v6.txt"

# Target blrules files
SHOREWALL_IPV4="/etc/shorewall/blrules"
SHOREWALL_IPV6="/etc/shorewall6/blrules"

# Shorewall executable paths
SHOREWALL_CMD="/usr/sbin/shorewall"
SHOREWALL6_CMD="/usr/sbin/shorewall6"

# Shorewall config paths
SHOREWALL_CONF="/etc/shorewall/shorewall.conf"
SHOREWALL6_CONF="/etc/shorewall6/shorewall6.conf"

# Flags to track changes
ipv4_changed=0
ipv6_changed=0

# Dependency and environment checks
step "Checking curl is installed..."
if ! command -v curl >/dev/null 2>&1; then
    die "curl is not installed or not in PATH. Please install curl and try again."
fi

step "Checking Shorewall is installed..."
SHOREWALL_CMD="$(resolve_cmd "$SHOREWALL_CMD" shorewall)"
if [ -z "$SHOREWALL_CMD" ]; then
    die "Shorewall is not installed (expected /usr/sbin/shorewall). Please install shorewall and try again."
fi

step "Checking Shorewall6 is installed..."
SHOREWALL6_CMD="$(resolve_cmd "$SHOREWALL6_CMD" shorewall6)"
if [ -z "$SHOREWALL6_CMD" ]; then
    die "Shorewall6 is not installed (expected /usr/sbin/shorewall6). Please install shorewall6 and try again."
fi

step "Checking Shorewall blacklist settings..."
require_blacklist_enabled "$SHOREWALL_CONF" "Shorewall (IPv4)"
require_blacklist_enabled "$SHOREWALL6_CONF" "Shorewall6 (IPv6)"
step "Checking IPv6 availability..."
check_ipv6_available

# Download IPv4 addresses
step "Downloading IPv4 blocklist..."
curl -sfSL -H "X-Broda-Key: ${API_KEY}" "$IPV4_URL" -o "$TMP_IPV4" || { echo "IPv4 download failed"; exit 1; }
step "Validating IPv4 blocklist..."
validate_subnet_list "$TMP_IPV4" ipv4

# Download IPv6 addresses
step "Downloading IPv6 blocklist..."
curl -sfSL -H "X-Broda-Key: ${API_KEY}" "$IPV6_URL" -o "$TMP_IPV6" || { echo "IPv6 download failed"; exit 1; }
step "Validating IPv6 blocklist..."
validate_subnet_list "$TMP_IPV6" ipv6

# Function to format rules properly (without timestamp comments)
format_rules() {
    local input_file=$1
    local ip_version=$2

    if [ "$ip_version" == "ipv4" ]; then
        awk '/^[^#]/ && NF {printf "DROP\tnet:%s\tall\n", $1}' "$input_file" | sort
    else
        awk '/^[^#]/ && NF {printf "DROP\tnet:[%s]\tall\n", $1}' "$input_file" | sort
    fi
}

# Function to strip comments from existing blrules for comparison
strip_comments() {
    grep -vE '^\s*#|^\s*$' "$1" | sort
}

# Check IPv4 differences (ignoring comments and timestamps)
if ! diff -q <(format_rules "$TMP_IPV4" ipv4) <(strip_comments "$SHOREWALL_IPV4") >/dev/null 2>&1; then
    step "IPv4 changes detected, updating..."
    if [ "$DRY_RUN" -eq 1 ]; then
        step "Would write updated IPv4 rules to $SHOREWALL_IPV4"
    else
        {
            echo "# Auto-generated: $(date -u)"
            format_rules "$TMP_IPV4" ipv4
        } > "$SHOREWALL_IPV4"
    fi
    ipv4_changed=1
else
    step "No IPv4 changes detected."
fi

# Check IPv6 differences (ignoring comments and timestamps)
if ! diff -q <(format_rules "$TMP_IPV6" ipv6) <(strip_comments "$SHOREWALL_IPV6") >/dev/null 2>&1; then
    step "IPv6 changes detected, updating..."
    if [ "$DRY_RUN" -eq 1 ]; then
        step "Would write updated IPv6 rules to $SHOREWALL_IPV6"
    else
        {
            echo "# Auto-generated: $(date -u)"
            format_rules "$TMP_IPV6" ipv6
        } > "$SHOREWALL_IPV6"
    fi
    ipv6_changed=1
else
    step "No IPv6 changes detected."
fi
# Reload Shorewall if changes occurred
if [ $ipv4_changed -eq 1 ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        step "Would reload IPv4 Shorewall rules..."
    else
        step "Reloading IPv4 Shorewall rules..."
        "$SHOREWALL_CMD" check && "$SHOREWALL_CMD" reload
    fi
fi

if [ $ipv6_changed -eq 1 ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        step "Would reload IPv6 Shorewall6 rules..."
    else
        step "Reloading IPv6 Shorewall6 rules..."
        "$SHOREWALL6_CMD" check && "$SHOREWALL6_CMD" reload
    fi
fi

if [ $ipv4_changed -eq 0 ] && [ $ipv6_changed -eq 0 ]; then
    step "No changes detected, skipping reload."
fi

# Cleanup
rm -f "$TMP_IPV4" "$TMP_IPV6"
