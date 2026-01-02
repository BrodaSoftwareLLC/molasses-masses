#!/bin/bash

set -euo pipefail

API_KEY=""

# DO NOT EDIT BELOW THIS LINE

if [ -z "$API_KEY" ];
then
    echo "Please set API_KEY first."
    exit 1
fi


# URLs
IPV4_URL="https://pd.broda.io/mm/combined-v4.txt?key=$API_KEY"
IPV6_URL="https://pd.broda.io/mm/combined-v6.txt?key=$API_KEY"

# Temporary download files
TMP_IPV4="/tmp/combined-v4.txt"
TMP_IPV6="/tmp/combined-v6.txt"

# Target blrules files
SHOREWALL_IPV4="/etc/shorewall/blrules"
SHOREWALL_IPV6="/etc/shorewall6/blrules"

# Shorewall executable paths
SHOREWALL_CMD="/usr/sbin/shorewall"
SHOREWALL6_CMD="/usr/sbin/shorewall6"

# Flags to track changes
ipv4_changed=0
ipv6_changed=0

# Download IPv4 addresses
echo "Downloading IPv4 blocklist..."
curl -sfSL "$IPV4_URL" -o "$TMP_IPV4" || { echo "IPv4 download failed"; exit 1; }

# Download IPv6 addresses
echo "Downloading IPv6 blocklist..."
curl -sfSL "$IPV6_URL" -o "$TMP_IPV6" || { echo "IPv6 download failed"; exit 1; }

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
    echo "IPv4 changes detected, updating..."
    {
        echo "# Auto-generated: $(date -u)"
        format_rules "$TMP_IPV4" ipv4
    } > "$SHOREWALL_IPV4"
    ipv4_changed=1
else
    echo "No IPv4 changes detected."
fi

# Check IPv6 differences (ignoring comments and timestamps)
if ! diff -q <(format_rules "$TMP_IPV6" ipv6) <(strip_comments "$SHOREWALL_IPV6") >/dev/null 2>&1; then
    echo "IPv6 changes detected, updating..."
    {
        echo "# Auto-generated: $(date -u)"
        format_rules "$TMP_IPV6" ipv6
    } > "$SHOREWALL_IPV6"
    ipv6_changed=1
else
    echo "No IPv6 changes detected."
fi
# Reload Shorewall if changes occurred
if [ $ipv4_changed -eq 1 ]; then
    echo "Reloading IPv4 Shorewall rules..."
    $SHOREWALL_CMD check && $SHOREWALL_CMD reload
fi

if [ $ipv6_changed -eq 1 ]; then
    echo "Reloading IPv6 Shorewall6 rules..."
    $SHOREWALL6_CMD check && $SHOREWALL6_CMD reload
fi

if [ $ipv4_changed -eq 0 ] && [ $ipv6_changed -eq 0 ]; then
    echo "No changes detected, skipping reload."
fi

# Cleanup
rm -f "$TMP_IPV4" "$TMP_IPV6"
