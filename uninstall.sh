#!/bin/sh
# cipher-shield uninstaller
set -e

CONFIG_DIR="$HOME/.cipher-shield"
INSTALL_DIR="/usr/local/bin"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

echo "→ Stopping cipher-shield proxy..."
cipher-shield proxy stop 2>/dev/null || true

echo "→ Removing daemon..."
if [ "$OS" = "darwin" ]; then
    PLIST="$HOME/Library/LaunchAgents/com.cipher-shield.proxy.plist"
    launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo "✓ LaunchAgent removed"
elif [ "$OS" = "linux" ]; then
    systemctl --user stop cipher-shield 2>/dev/null || true
    systemctl --user disable cipher-shield 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/cipher-shield.service"
    systemctl --user daemon-reload 2>/dev/null || true
    echo "✓ systemd unit removed"
fi

echo "→ Restoring npm and pip config..."
# Restore npm registry
if [ -f "$CONFIG_DIR/npm_registry.orig" ]; then
    ORIG=$(cat "$CONFIG_DIR/npm_registry.orig")
    npm config set registry "$ORIG" 2>/dev/null || true
    echo "✓ npm registry restored to $ORIG"
fi
# Restore pip config
if [ -f "$CONFIG_DIR/pip_index.orig" ]; then
    ORIG=$(cat "$CONFIG_DIR/pip_index.orig")
    if [ "$OS" = "darwin" ] || [ "$OS" = "linux" ]; then
        PIP_CONF="$HOME/.pip/pip.conf"
        if [ "$ORIG" = "https://pypi.org/simple/" ]; then
            rm -f "$PIP_CONF"
        else
            printf '[global]\nindex-url = %s\n' "$ORIG" > "$PIP_CONF"
        fi
    fi
    echo "✓ pip index-url restored"
fi

echo "→ Removing binary and config..."
rm -f "${INSTALL_DIR}/cipher-shield"
rm -rf "$CONFIG_DIR"
echo "✓ cipher-shield fully removed"
