#!/bin/sh
# cipher-shield installer
# Usage: curl -fsSL https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/install.sh | sh
set -e

VERSION="${CIPHER_SHIELD_VERSION:-latest}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.cipher-shield"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Base download URL — points to GitHub releases
BASE_URL="https://github.com/cipher-oss/cipher-shield/releases/latest/download"

install_macos_daemon() {
    PLIST="$HOME/Library/LaunchAgents/com.cipher-shield.proxy.plist"
    ENV_VARS=""
    if [ -f "$CONFIG_DIR/cipher-shield.env" ]; then
        # shellcheck disable=SC1090
        . "$CONFIG_DIR/cipher-shield.env"
        if [ -n "$ANTHROPIC_API_KEY" ]; then
            ENV_VARS="
  <key>EnvironmentVariables</key>
  <dict>
    <key>ANTHROPIC_API_KEY</key>
    <string>${ANTHROPIC_API_KEY}</string>
  </dict>"
        fi
    fi
    cat > "$PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.cipher-shield.proxy</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/cipher-shield</string>
    <string>proxy</string>
    <string>start</string>
  </array>${ENV_VARS}
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${CONFIG_DIR}/proxy.log</string>
  <key>StandardErrorPath</key>
  <string>${CONFIG_DIR}/proxy.log</string>
</dict>
</plist>
EOF
    launchctl load "$PLIST" 2>/dev/null || true
    echo "✓ macOS LaunchAgent installed (auto-starts on login)"
}

install_linux_daemon() {
    # User-level systemd unit (no root required)
    UNIT_DIR="$HOME/.config/systemd/user"
    mkdir -p "$UNIT_DIR"

    ENV_LINE=""
    if [ -f "$CONFIG_DIR/cipher-shield.env" ]; then
        ENV_LINE="EnvironmentFile=$CONFIG_DIR/cipher-shield.env"
    fi

    cat > "$UNIT_DIR/cipher-shield.service" << EOF
[Unit]
Description=Cipher Shield Package Security Proxy
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/cipher-shield proxy start
ExecStop=${INSTALL_DIR}/cipher-shield proxy stop
${ENV_LINE}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable cipher-shield 2>/dev/null || true
    systemctl --user start cipher-shield 2>/dev/null || true
    echo "✓ systemd user unit installed (auto-starts on login)"
}

# --- Main install logic ---

echo "→ Installing cipher-shield (${OS}/${ARCH})..."

# Download binary
BINARY="cipher-shield-${OS}-${ARCH}"
if [ "$OS" = "windows" ]; then
    BINARY="${BINARY}.exe"
fi

curl -fsSL "${BASE_URL}/${BINARY}" -o /tmp/cipher-shield-download
chmod +x /tmp/cipher-shield-download
mv /tmp/cipher-shield-download "${INSTALL_DIR}/cipher-shield"
echo "✓ Binary installed to ${INSTALL_DIR}/cipher-shield"

# Create config dir
mkdir -p "$CONFIG_DIR"

# Set ANTHROPIC_API_KEY if provided
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" > "$CONFIG_DIR/cipher-shield.env"
    chmod 600 "$CONFIG_DIR/cipher-shield.env"
    echo "✓ API key saved to $CONFIG_DIR/cipher-shield.env"
fi

# Install daemon
if [ "$OS" = "darwin" ]; then
    install_macos_daemon
elif [ "$OS" = "linux" ]; then
    install_linux_daemon
fi

echo ""
echo "✓ cipher-shield installed successfully!"
echo ""
echo "  Start proxy:   cipher-shield proxy start"
echo "  Stop proxy:    cipher-shield proxy stop"
echo "  Scan lockfile: cipher-shield scan lockfile package-lock.json"
echo ""
echo "  To enable Claude Opus deep analysis:"
echo "  export ANTHROPIC_API_KEY=your-key-here"
echo ""
