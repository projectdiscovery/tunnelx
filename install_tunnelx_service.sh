#!/bin/bash

set -e

# Check if the OS is Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "This script only supports Linux systems."
    exit 1
fi

# Check if systemd is running
if ! pidof systemd > /dev/null; then
    echo "Systemd is not running on this system. Cannot continue."
    exit 1
fi

# Check if curl is available
if ! command -v curl >/dev/null 2>&1; then
    echo "❌ 'curl' is not installed. Please install curl first."
    echo "   Ubuntu/Debian: sudo apt install curl"
    echo "   RHEL/CentOS: sudo yum install curl"
    echo "   Fedora: sudo dnf install curl"
    exit 1
fi

echo "Operating System: Linux"

# Detect architecture
ARCH=$(uname -m)
echo "Detected architecture: $ARCH"

case "$ARCH" in
    x86_64)
        ARCH_NAME="amd64"
        ;;
    aarch64 | arm64)
        ARCH_NAME="arm64"
        ;;
    armv7l)
        ARCH_NAME="armv7"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Get latest release tag from GitHub
echo "Fetching latest release version from GitHub..."
LATEST_TAG=$(curl -s https://api.github.com/repos/projectdiscovery/tunnelx/releases/latest | grep -Po '"tag_name": "\K.*?(?=")')
if [[ -z "$LATEST_TAG" ]]; then
    echo "Failed to fetch the latest release tag from GitHub."
    exit 1
fi
echo "Latest release found: $LATEST_TAG"

# Construct download URL
FILE_NAME="tunnelx_${LATEST_TAG#v}_linux_${ARCH_NAME}.zip"
BASE_URL="https://github.com/projectdiscovery/tunnelx/releases/download/${LATEST_TAG}"
DOWNLOAD_URL="${BASE_URL}/${FILE_NAME}"

# Download the zip file
echo "Downloading ${FILE_NAME} from ${DOWNLOAD_URL}"
if ! curl -fLO "$DOWNLOAD_URL"; then
    echo "❌ Download failed. The file may not exist for this architecture or release."
    exit 1
fi

# Check file type
if ! file "$FILE_NAME" | grep -q 'Zip archive data'; then
    echo "❌ The downloaded file is not a valid ZIP archive."
    rm -f "$FILE_NAME"
    exit 1
fi

# Ensure unzip is installed
if ! command -v unzip >/dev/null 2>&1; then
    echo "⚠️ 'unzip' is not installed. Attempting to install..."

    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y unzip
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y unzip
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y unzip
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add unzip
    else
        echo "❌ Could not detect package manager. Please install 'unzip' manually."
        exit 1
    fi
fi

# Extract the archive
unzip -o "$FILE_NAME"

# Clean up the downloaded zip file
rm -f "$FILE_NAME"

# Check if the binary exists
if [[ ! -f "tunnelx" ]]; then
    echo "❌ tunnelx binary not found after extraction."
    exit 1
fi

# Ensure /usr/local/bin exists
if [[ ! -d "/usr/local/bin" ]]; then
    echo "/usr/local/bin does not exist. Creating it..."
    sudo mkdir -p /usr/local/bin
fi

# Warn if /usr/local/bin is not in PATH
if ! echo "$PATH" | grep -q "/usr/local/bin"; then
    echo "⚠️ Warning: /usr/local/bin is not in your PATH. You may need to add it to your shell profile."
fi

# Move the binary
sudo mv tunnelx /usr/local/bin/
sudo chmod +x /usr/local/bin/tunnelx

# Prompt for PDCP_API_KEY
read -rp "Enter your PDCP_API_KEY: " PDCP_API_KEY

# Basic validation for API key (check if not empty)
if [[ -z "$PDCP_API_KEY" ]]; then
    echo "❌ API key cannot be empty."
    exit 1
fi


# Store the key securely in an environment file
ENV_FILE="/etc/tunnelx.env"
echo "Creating environment file at $ENV_FILE"
echo "PDCP_API_KEY=${PDCP_API_KEY}" | sudo tee "$ENV_FILE" > /dev/null
sudo chmod 600 "$ENV_FILE"

# Create systemd service file with logging and environment file
SERVICE_FILE="/etc/systemd/system/tunnelx.service"

# Stop existing service if running
if systemctl is-active --quiet tunnelx; then
    echo "Stopping existing tunnelx service..."
    sudo systemctl stop tunnelx
fi


sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=TunnelX Service
After=network.target

[Service]
ExecStart=/usr/local/bin/tunnelx
Restart=always
RestartSec=5
EnvironmentFile=$ENV_FILE
StandardOutput=append:/var/log/tunnelx.log
StandardError=append:/var/log/tunnelx.err

[Install]
WantedBy=multi-user.target
EOF

# Reload and start the service
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable tunnelx
sudo systemctl start tunnelx

# Verify service started successfully
sleep 2
if systemctl is-active --quiet tunnelx; then
    echo "✅ TunnelX ${LATEST_TAG} installed and running as a systemd service!"
    echo "📝 Logs: /var/log/tunnelx.log and /var/log/tunnelx.err"
    echo "🔧 Service status: sudo systemctl status tunnelx"
    echo "🔍 Real-time logs: tail -f /var/log/tunnelx.log"
else
    echo "❌ Service failed to start. Check logs with: sudo journalctl -u tunnelx -n 20"
    exit 1
fi
