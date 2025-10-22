#!/bin/bash
# Installation script for Apache Bot Monitor

set -e

echo "======================================================================"
echo "Apache Bot Monitor - Installation Script"
echo "======================================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Create directories
echo "Creating directories..."
mkdir -p /var/lib/bot_monitor
mkdir -p /etc

# Install Python scripts
echo "Installing scripts..."
cp bot_monitor_daemon.py /usr/local/bin/
cp bot_monitor_client.py /usr/local/bin/
chmod +x /usr/local/bin/bot_monitor_daemon.py
chmod +x /usr/local/bin/bot_monitor_client.py

# Install configuration
if [ ! -f /etc/bot_monitor.conf ]; then
    echo "Installing configuration..."
    cp bot_monitor.conf /etc/
    echo "✓ Configuration installed at /etc/bot_monitor.conf"
    echo "  Please edit this file to customize settings"
else
    echo "⚠ Configuration already exists at /etc/bot_monitor.conf"
    echo "  Backup created at /etc/bot_monitor.conf.new"
    cp bot_monitor.conf /etc/bot_monitor.conf.new
fi

# Install systemd service
echo "Installing systemd service..."
cp bot_monitor.service /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "======================================================================"
echo "Installation Complete!"
echo "======================================================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Edit configuration:"
echo "   sudo nano /etc/bot_monitor.conf"
echo ""
echo "2. Start the daemon:"
echo "   sudo systemctl start bot_monitor"
echo ""
echo "3. Enable auto-start on boot:"
echo "   sudo systemctl enable bot_monitor"
echo ""
echo "4. Check status:"
echo "   sudo systemctl status bot_monitor"
echo ""
echo "5. View logs:"
echo "   sudo journalctl -u bot_monitor -f"
echo ""
echo "6. Connect with client:"
echo "   bot_monitor_client.py"
echo ""
echo "======================================================================"
