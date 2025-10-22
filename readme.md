# Apache Bot Monitor

A professional daemon/client system for real-time monitoring and analysis of bot traffic in Apache logs. Features attack detection, email alerts, and a beautiful curses-based dashboard.

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🎯 Architecture

**Daemon** (`bot_monitor_daemon.py`):
- Runs continuously in background as a system service
- Monitors Apache logs 24/7
- Detects bot attacks in real-time
- Sends email alerts
- Handles log rotation automatically
- Serves data to clients via Unix socket

**Client** (`bot_monitor_client.py`):
- Connects to daemon on-demand
- Displays live curses dashboard
- Multiple clients can connect simultaneously
- View stats without interrupting monitoring

## ✨ Features

### 📊 **Five Dashboard Screens:**

1. **Bot Names** - Top bots by request count (minute/hour/day)
2. **Bot IPs** - Top bot IP addresses (minute/hour/day)
3. **Bot Ratios** - Visual graphs of bot vs non-bot traffic
4. **Detected Bots** - All detected bots with counts and last seen timestamps
   - Sortable by Name, Last Seen, or Count
   - Press Enter for detailed bot information
5. **Bot Attacks** - Real-time attack monitoring
   - Shows active attacks with peak QPS
   - Historical attack log
   - Sortable by Time, QPS, or Duration

### 🚨 **Attack Detection:**
- Configurable QPS thresholds
- Detects sustained bot attacks
- Tracks attack duration and peak QPS
- Cooldown periods to prevent alert spam

### 📧 **Email Alerting:**
- Automatic email alerts on attack detection
- Uses local MTA (sendmail/postfix)
- Configurable recipients and templates

### 🔄 **Log Rotation:**
- Automatic detection of log file rotation
- Seamlessly follows new log files
- No monitoring gaps

### 🎨 **Interactive UI:**
- Color-coded displays
- Keyboard navigation
- Sortable tables
- Scrollable lists
- Bot detail popups with URLs and metadata

### 🤖 **Bot Detection:**
- 900+ bot patterns from [monperrus/crawler-user-agents](https://github.com/monperrus/crawler-user-agents)
- Includes URLs and documentation for each bot
- Automatic database updates
- Offline caching

## 📦 Installation

### Quick Install

```bash
# Clone repository
git clone https://github.com/yourusername/apache-bot-monitor.git
cd apache-bot-monitor

# Run installer
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation

```bash
# Copy files
sudo cp bot_monitor_daemon.py /usr/local/bin/
sudo cp bot_monitor_client.py /usr/local/bin/
sudo chmod +x /usr/local/bin/bot_monitor_*.py

# Copy configuration
sudo cp bot_monitor.conf /etc/

# Install systemd service
sudo cp bot_monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## ⚙️ Configuration

Edit `/etc/bot_monitor.conf`:

```ini
[daemon]
socket_path = /var/run/bot_monitor.sock

[logs]
log_file = /var/log/apache2/access.log
tail_lines = 10000
rotation_check_interval = 60

[attack_detection]
enabled = true
qps_threshold = 10
time_window = 60
min_duration = 30
cooldown = 300

[alerting]
enabled = true
smtp_host = localhost
smtp_port = 25
from_address = bot-monitor@localhost
to_addresses = admin@localhost,security@localhost
```

## 🚀 Usage

### Start the Daemon

```bash
# Start manually
sudo bot_monitor_daemon.py

# Or use systemd
sudo systemctl start bot_monitor

# Enable auto-start on boot
sudo systemctl enable bot_monitor

# Check status
sudo systemctl status bot_monitor

# View logs
sudo journalctl -u bot_monitor -f
```

### Connect with Client

```bash
# Run the dashboard
bot_monitor_client.py
```

### Keyboard Controls

**Navigation:**
- `1-5` - Jump to specific screen
- `←/→` - Navigate between screens
- `Q` - Quit

**On Detected Bots Screen:**
- `↑/↓` - Select bot
- `PgUp/PgDn` - Page up/down
- `S` - Change sort mode (Name → Last Seen → Count)
- `Enter` - View bot details
- `ESC` - Close details

**On Bot Attacks Screen:**
- `↑/↓` - Scroll
- `S` - Change sort mode (Time → QPS → Duration)

## 📊 Screenshots

### Bot Names Screen
```
┌────────────────────────────────────────────────────────────────────┐
│ Apache Bot Monitor - Bot Names [LIVE]                             │
│ QPS: 12.45 | Total: 45,230 | Bots: 8,942 (19.8%)                  │
├────────────────────────────────────────────────────────────────────┤
│    Past Minute        Past Hour           Past Day                 │
│ 1. Googlebot    142   1. Bingbot    1,234 1. Googlebot  12,456   │
│ 2. Bingbot       89   2. Googlebot  1,102 2. Bingbot    10,234   │
└────────────────────────────────────────────────────────────────────┘
```

### Detected Bots Screen
```
Detected Bots - Sorted by Count (High-Low) (34 unique bots)
────────────────────────────────────────────────────────────
#     Bot Name                           Count      Last Seen
────────────────────────────────────────────────────────────
1.    Googlebot                          1,234      Just now
2.    Bingbot                            856        15s ago
3.    Ahrefs Bot                         432        2m ago

Press Enter for details
```

### Bot Attacks Screen
```
Bot Attacks - 1 Active, 5 Historical
────────────────────────────────────────────────────────────
⚠ ACTIVE ATTACKS:
  Bad Bot: Peak QPS 45.2, Duration 120s

Attack History:
────────────────────────────────────────────────────────────
Time                 Bot Name              Peak QPS    Duration
2025-10-21 14:30:15  Scrapy Bot            23.4        180s
```

## 🔧 Advanced Configuration

### Attack Detection Tuning

```ini
[attack_detection]
# Alert when bot exceeds this QPS
qps_threshold = 10

# Measure QPS over this window (seconds)
time_window = 60

# Minimum attack duration to record (seconds)
min_duration = 30

# Wait this long before alerting again for same bot
cooldown = 300
```

### Email Alert Template

```ini
[alerting]
subject = [Bot Monitor] Attack detected from {bot_name}
```

### Log Rotation

The daemon automatically detects when Apache rotates logs by monitoring the file inode. No configuration needed!

## 🛠️ Troubleshooting

### Daemon won't start

```bash
# Check logs
sudo journalctl -u bot_monitor -n 50

# Check configuration
sudo bot_monitor_daemon.py -f  # Run in foreground

# Check permissions
ls -l /var/log/apache2/access.log
```

### Client can't connect

```bash
# Check if daemon is running
sudo systemctl status bot_monitor

# Check socket exists
ls -l /var/run/bot_monitor.sock

# Check socket permissions
sudo chmod 666 /var/run/bot_monitor.sock
```

### No alerts being sent

```bash
# Test local MTA
echo "Test" | mail -s "Test" admin@localhost

# Check alerting is enabled
grep "enabled = true" /etc/bot_monitor.conf

# Check daemon logs
sudo journalctl -u bot_monitor | grep -i alert
```

## 📈 Performance

- **Memory**: ~100MB for 10,000 log entries
- **CPU**: <1% when idle, <5% during active monitoring
- **Disk**: Minimal (only configuration and cache)

## 🔐 Security Considerations

- Runs as root to access Apache logs (can be changed)
- Unix socket permissions: 0666 (configurable)
- No network exposure by default
- Systemd hardening enabled

## 📝 Log Format Support

Supports Apache Combined Log Format:
```
192.168.1.1 - - [21/Oct/2025:10:30:45 +0000] "GET /page HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0 (compatible; Googlebot/2.1)"
```

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Bot patterns: [monperrus/crawler-user-agents](https://github.com/monperrus/crawler-user-agents)
- Inspired by htop, iftop, and other monitoring tools

## 📞 Support

- Issues: [GitHub Issues](https://github.com/yourusername/apache-bot-monitor/issues)
- Documentation: [Wiki](https://github.com/yourusername/apache-bot-monitor/wiki)

## 🚀 Roadmap

- [ ] Web-based dashboard
- [ ] Multiple log file support
- [ ] Database storage for long-term statistics
- [ ] Grafana integration
- [ ] API endpoints
- [ ] IP geolocation
- [ ] Bot behavior analysis

---

**Made with ❤️ for system administrators** 🤖📊
