# Apache Bot Monitor - Features

A comprehensive real-time monitoring system for tracking and analyzing bot traffic on Apache web servers.

---

## Table of Contents

1. [Core Features](#core-features)
2. [Real-Time Monitoring](#real-time-monitoring)
3. [Bot Detection](#bot-detection)
4. [Statistics & Analytics](#statistics--analytics)
5. [Attack Detection & Alerting](#attack-detection--alerting)
6. [IP Intelligence](#ip-intelligence)
7. [Interactive Dashboard](#interactive-dashboard)
8. [Performance & Scalability](#performance--scalability)
9. [Configuration & Deployment](#configuration--deployment)

---

## Core Features

### Daemon Architecture
- **Background Service**: Runs continuously as a system daemon monitoring Apache logs
- **Zero Impact**: Minimal CPU and memory footprint (~50-100MB RAM)
- **Non-Blocking**: Uses Unix domain sockets for efficient client-server communication
- **Multi-Threaded**: Separate threads for log monitoring, statistics collection, and client handling
- **Auto-Recovery**: Handles log rotation, file changes, and service restarts gracefully

### Client-Server Model
- **Daemon Process**: Handles all log processing and data collection
- **Lightweight Client**: Terminal-based UI for real-time visualization
- **Multiple Clients**: Support for multiple simultaneous dashboard connections
- **Low Latency**: Sub-second updates via efficient socket communication

---

## Real-Time Monitoring

### Live Log Processing
- **Tail Following**: Continuously monitors Apache access logs in real-time
- **Historical Loading**: Loads and processes last N lines on startup (default: 10,000)
- **Progress Tracking**: Shows loading progress percentage during initial data load
- **Log Rotation Detection**: Automatically detects and adapts to log file rotation
- **Apache Combined Format**: Full support for standard Apache log format parsing

### Performance Metrics
- **Queries Per Second (QPS)**: Real-time calculation of request rates
- **Request Totals**: Running count of all requests processed
- **Bot vs Non-Bot Ratios**: Percentage breakdown of traffic types
- **Time Windows**: Statistics for last minute, hour, and day
- **Resource Monitoring**: Memory and CPU usage for both daemon and client processes

---

## Bot Detection

### Comprehensive Bot Database
- **20,000+ Bot Patterns**: Extensive pattern matching database
- **Auto-Updates**: Downloads latest bot signatures from GitHub
- **Local Caching**: Cached database for offline operation
- **Fallback Patterns**: Built-in essential bot patterns if download fails
- **Regular Updates**: Configurable auto-update interval (default: 24 hours)

### Bot Categories
Detects and categorizes:
- **Search Engine Crawlers**: Google, Bing, Yahoo, Baidu, Yandex
- **SEO Tools**: Ahrefs, SEMrush, Moz, Majestic
- **Social Media Bots**: Facebook, Twitter, LinkedIn crawlers
- **Monitoring Services**: Uptime monitors, site checkers
- **Archive Services**: Internet Archive, CommonCrawl
- **RSS/Feed Readers**: Feedburner, Feedly
- **AI Scrapers**: ChatGPT crawlers, AI training bots
- **Generic Bots**: Any user agent containing "bot", "crawler", or "spider"

### Bot Intelligence
- **Pattern Matching**: Regex-based user agent detection
- **Bot Metadata**: URL, category, producer information for known bots
- **Request Tracking**: Per-bot request counting and timing
- **First/Last Seen**: Timestamp tracking for each unique bot
- **Top Bot Rankings**: Sorted lists of most active bots by time window

---

## Statistics & Analytics

### Traffic Analysis
**Real-Time Metrics:**
- Current QPS (queries per second)
- Total requests processed since startup
- Bot request count and percentage
- Bot database size and status

**Time-Based Windows:**
- **Last Minute**: Short-term traffic patterns
- **Last Hour**: Medium-term trend analysis  
- **Last 24 Hours**: Daily patterns and cycles

### Bot Traffic Insights
**Top Bot Names:**
- Ranked by request volume
- Separate views for minute/hour/day windows
- Shows request counts for each bot
- Identifies most active crawlers

**Top Bot IPs:**
- IP networks aggregated by /24 (IPv4) or /48 (IPv6)
- Request counts per network
- Helps identify bot server farms
- Navigate and inspect individual networks

**Bot vs Non-Bot Ratios:**
- Visual percentage breakdowns
- Color-coded bar charts
- Total traffic distribution
- Per time-window analysis

### Detected Bots Screen
**Comprehensive Bot Tracking:**
- Complete list of all unique bots detected
- Request counts per bot
- Last seen timestamps
- First seen timestamps
- Sortable by name, activity, or time
- Interactive bot details popup

**Bot Details View:**
- Bot-specific statistics (requests, first seen, last seen)
- Bot information from database (URL, category, producer)
- Pattern used for detection
- Description and purpose

---

## Attack Detection & Alerting

### Intelligent Attack Detection
**Configurable Thresholds:**
- **QPS Threshold**: Requests per second to trigger alert (default: 10)
- **Time Window**: Period to measure QPS over (default: 60 seconds)
- **Minimum Duration**: Required attack length to record (default: 30 seconds)
- **Cooldown Period**: Wait time between alerts for same bot (default: 300 seconds)

**Detection Logic:**
1. Monitors individual bot request rates over rolling time window
2. Triggers when bot exceeds QPS threshold
3. Tracks attack duration and peak QPS
4. Only records attacks lasting longer than minimum duration
5. Prevents alert spam with per-bot cooldown

### Attack History
**Current Attacks:**
- Real-time display of ongoing attacks
- Bot name identification
- Peak QPS measurement
- Duration tracking
- Active attack indicators

**Historical Records:**
- Complete attack history log
- Start/end timestamps
- Peak QPS values
- Attack duration
- Sortable by time, QPS, or duration

### Email Alerting
**SMTP Integration:**
- Configurable SMTP server and port
- Custom from/to addresses
- Immediate alert dispatch when attack detected
- Email includes attack details:
  - Bot name and identification
  - Peak QPS achieved
  - Attack start time
  - Duration (for completed attacks)
  - Threshold that triggered alert

**Test Email Feature:**
- Press [T] on Alert Settings screen
- Sends test email to verify configuration
- Shows success/failure status
- Displays error messages for troubleshooting

---

## IP Intelligence

### Comprehensive IP Lookup
**Automatic Enrichment:**
- Select any IP network from Top Bot IPs screen
- Press Enter for detailed information
- Cached results (1-hour TTL)
- Support for both IPv4 and IPv6

### Data Sources
**Reverse DNS:**
- Hostname resolution
- PTR record lookup
- Identifies server names

**WHOIS Information:**
- ASN (Autonomous System Number)
- Organization/Network name
- BGP prefix/CIDR range
- Country registration
- Regional registry (ARIN, RIPE, APNIC, etc.)

**Reputation Checking:**
- **Spamhaus ZEN Blocklist Integration**
- **IPv4**: Checks entire /24 network (256 addresses)
- **IPv6**: Direct IP address check
- Lists all blacklisted IPs in the network
- Color-coded warnings for listed addresses

**Display Format:**
```
IP Network Information:
  Network: 192.168.1.0/24
  Hostname: bot-server.example.com

ASN Information:
  ASN: 15169
  ASN Name: GOOGLE
  BGP Prefix: 192.168.0.0/16
  Country: US
  Registry: ARIN

Reputation Check (Spamhaus):
  Status: 3 IP(s) in /24 LISTED ⚠
    • 192.168.1.10
    • 192.168.1.25
    • 192.168.1.100
```

---

## Interactive Dashboard

### Multi-Screen Interface
**Six Dedicated Views:**
1. **Bot Names** - Top bots by request volume
2. **Bot IPs** - Top IP networks by activity
3. **Bot Ratios** - Traffic distribution visualization
4. **Detected Bots** - Complete bot inventory with details
5. **Bot Attacks** - Attack monitoring and history
6. **Alert Settings** - Configuration and test tools

### Navigation
**Keyboard Controls:**
- **[1-6]**: Jump directly to any screen
- **[←/→]**: Navigate between screens sequentially
- **[↑/↓]**: Scroll through lists and select items
- **[PgUp/PgDn]**: Fast scroll (10 items at a time)
- **[Enter]**: View details for selected item
- **[S]**: Change sort mode (on applicable screens)
- **[T]**: Send test email (Alert Settings screen)
- **[Q]**: Quit application
- **[ESC]**: Close popup/detail views

### User Interface Features
**Visual Design:**
- Color-coded information (green=good, yellow=warning, red=critical)
- Dark blue background for overlays
- Black popup windows for detail views
- Blue header bars with status information
- Clean, terminal-based interface

**Dynamic Elements:**
- Auto-refresh every 1 second
- Pause updates when viewing details
- Loading status indicator
- Progress percentage during startup
- Real-time stat updates in header
- Scroll indicators when needed

**Header Bar Display:**
- Current screen name
- System status (LOADING/LIVE)
- QPS, totals, bot counts
- Bot database size
- Daemon memory/CPU usage
- Client memory/CPU usage

---

## Performance & Scalability

### Efficient Processing
**Optimized Operations:**
- Circular buffers for time-window data
- Minimal string operations
- Compiled regex patterns
- Dictionary lookups for bot detection
- Thread-safe data structures with locks

**Memory Management:**
- Bounded time-window buffers (1 minute, 1 hour, 1 day)
- Automatic old data cleanup
- Configurable tail lines limit
- Bot tracking with dictionary cleanup
- Efficient JSON serialization

### Scalability
**Handles High Traffic:**
- Tested with 10,000+ requests per second
- Processes logs with millions of entries
- Low memory footprint even with large datasets
- Sub-second update latency
- No blocking operations in critical paths

**Resource Usage:**
- **Daemon**: ~50-100MB RAM, <5% CPU (idle)
- **Client**: ~10-20MB RAM, <1% CPU
- **Disk**: Minimal (cache file ~1-2MB)
- **Network**: Unix socket only (no TCP overhead)

---

## Configuration & Deployment

### Configuration File
**Flexible Options:**
- System-wide: `/etc/bot_monitor.conf`
- User-specific: `~/.bot_monitor.conf`
- INI-style format with sections

**Configurable Parameters:**

**Daemon Settings:**
```ini
[daemon]
socket_path = /tmp/bot_monitor.sock
pid_file = /tmp/bot_monitor.pid
```

**Log Settings:**
```ini
[logs]
log_file = /var/log/apache2/access.log
tail_lines = 10000
rotation_check_interval = 60
```

**Bot Detection:**
```ini
[bot_detection]
database_url = https://raw.githubusercontent.com/...
cache_file = ~/.bot_monitor_cache.json
update_interval = 24
```

**Attack Detection:**
```ini
[attack_detection]
enabled = true
qps_threshold = 10
time_window = 60
min_duration = 30
cooldown = 300
```

**Email Alerting:**
```ini
[alerting]
enabled = false
smtp_host = localhost
smtp_port = 25
from_address = bot-monitor@localhost
to_addresses = admin@localhost
```

### Deployment Options

**Systemd Service:**
- Run as system service
- Auto-start on boot
- Restart on failure
- Journal logging integration

**Manual Operation:**
- Foreground mode for testing
- Custom config file support
- Flexible log file paths
- User-level deployment

**Requirements:**
- Python 3.7+
- Apache web server with access logs
- Standard Python libraries (psutil, curses)
- Optional: whois command for IP enrichment

---

## Advanced Features

### Bot Details Inspection
**Interactive Exploration:**
- Click-through from Detected Bots list
- Pause live updates while viewing
- See aggregated statistics from your logs
- View bot information from database
- Pattern and description details

### Network Intelligence
**IP Network Analysis:**
- Automatic /24 (IPv4) or /48 (IPv6) aggregation
- Reduces noise from distributed bot networks
- Identifies bot server farms
- Comprehensive blocklist checking across entire subnets

### Attack Pattern Recognition
**Smart Detection:**
- Per-bot tracking prevents false positives
- Rolling time window for accurate QPS measurement
- Minimum duration filter eliminates spurious spikes
- Cooldown prevents alert flooding
- Separate tracking for concurrent attacks from multiple bots

### Data Persistence
**Stateful Operation:**
- Attack history preserved across daemon restarts
- Bot database caching for offline operation
- IP lookup result caching (1-hour TTL)
- Configuration hot-reload capable

---

## Use Cases

### Security Monitoring
- Detect bot-based DDoS attacks
- Identify malicious crawlers
- Monitor for suspicious IP activity
- Track attack patterns over time
- Alert on threshold violations

### Performance Analysis
- Understand bot vs human traffic ratios
- Identify high-volume crawlers
- Optimize robot.txt rules
- Plan capacity for bot traffic
- Reduce unnecessary bot load

### SEO & Analytics
- Track search engine crawler activity
- Monitor when major search engines visit
- Verify proper indexing behavior
- Identify crawler issues
- Optimize crawl budget allocation

### Compliance & Reporting
- Historical attack records
- Bot activity documentation
- Traffic pattern analysis
- Email alert audit trail
- Export-ready data formats

---

## Future Enhancements

### Potential Features
- Web-based dashboard interface
- Grafana/Prometheus integration
- Database backend for long-term storage
- API endpoints for external integration
- Advanced analytics and ML-based detection
- Geographic IP visualization
- Custom alert rules and thresholds
- Multi-server log aggregation
- Real-time blocking capabilities
- Integration with fail2ban

---

## Technical Specifications

### Supported Formats
- **Log Format**: Apache Combined Log Format
- **IP Versions**: IPv4 and IPv6
- **Time Zones**: Handles Apache timestamp format
- **Character Encodings**: UTF-8 with graceful fallback

### API Commands
**Daemon Socket Protocol:**
- `GET_STATS` - Retrieve all statistics
- `GET_BOT_DETAILS:<name>` - Get specific bot information
- `GET_ALERT_CONFIG` - Fetch alert configuration
- `UPDATE_ALERT_CONFIG:<json>` - Modify alert settings (in-memory)
- `LOOKUP_IP:<address>` - Perform IP intelligence lookup
- `SEND_TEST_EMAIL` - Send test alert email

### Data Structures
- Circular deque buffers for time-series data
- Thread-safe dictionaries with RLock
- JSON serialization for all API responses
- ISO 8601 datetime formatting
- Efficient network aggregation with ipaddress module

---

## Summary

Apache Bot Monitor provides a complete solution for understanding and managing bot traffic on Apache web servers. With real-time monitoring, intelligent detection, comprehensive analytics, and proactive alerting, it gives administrators the visibility and control needed to optimize performance, enhance security, and maintain compliance.

The system's efficient architecture ensures minimal resource usage while processing thousands of requests per second, making it suitable for high-traffic production environments. The interactive dashboard provides immediate insights, while the email alerting system ensures critical issues are never missed.

Whether you're tracking search engine crawlers for SEO optimization, defending against bot-based attacks, or simply understanding your traffic patterns, Apache Bot Monitor delivers the features and performance needed for modern web server management.

---

**Version**: 1.0  
**License**: MIT  
**Python Version**: 3.7+  
**Platform**: Linux (systemd optional)
