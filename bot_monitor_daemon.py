#!/usr/bin/env python3
"""
Apache Bot Monitor Daemon
Runs continuously in the background monitoring Apache logs for bot activity.
"""

import os
import sys
import signal
import socket
import socketserver
import json
import time
import re
import urllib.request
import smtplib
import subprocess
import psutil
import ipaddress
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Thread, Lock, RLock
from configparser import ConfigParser
import argparse


class Config:
    """Configuration management."""
    
    DEFAULT_CONFIG = '/etc/bot_monitor.conf'
    USER_CONFIG = os.path.expanduser('~/.bot_monitor.conf')
    
    def __init__(self, config_file=None):
        self.config = ConfigParser()
        
        # Try to load config file
        config_paths = []
        if config_file:
            config_paths.append(config_file)
        config_paths.extend([self.USER_CONFIG, self.DEFAULT_CONFIG])
        
        loaded = False
        for path in config_paths:
            if os.path.exists(path):
                self.config.read(path)
                loaded = True
                print(f"Loaded configuration from: {path}")
                break
        
        if not loaded:
            print("Warning: No configuration file found, using defaults")
            self._set_defaults()
    
    def _set_defaults(self):
        """Set default configuration values."""
        self.config.add_section('daemon')
        self.config.set('daemon', 'socket_path', '/tmp/bot_monitor.sock')
        self.config.set('daemon', 'pid_file', '/tmp/bot_monitor.pid')
        
        self.config.add_section('logs')
        self.config.set('logs', 'log_file', '/var/log/apache2/access.log')
        self.config.set('logs', 'tail_lines', '10000')
        self.config.set('logs', 'rotation_check_interval', '60')
        
        self.config.add_section('bot_detection')
        self.config.set('bot_detection', 'database_url', 
                       'https://raw.githubusercontent.com/monperrus/crawler-user-agents/refs/heads/master/crawler-user-agents.json')
        self.config.set('bot_detection', 'cache_file', os.path.expanduser('~/.bot_monitor_cache.json'))
        self.config.set('bot_detection', 'update_interval', '24')
        
        self.config.add_section('attack_detection')
        self.config.set('attack_detection', 'enabled', 'true')
        self.config.set('attack_detection', 'qps_threshold', '10')
        self.config.set('attack_detection', 'time_window', '60')
        self.config.set('attack_detection', 'min_duration', '30')
        self.config.set('attack_detection', 'cooldown', '300')
        
        self.config.add_section('alerting')
        self.config.set('alerting', 'enabled', 'false')
        self.config.set('alerting', 'smtp_host', 'localhost')
        self.config.set('alerting', 'smtp_port', '25')
        self.config.set('alerting', 'from_address', 'bot-monitor@localhost')
        self.config.set('alerting', 'to_addresses', 'admin@localhost')
        
    def get(self, section, option, fallback=None):
        """Get configuration value."""
        try:
            return self.config.get(section, option)
        except:
            return fallback
    
    def getint(self, section, option, fallback=0):
        """Get integer configuration value."""
        try:
            return self.config.getint(section, option)
        except:
            return fallback
    
    def getboolean(self, section, option, fallback=False):
        """Get boolean configuration value."""
        try:
            return self.config.getboolean(section, option)
        except:
            return fallback


class LogParser:
    """Parse Apache Combined log format."""
    
    LOG_PATTERN = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d+) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    
    @staticmethod
    def parse_line(line):
        """Parse a single log line."""
        match = LogParser.LOG_PATTERN.match(line)
        if match:
            return match.groupdict()
        return None
    
    @staticmethod
    def parse_timestamp(timestamp_str):
        """Parse Apache timestamp to datetime object."""
        try:
            return datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        except:
            return datetime.now()


class BotDetector:
    """Detect and categorize bots."""
    
    def __init__(self, config):
        self.config = config
        self.bots = {}
        self.bot_details = {}  # Store full bot info including URLs
        self.loaded = False
        self.lock = Lock()
        
        self.fallback_bots = {
            'googlebot': 'Googlebot',
            'bingbot': 'Bingbot',
            'slurp': 'Yahoo Slurp',
            'duckduckbot': 'DuckDuckBot',
            'baiduspider': 'Baiduspider',
            'yandexbot': 'YandexBot',
            'ahrefsbot': 'Ahrefs Bot',
            'semrushbot': 'SEMrush Bot',
            'mj12bot': 'Majestic Bot',
            'facebookexternalhit': 'Facebook Bot',
            'twitterbot': 'Twitter Bot',
            'bot': 'Generic Bot',
            'crawler': 'Generic Crawler',
            'spider': 'Generic Spider',
        }
    
    def load_bot_database(self):
        """Load bot database from cache or download."""
        cache_file = self.config.get('bot_detection', 'cache_file')
        
        # Try cache first
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    self._parse_bot_data(data)
                    self.loaded = True
                    print(f"✓ Loaded {len(self.bots)} bot patterns from cache")
                    return True
            except Exception as e:
                print(f"Warning: Failed to load cache: {e}")
        
        # Download from URL
        url = self.config.get('bot_detection', 'database_url')
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Bot Monitor)')
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())
                self._parse_bot_data(data)
                
                # Save to cache
                try:
                    with open(cache_file, 'w') as f:
                        json.dump(data, f)
                except:
                    pass
                
                self.loaded = True
                print(f"✓ Downloaded {len(self.bots)} bot patterns")
                return True
        except Exception as e:
            print(f"Warning: Failed to download bot database: {e}")
            print(f"✓ Using {len(self.fallback_bots)} fallback patterns")
            return False
    
    def _parse_bot_data(self, data):
        """Parse bot database JSON."""
        if isinstance(data, list):
            for entry in data:
                pattern = entry.get('pattern', '')
                if pattern:
                    name = self._extract_bot_name(pattern)
                    self.bots[pattern.lower()] = name
                    # Store full details
                    self.bot_details[name] = {
                        'pattern': pattern,
                        'url': entry.get('url', ''),
                        'category': entry.get('category', 'Unknown'),
                        'producer': entry.get('producer', ''),
                        'description': entry.get('description', '')
                    }
    
    def _extract_bot_name(self, pattern):
        """Extract a friendly bot name from a pattern string."""
        name = pattern.strip()
        name = re.sub(r'[\[\]\(\)\{\}\^\$\.\*\+\?\\\/]', ' ', name)
        words = [w for w in name.split() if len(w) > 2]
        if words:
            bot_name = words[0]
            if 'bot' in bot_name.lower():
                return bot_name.capitalize()
            else:
                return bot_name.capitalize() + ' Bot'
        return 'Unknown Bot'
    
    def identify_bot(self, user_agent):
        """Identify if user agent is a bot. Returns (is_bot, bot_name)."""
        if not user_agent:
            return False, None
            
        ua_lower = user_agent.lower()
        
        with self.lock:
            # Check against known patterns from database first
            if self.loaded and self.bots:
                for pattern, name in self.bots.items():
                    try:
                        if re.search(pattern, ua_lower, re.IGNORECASE):
                            return True, name
                    except re.error:
                        if pattern in ua_lower:
                            return True, name
            
            # Check specific fallback patterns (skip generic ones if DB loaded)
            if self.loaded:
                # If we have the full database, only check specific fallbacks
                specific_fallbacks = {k: v for k, v in self.fallback_bots.items() 
                                     if k not in ['bot', 'crawler', 'spider']}
                for pattern, name in specific_fallbacks.items():
                    if pattern in ua_lower:
                        return True, name
            else:
                # No database loaded, use all fallback patterns
                for pattern, name in self.fallback_bots.items():
                    if pattern in ua_lower:
                        return True, name
        
        return False, None
    
    def get_bot_details(self, bot_name):
        """Get detailed information about a bot."""
        with self.lock:
            return self.bot_details.get(bot_name, {})


class AttackDetector:
    """Detect bot attacks based on QPS thresholds."""
    
    def __init__(self, config):
        self.config = config
        self.enabled = config.getboolean('attack_detection', 'enabled', True)
        self.qps_threshold = config.getint('attack_detection', 'qps_threshold', 10)
        self.time_window = config.getint('attack_detection', 'time_window', 60)
        self.min_duration = config.getint('attack_detection', 'min_duration', 30)
        self.cooldown = config.getint('attack_detection', 'cooldown', 300)
        
        self.bot_requests = defaultdict(lambda: deque())  # {bot_name: deque of timestamps}
        self.active_attacks = {}  # {bot_name: attack_info}
        self.attack_history = []  # List of completed attacks
        self.last_alert_time = {}  # {bot_name: timestamp}
        self.email_sent_count = 0  # Counter for emails sent
        self.lock = RLock()
    
    def record_request(self, bot_name, timestamp):
        """Record a bot request and check for attacks."""
        if not self.enabled or not bot_name:
            return None
        
        with self.lock:
            # Add request
            self.bot_requests[bot_name].append(timestamp)
            
            # Clean old requests outside time window
            cutoff = timestamp - timedelta(seconds=self.time_window)
            while self.bot_requests[bot_name] and self.bot_requests[bot_name][0] < cutoff:
                self.bot_requests[bot_name].popleft()
            
            # Calculate current QPS
            request_count = len(self.bot_requests[bot_name])
            qps = request_count / self.time_window
            
            # Check if attack threshold exceeded
            if qps >= self.qps_threshold:
                if bot_name not in self.active_attacks:
                    # New attack starting
                    self.active_attacks[bot_name] = {
                        'bot_name': bot_name,
                        'start_time': timestamp,
                        'peak_qps': qps,
                        'total_requests': request_count
                    }
                    
                    # Check cooldown before alerting
                    last_alert = self.last_alert_time.get(bot_name)
                    if not last_alert or (timestamp - last_alert).total_seconds() >= self.cooldown:
                        self.last_alert_time[bot_name] = timestamp
                        return self.active_attacks[bot_name]
                else:
                    # Update ongoing attack
                    attack = self.active_attacks[bot_name]
                    attack['peak_qps'] = max(attack['peak_qps'], qps)
                    attack['total_requests'] += 1
            else:
                # Attack ended
                if bot_name in self.active_attacks:
                    attack = self.active_attacks[bot_name]
                    duration = (timestamp - attack['start_time']).total_seconds()
                    
                    # Only record if it lasted long enough
                    if duration >= self.min_duration:
                        attack['end_time'] = timestamp
                        attack['duration'] = duration
                        self.attack_history.append(attack)
                        
                        # Keep history limited
                        max_history = self.config.getint('storage', 'max_attack_history', 1000)
                        if len(self.attack_history) > max_history:
                            self.attack_history = self.attack_history[-max_history:]
                    
                    del self.active_attacks[bot_name]
        
        return None
    
    def get_current_attacks(self):
        """Get list of currently active attacks."""
        with self.lock:
            return list(self.active_attacks.values())
    
    def get_attack_history(self, limit=100):
        """Get recent attack history."""
        with self.lock:
            return self.attack_history[-limit:]


class EmailAlerter:
    """Send email alerts for bot attacks."""
    
    def __init__(self, config):
        self.config = config
        self.enabled = config.getboolean('alerting', 'enabled', False)
        self.smtp_host = config.get('alerting', 'smtp_host', 'localhost')
        self.smtp_port = config.getint('alerting', 'smtp_port', 25)
        self.from_addr = config.get('alerting', 'from_address', 'bot-monitor@localhost')
        self.to_addrs = [addr.strip() for addr in config.get('alerting', 'to_addresses', '').split(',')]
    
    def send_alert(self, attack_info):
        """Send email alert for an attack."""
        if not self.enabled:
            return
        
        try:
            bot_name = attack_info['bot_name']
            start_time = attack_info['start_time'].strftime('%Y-%m-%d %H:%M:%S')
            peak_qps = attack_info['peak_qps']
            
            subject = f"[Bot Monitor] Attack detected from {bot_name}"
            body = f"""Bot Attack Detected

Bot Name: {bot_name}
Start Time: {start_time}
Peak QPS: {peak_qps:.2f}
Status: ACTIVE

This bot has exceeded the QPS threshold and may be hammering the server.

---
Apache Bot Monitor
"""
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = self.from_addr
            msg['To'] = ', '.join(self.to_addrs)
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.send_message(msg)
            
            print(f"✓ Alert sent: {subject}")
        except Exception as e:
            print(f"✗ Failed to send alert: {e}")


class IPLookup:
    """Lookup IP address information using whois and DNS."""
    
    def __init__(self):
        self.cache = {}
        self.cache_timeout = 3600  # 1 hour cache
        self.lock = Lock()
    
    def lookup(self, ip_address):
        """Lookup information for an IP address."""
        # Check cache first
        with self.lock:
            if ip_address in self.cache:
                cached_time, cached_data = self.cache[ip_address]
                if time.time() - cached_time < self.cache_timeout:
                    return cached_data
        
        # Perform lookup
        info = {}
        
        # Detect IP version
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            is_ipv6 = ip_obj.version == 6
            info['ip_version'] = ip_obj.version
        except:
            is_ipv6 = ':' in ip_address  # Fallback detection
            info['ip_version'] = 6 if is_ipv6 else 4
        
        # Try reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            info['hostname'] = hostname
        except:
            info['hostname'] = None
        
        # Try whois lookup for ASN info
        try:
            result = subprocess.run(
                ['whois', ip_address],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse ASN information (works for both IPv4 and IPv6)
                for line in output.split('\n'):
                    line_lower = line.lower()
                    
                    # ASN/Origin (various formats)
                    if 'origin:' in line_lower or 'originas:' in line_lower or 'originnas:' in line_lower:
                        asn = line.split(':', 1)[1].strip()
                        if asn.startswith('AS'):
                            asn = asn[2:]
                        info['asn'] = asn
                    
                    # Organization/Network name (various formats)
                    elif any(x in line_lower for x in ['org-name:', 'orgname:', 'netname:', 'descr:']):
                        if 'asn_name' not in info:
                            info['asn_name'] = line.split(':', 1)[1].strip()
                    
                    # Network prefix (IPv4 CIDR or IPv6 range)
                    elif 'cidr:' in line_lower or 'inet6num:' in line_lower or 'inetnum:' in line_lower:
                        if 'bgp_prefix' not in info:
                            info['bgp_prefix'] = line.split(':', 1)[1].strip()
                    
                    # Country
                    elif 'country:' in line_lower:
                        if 'country' not in info:
                            info['country'] = line.split(':', 1)[1].strip()
                    
                    # Registry/Source
                    elif 'source:' in line_lower:
                        if 'registry' not in info:
                            info['registry'] = line.split(':', 1)[1].strip()
        
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # whois command not available
            pass
        except Exception as e:
            pass
        
        # Check Spamhaus (basic check via DNS)
        try:
            if is_ipv6:
                # For IPv6, use different Spamhaus zone
                # Convert IPv6 to nibble format for DNS lookup
                try:
                    ip_obj = ipaddress.IPv6Address(ip_address)
                    # Expand to full format and remove colons
                    expanded = ip_obj.exploded.replace(':', '')
                    # Reverse nibbles and add dots
                    nibbles = '.'.join(reversed(expanded))
                    query = f"{nibbles}.ipv6.zen.spamhaus.org"
                    
                    try:
                        socket.gethostbyname(query)
                        info['spamhaus'] = 'LISTED'
                    except socket.gaierror:
                        info['spamhaus'] = 'NOT LISTED'
                except:
                    info['spamhaus'] = 'UNKNOWN'
            else:
                # IPv4 - Check entire /24 network
                try:
                    # Get the /24 network
                    ip_obj = ipaddress.IPv4Address(ip_address)
                    network = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)
                    
                    listed_ips = []
                    checked_count = 0
                    max_checks = 256  # Full /24
                    
                    # Check each IP in the /24 network
                    for host in network.hosts():
                        if checked_count >= max_checks:
                            break
                        
                        host_str = str(host)
                        reversed_ip = '.'.join(reversed(host_str.split('.')))
                        query = f"{reversed_ip}.zen.spamhaus.org"
                        
                        try:
                            socket.gethostbyname(query)
                            listed_ips.append(host_str)
                        except socket.gaierror:
                            pass  # Not listed, continue
                        
                        checked_count += 1
                    
                    # Report results
                    if listed_ips:
                        # Limit to first 10 IPs to avoid overwhelming the display
                        if len(listed_ips) > 10:
                            info['spamhaus'] = f"LISTED ({len(listed_ips)} IPs): {', '.join(listed_ips[:10])}, ..."
                        else:
                            info['spamhaus'] = f"LISTED ({len(listed_ips)} IPs): {', '.join(listed_ips)}"
                        info['spamhaus_listed_ips'] = listed_ips
                        info['spamhaus_listed_count'] = len(listed_ips)
                    else:
                        info['spamhaus'] = 'NOT LISTED'
                        info['spamhaus_listed_count'] = 0
                except Exception as e:
                    info['spamhaus'] = 'UNKNOWN'
        except:
            info['spamhaus'] = 'UNKNOWN'
        
        # Cache the result
        with self.lock:
            self.cache[ip_address] = (time.time(), info)
        
        return info


class StatsCollector:
    """Collect and maintain all statistics."""
    
    def __init__(self):
        self.lock = RLock()
        self.total_requests = 0
        self.bot_requests = 0
        self.bot_tracking = {}  # {bot_name: {'last_seen': datetime, 'count': int, 'first_seen': datetime}}
        self.qps = 0.0
        self.qps_counter = 0
        self.last_qps_update = time.time()
        
        # Time window stats
        self.events = deque()
        self.bot_counts = defaultdict(lambda: defaultdict(int))
        self.bot_ip_counts = defaultdict(lambda: defaultdict(int))
        self.window_totals = defaultdict(int)
        self.window_bots = defaultdict(int)
    
    def record_event(self, timestamp, ip, is_bot, bot_name):
        """Record a log event."""
        with self.lock:
            self.total_requests += 1
            if is_bot:
                self.bot_requests += 1
                if bot_name:
                    if bot_name not in self.bot_tracking:
                        self.bot_tracking[bot_name] = {
                            'first_seen': timestamp,
                            'last_seen': timestamp,
                            'count': 0
                        }
                    self.bot_tracking[bot_name]['last_seen'] = timestamp
                    self.bot_tracking[bot_name]['count'] += 1
            
            # Update events for time windows
            self.events.append((timestamp, ip, is_bot, bot_name))
            self._cleanup_old_events()
            self._update_window_stats()
            
            # Update QPS
            self.qps_counter += 1
            current_time = time.time()
            if current_time - self.last_qps_update >= 1.0:
                self.qps = self.qps_counter / (current_time - self.last_qps_update)
                self.qps_counter = 0
                self.last_qps_update = current_time
    
    def _cleanup_old_events(self):
        """Remove events older than 24 hours."""
        cutoff = datetime.now() - timedelta(days=1)
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
    
    def _update_window_stats(self):
        """Update time window statistics."""
        now = datetime.now()
        windows = {
            'minute': timedelta(minutes=1),
            'hour': timedelta(hours=1),
            'day': timedelta(days=1)
        }
        
        for window in windows:
            self.bot_counts[window].clear()
            self.bot_ip_counts[window].clear()
            self.window_totals[window] = 0
            self.window_bots[window] = 0
        
        for timestamp, ip, is_bot, bot_name in self.events:
            for window_name, window_delta in windows.items():
                if now - timestamp <= window_delta:
                    self.window_totals[window_name] += 1
                    if is_bot and bot_name:
                        self.window_bots[window_name] += 1
                        self.bot_counts[window_name][bot_name] += 1
                        self.bot_ip_counts[window_name][ip] += 1
    
    def get_stats(self):
        """Get all statistics for clients."""
        with self.lock:
            return {
                'total_requests': self.total_requests,
                'bot_requests': self.bot_requests,
                'qps': self.qps,
                'bot_tracking': dict(self.bot_tracking),
                'bot_counts': {k: dict(v) for k, v in self.bot_counts.items()},
                'bot_ip_counts': {k: dict(v) for k, v in self.bot_ip_counts.items()},
                'window_totals': dict(self.window_totals),
                'window_bots': dict(self.window_bots),
            }


class LogMonitor:
    """Monitor Apache log file continuously."""
    
    def __init__(self, config, bot_detector, stats_collector, attack_detector, email_alerter):
        self.config = config
        self.bot_detector = bot_detector
        self.stats = stats_collector
        self.attack_detector = attack_detector
        self.alerter = email_alerter
        self.parser = LogParser()
        self.running = False
        self.log_file = config.get('logs', 'log_file')
        self.file_inode = None
        self.loading_complete = False
        self.loading_progress = 0  # 0-100
        self.process = psutil.Process()  # For monitoring memory/CPU
    
    def start(self):
        """Start monitoring."""
        self.running = True
        
        # Start monitor thread
        monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        
        # Start rotation check thread
        rotation_thread = Thread(target=self._check_rotation, daemon=True)
        rotation_thread.start()
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
    
    def _read_last_n_lines(self, n):
        """Read last N lines from log file."""
        buffer = b''
        lines_found = []
        block_size = 8192
        
        try:
            with open(self.log_file, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()
                
                if file_size == 0:
                    return []
                
                position = file_size
                
                while position > 0 and len(lines_found) < n:
                    chunk_size = min(block_size, position)
                    position -= chunk_size
                    f.seek(position)
                    chunk = f.read(chunk_size)
                    buffer = chunk + buffer
                    
                    try:
                        decoded = buffer.decode('utf-8', errors='ignore')
                        all_lines = [line for line in decoded.split('\n') if line.strip()]
                        if len(all_lines) >= n:
                            return all_lines[-n:]
                        lines_found = all_lines
                    except:
                        continue
                
                return lines_found
        except Exception as e:
            print(f"Error reading log file: {e}")
            return []
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        print(f"Starting log monitor: {self.log_file}")
        
        # Load initial lines
        tail_lines = self.config.getint('logs', 'tail_lines', 10000)
        if tail_lines > 0:
            print(f"Loading last {tail_lines} lines...")
            lines = self._read_last_n_lines(tail_lines)
            total = len(lines)
            for i, line in enumerate(lines):
                self._process_line(line)
                if i % 100 == 0:  # Update progress every 100 lines
                    self.loading_progress = int((i / total) * 100)
            self.loading_progress = 100
            print(f"✓ Loaded {len(lines)} lines")
        
        # Mark loading as complete
        self.loading_complete = True
        print("✓ Initial load complete")
        
        # Get file inode
        try:
            self.file_inode = os.stat(self.log_file).st_ino
        except:
            pass
        
        # Follow file
        print("✓ Now monitoring for new entries...")
        with open(self.log_file, 'r', errors='ignore') as f:
            f.seek(0, 2)  # Go to end
            
            while self.running:
                line = f.readline()
                if line:
                    self._process_line(line.strip())
                else:
                    time.sleep(0.1)
    
    def get_system_stats(self):
        """Get daemon memory and CPU usage."""
        try:
            return {
                'memory_mb': self.process.memory_info().rss / 1024 / 1024,
                'cpu_percent': self.process.cpu_percent()
            }
        except:
            return {'memory_mb': 0, 'cpu_percent': 0}
    
    def _check_rotation(self):
        """Check for log file rotation."""
        interval = self.config.getint('logs', 'rotation_check_interval', 60)
        
        while self.running:
            time.sleep(interval)
            
            try:
                current_inode = os.stat(self.log_file).st_ino
                if self.file_inode and current_inode != self.file_inode:
                    print("✓ Log rotation detected, reopening file...")
                    self.file_inode = current_inode
                    # The monitor loop will reopen automatically on next iteration
            except Exception as e:
                print(f"Warning: Error checking log rotation: {e}")
    
    def _process_line(self, line):
        """Process a single log line."""
        if not line:
            return
        
        parsed = self.parser.parse_line(line)
        if not parsed:
            return
        
        timestamp = self.parser.parse_timestamp(parsed['timestamp'])
        ip = parsed['ip']
        user_agent = parsed['user_agent']
        
        is_bot, bot_name = self.bot_detector.identify_bot(user_agent)
        
        # Record in stats
        self.stats.record_event(timestamp, ip, is_bot, bot_name)
        
        # Check for attacks
        if is_bot and bot_name:
            attack = self.attack_detector.record_request(bot_name, timestamp)
            if attack:
                print(f"⚠ Attack detected from {bot_name} (QPS: {attack['peak_qps']:.2f})")
                self.alerter.send_alert(attack)
                # Increment email counter
                self.attack_detector.email_sent_count += 1


class DaemonServer:
    """Socket server for client connections."""
    
    def __init__(self, config, stats_collector, attack_detector, bot_detector, log_monitor, ip_lookup):
        self.config = config
        self.stats = stats_collector
        self.attacks = attack_detector
        self.bot_detector = bot_detector
        self.log_monitor = log_monitor
        self.ip_lookup = ip_lookup
        self.socket_path = config.get('daemon', 'socket_path')
        self.server = None
    
    def start(self):
        """Start the server."""
        # Remove old socket if exists
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        
        # Create server
        self.server = socketserver.UnixStreamServer(self.socket_path, self._make_handler())
        os.chmod(self.socket_path, 0o666)
        
        print(f"✓ Server listening on {self.socket_path}")
        
        # Start server thread
        server_thread = Thread(target=self.server.serve_forever, daemon=True)
        server_thread.start()
    
    def stop(self):
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
    
    def _make_handler(self):
        """Create request handler class."""
        stats = self.stats
        attacks = self.attacks
        bot_detector = self.bot_detector
        log_monitor = self.log_monitor
        config = self.config
        ip_lookup = self.ip_lookup
        
        class RequestHandler(socketserver.StreamRequestHandler):
            def handle(self):
                try:
                    # Read command
                    data = self.rfile.readline().decode('utf-8').strip()
                    
                    if data == 'GET_STATS':
                        # Get stats and convert datetime objects to ISO strings
                        stats_data = stats.get_stats()
                        
                        # Convert datetime objects in bot_tracking
                        for bot_name, bot_data in stats_data['bot_tracking'].items():
                            if 'last_seen' in bot_data and isinstance(bot_data['last_seen'], datetime):
                                bot_data['last_seen'] = bot_data['last_seen'].isoformat()
                            if 'first_seen' in bot_data and isinstance(bot_data['first_seen'], datetime):
                                bot_data['first_seen'] = bot_data['first_seen'].isoformat()
                        
                        # Convert datetime objects in attacks
                        current_attacks = attacks.get_current_attacks()
                        for attack in current_attacks:
                            if 'start_time' in attack and isinstance(attack['start_time'], datetime):
                                attack['start_time'] = attack['start_time'].isoformat()
                            if 'end_time' in attack and isinstance(attack['end_time'], datetime):
                                attack['end_time'] = attack['end_time'].isoformat()
                        
                        attack_history = attacks.get_attack_history()
                        for attack in attack_history:
                            if 'start_time' in attack and isinstance(attack['start_time'], datetime):
                                attack['start_time'] = attack['start_time'].isoformat()
                            if 'end_time' in attack and isinstance(attack['end_time'], datetime):
                                attack['end_time'] = attack['end_time'].isoformat()
                        
                        # Get bot database count
                        bot_db_count = len(bot_detector.bots) if bot_detector.loaded else len(bot_detector.fallback_bots)
                        
                        response = {
                            'stats': stats_data,
                            'attacks': {
                                'current': current_attacks,
                                'history': attack_history
                            },
                            'loading_complete': log_monitor.loading_complete,
                            'loading_progress': log_monitor.loading_progress,
                            'bot_db_count': bot_db_count,
                            'email_sent_count': attacks.email_sent_count
                        }
                        self.wfile.write((json.dumps(response) + '\n').encode('utf-8'))
                    
                    elif data.startswith('GET_BOT_DETAILS:'):
                        bot_name = data.split(':', 1)[1]
                        details = bot_detector.get_bot_details(bot_name)
                        response = {'details': details}
                        self.wfile.write((json.dumps(response) + '\n').encode('utf-8'))
                    
                    elif data == 'GET_ALERT_CONFIG':
                        alert_config = {
                            'enabled': config.getboolean('attack_detection', 'enabled', True),
                            'qps_threshold': config.getint('attack_detection', 'qps_threshold', 10),
                            'time_window': config.getint('attack_detection', 'time_window', 60),
                            'min_duration': config.getint('attack_detection', 'min_duration', 30),
                            'cooldown': config.getint('attack_detection', 'cooldown', 300),
                            'email_enabled': config.getboolean('alerting', 'enabled', False),
                            'smtp_host': config.get('alerting', 'smtp_host', 'localhost'),
                            'smtp_port': config.getint('alerting', 'smtp_port', 25),
                            'from_address': config.get('alerting', 'from_address', 'bot-monitor@localhost'),
                            'to_addresses': config.get('alerting', 'to_addresses', 'admin@localhost')
                        }
                        response = {'config': alert_config}
                        self.wfile.write((json.dumps(response) + '\n').encode('utf-8'))
                    
                    elif data.startswith('UPDATE_ALERT_CONFIG:'):
                        try:
                            config_json = data.split(':', 1)[1]
                            new_config = json.loads(config_json)
                            
                            # Update attack detection settings
                            attacks.enabled = new_config.get('enabled', attacks.enabled)
                            attacks.qps_threshold = new_config.get('qps_threshold', attacks.qps_threshold)
                            attacks.time_window = new_config.get('time_window', attacks.time_window)
                            attacks.min_duration = new_config.get('min_duration', attacks.min_duration)
                            attacks.cooldown = new_config.get('cooldown', attacks.cooldown)
                            
                            response = {'status': 'ok', 'message': 'Alert settings updated (in-memory only)'}
                        except Exception as e:
                            response = {'status': 'error', 'message': str(e)}
                        
                        self.wfile.write((json.dumps(response) + '\n').encode('utf-8'))
                    
                    elif data.startswith('LOOKUP_IP:'):
                        ip_address = data.split(':', 1)[1]
                        ip_info = ip_lookup.lookup(ip_address)
                        response = {'ip_info': ip_info}
                        self.wfile.write((json.dumps(response) + '\n').encode('utf-8'))
                    
                    elif data == 'SEND_TEST_EMAIL':
                        try:
                            # Get email config
                            email_enabled = config.getboolean('alerting', 'enabled', False)
                            
                            if not email_enabled:
                                response = {'status': 'error', 'message': 'Email alerting is disabled in configuration'}
                            else:
                                smtp_host = config.get('alerting', 'smtp_host', 'localhost')
                                smtp_port = config.getint('alerting', 'smtp_port', 25)
                                from_addr = config.get('alerting', 'from_address', 'bot-monitor@localhost')
                                to_addrs = config.get('alerting', 'to_addresses', 'admin@localhost')
                                
                                # Create test email
                                subject = "Apache Bot Monitor - Test Email"
                                body = f"""This is a test email from Apache Bot Monitor.

If you received this message, email alerting is configured correctly.

Configuration:
- SMTP Host: {smtp_host}
- SMTP Port: {smtp_port}
- From: {from_addr}
- To: {to_addrs}

Sent: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
                                
                                msg = MIMEText(body)
                                msg['Subject'] = subject
                                msg['From'] = from_addr
                                msg['To'] = to_addrs
                                
                                # Send email
                                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                                server.send_message(msg)
                                server.quit()
                                
                                # Increment email counter for test emails too
                                attacks.email_sent_count += 1
                                
                                response = {'status': 'ok', 'message': f'Test email sent successfully to {to_addrs}'}
                        except Exception as e:
                            response = {'status': 'error', 'message': f'Failed to send test email: {str(e)}'}
                        
                        self.wfile.write((json.dumps(response) + '\n').encode('utf-8'))
                    
                except Exception as e:
                    print(f"Error handling client request: {e}")
        
        return RequestHandler


def create_pid_file(pid_file):
    """Create PID file."""
    try:
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
        return True
    except Exception as e:
        print(f"Error creating PID file: {e}")
        return False


def remove_pid_file(pid_file):
    """Remove PID file."""
    try:
        if os.path.exists(pid_file):
            os.unlink(pid_file)
    except:
        pass


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Apache Bot Monitor Daemon')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-f', '--foreground', action='store_true', help='Run in foreground (don\'t daemonize)')
    args = parser.parse_args()
    
    # Load configuration
    config = Config(args.config)
    
    # Create PID file
    pid_file = config.get('daemon', 'pid_file')
    if not create_pid_file(pid_file):
        print("Failed to create PID file")
        sys.exit(1)
    
    print("=" * 70)
    print("Apache Bot Monitor Daemon")
    print("=" * 70)
    
    # Initialize components
    print("\nInitializing components...")
    bot_detector = BotDetector(config)
    bot_detector.load_bot_database()
    
    stats_collector = StatsCollector()
    attack_detector = AttackDetector(config)
    email_alerter = EmailAlerter(config)
    ip_lookup = IPLookup()
    
    # Start log monitor
    log_monitor = LogMonitor(config, bot_detector, stats_collector, attack_detector, email_alerter)
    log_monitor.start()
    
    # Start daemon server
    daemon_server = DaemonServer(config, stats_collector, attack_detector, bot_detector, log_monitor, ip_lookup)
    daemon_server.start()
    
    print("\n" + "=" * 70)
    print("Daemon started successfully!")
    print("=" * 70)
    print(f"Socket: {config.get('daemon', 'socket_path')}")
    print(f"Log file: {config.get('logs', 'log_file')}")
    print("Press Ctrl+C to stop")
    print("=" * 70)
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        print("\n\nShutting down...")
        log_monitor.stop()
        daemon_server.stop()
        remove_pid_file(pid_file)
        print("Daemon stopped.")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Keep running
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
