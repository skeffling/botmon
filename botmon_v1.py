#!/usr/bin/env python3
"""
Apache Combined Log Bot Monitor
A curses-based real-time monitoring tool for tracking bot activity in Apache logs.
"""

import curses
import re
import time
import urllib.request
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Thread, Lock
import os
import sys
import argparse


class LogParser:
    """Parse Apache Combined log format."""
    
    # Apache Combined Log Format regex
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
            # Format: 21/Oct/2025:10:30:45 +0000
            return datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        except:
            return datetime.now()


class BotDetector:
    """Detect and categorize bots using well-known-bots.json."""
    
    def __init__(self):
        self.bots = {}
        self.loaded = False
        self.fallback_bots = {
            # Common search engine bots
            'googlebot': 'Googlebot',
            'bingbot': 'Bingbot',
            'slurp': 'Yahoo Slurp',
            'duckduckbot': 'DuckDuckBot',
            'baiduspider': 'Baiduspider',
            'yandexbot': 'YandexBot',
            'sogou': 'Sogou Spider',
            'exabot': 'Exabot',
            
            # Social media bots
            'facebookexternalhit': 'Facebook Bot',
            'twitterbot': 'Twitter Bot',
            'linkedinbot': 'LinkedIn Bot',
            'pinterest': 'Pinterest Bot',
            'whatsapp': 'WhatsApp Bot',
            'telegrambot': 'Telegram Bot',
            'slackbot': 'Slack Bot',
            'discordbot': 'Discord Bot',
            
            # SEO/monitoring bots
            'ahrefsbot': 'Ahrefs Bot',
            'semrushbot': 'SEMrush Bot',
            'mj12bot': 'Majestic Bot',
            'dotbot': 'Moz DotBot',
            'rogerbot': 'Moz RogerBot',
            'screaming frog': 'Screaming Frog',
            'serpstatbot': 'SerpstatBot',
            'seokicks': 'SEOkicks',
            
            # Generic patterns
            'bot': 'Generic Bot',
            'crawler': 'Generic Crawler',
            'spider': 'Generic Spider',
            'scraper': 'Generic Scraper',
            'curl': 'cURL',
            'wget': 'Wget',
            'python-requests': 'Python Requests',
            'go-http-client': 'Go HTTP Client',
            'java': 'Java Client',
            'apache-httpclient': 'Apache HttpClient',
            
            # Monitoring/uptime bots
            'uptimerobot': 'UptimeRobot',
            'pingdom': 'Pingdom',
            'statuscake': 'StatusCake',
            'monitor': 'Generic Monitor',
            
            # Archive bots
            'ia_archiver': 'Internet Archive',
            'archive.org_bot': 'Archive.org Bot',
        }
        
    def load_bot_list(self, url="https://raw.githubusercontent.com/monperrus/crawler-user-agents/refs/heads/master/crawler-user-agents.json"):
        """Download and load bot list from GitHub."""
        cache_file = os.path.expanduser('~/.bot_monitor_cache.json')
        
        # Try to load from cache first
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cached_bots = json.load(f)
                    self.bots = cached_bots
                    self.loaded = True
                    return True, f"Loaded from cache ({len(self.bots)} patterns)"
            except:
                pass
        
        # Try to download
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Bot Monitor)')
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())
                
                # Parse the crawler-user-agents.json format
                # This format is an array of objects with "pattern" field
                if isinstance(data, list):
                    for entry in data:
                        pattern = entry.get('pattern', '')
                        if pattern:
                            # Try to extract a friendly name from the pattern
                            bot_name = self._extract_bot_name(pattern)
                            self.bots[pattern.lower()] = bot_name
                
                # Save to cache
                try:
                    with open(cache_file, 'w') as f:
                        json.dump(self.bots, f)
                except:
                    pass
                
                self.loaded = True
                return True, f"Downloaded {len(self.bots)} bot patterns"
        except urllib.error.URLError as e:
            return False, f"Network error: {str(e.reason)}"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def _extract_bot_name(self, pattern):
        """Extract a friendly bot name from a pattern string."""
        # Remove common regex characters and extract the core name
        name = pattern.strip()
        
        # Remove regex anchors and special chars
        name = re.sub(r'[\[\]\(\)\{\}\^\$\.\*\+\?\\\/]', ' ', name)
        
        # Get the first meaningful word (usually the bot name)
        words = [w for w in name.split() if len(w) > 2]
        if words:
            bot_name = words[0]
            # Capitalize properly
            if 'bot' in bot_name.lower():
                return bot_name.capitalize()
            else:
                return bot_name.capitalize() + ' Bot'
        
        return 'Unknown Bot'
    
    def identify_bot(self, user_agent):
        """
        Identify if user agent is a bot and return bot name.
        Returns (is_bot, bot_name)
        """
        if not user_agent:
            return False, None
            
        ua_lower = user_agent.lower()
        
        # Check against known bot patterns from database
        if self.loaded and self.bots:
            for pattern, name in self.bots.items():
                # Try regex match first
                try:
                    if re.search(pattern, ua_lower, re.IGNORECASE):
                        return True, name
                except re.error:
                    # If regex fails, try simple substring match
                    if pattern in ua_lower:
                        return True, name
        
        # Check against fallback patterns
        for pattern, name in self.fallback_bots.items():
            if pattern in ua_lower:
                return True, name
        
        return False, None


class TimeWindowStats:
    """Maintain statistics over rolling time windows."""
    
    def __init__(self):
        self.lock = Lock()
        self.events = deque()  # (timestamp, data) tuples
        self.bot_counts = defaultdict(lambda: defaultdict(int))  # {window: {bot: count}}
        self.bot_ip_counts = defaultdict(lambda: defaultdict(int))  # {window: {ip: count}}
        self.total_requests = defaultdict(int)  # {window: count}
        self.bot_requests = defaultdict(int)  # {window: count}
        self.reference_time = None  # For initial load, use most recent log timestamp
        self.live_mode = False  # Switch to live mode after initial load
        
    def set_live_mode(self):
        """Switch to live monitoring mode (use current time as reference)."""
        self.live_mode = True
        self.reference_time = None
    
    def add_event(self, timestamp, ip, is_bot, bot_name):
        """Add a new event to the statistics."""
        with self.lock:
            self.events.append((timestamp, ip, is_bot, bot_name))
            
            # Track the most recent timestamp for initial load reference
            if not self.live_mode:
                if self.reference_time is None or timestamp > self.reference_time:
                    self.reference_time = timestamp
            
            self._cleanup_old_events()
            self._update_stats()
    
    def _cleanup_old_events(self):
        """Remove events older than 24 hours."""
        reference = self.reference_time if self.reference_time and not self.live_mode else datetime.now()
        cutoff = reference - timedelta(days=1)
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
    
    def _update_stats(self):
        """Recalculate statistics for all time windows."""
        # Use most recent event timestamp for initial load, current time for live mode
        reference = datetime.now() if self.live_mode else (self.reference_time or datetime.now())
        
        windows = {
            'minute': timedelta(minutes=1),
            'hour': timedelta(hours=1),
            'day': timedelta(days=1)
        }
        
        # Reset counters
        for window in windows:
            self.bot_counts[window].clear()
            self.bot_ip_counts[window].clear()
            self.total_requests[window] = 0
            self.bot_requests[window] = 0
        
        # Count events in each window
        for timestamp, ip, is_bot, bot_name in self.events:
            for window_name, window_delta in windows.items():
                if reference - timestamp <= window_delta:
                    self.total_requests[window_name] += 1
                    if is_bot and bot_name:
                        self.bot_requests[window_name] += 1
                        self.bot_counts[window_name][bot_name] += 1
                        self.bot_ip_counts[window_name][ip] += 1
    
    def get_top_bots(self, window, n=10):
        """Get top N bots for a time window."""
        with self.lock:
            counts = self.bot_counts.get(window, {})
            return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_top_bot_ips(self, window, n=10):
        """Get top N bot IPs for a time window."""
        with self.lock:
            counts = self.bot_ip_counts.get(window, {})
            return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_bot_ratio(self, window):
        """Get bot vs non-bot ratio for a time window."""
        with self.lock:
            total = self.total_requests.get(window, 0)
            bots = self.bot_requests.get(window, 0)
            non_bots = total - bots
            return bots, non_bots, total


class LogMonitor:
    """Monitor log file and collect statistics."""
    
    def __init__(self, log_file, tail_lines=None):
        self.log_file = log_file
        self.tail_lines = tail_lines
        self.parser = LogParser()
        self.bot_detector = BotDetector()
        self.stats = TimeWindowStats()
        self.running = False
        self.qps = 0.0
        self.total_lines = 0
        self.initial_lines = 0  # Track lines from initial load
        self.bot_lines = 0
        self.last_qps_update = time.time()
        self.qps_counter = 0
        self.load_progress = 0.0
        self.load_complete = False
        self.bot_tracking = {}  # {bot_name: {'last_seen': datetime, 'count': int}}
        
    def start(self):
        """Start monitoring the log file."""
        self.running = True
        
        # Load bot list (will use fallback if download fails)
        success, message = self.bot_detector.load_bot_list()
        
        # Start monitoring thread
        thread = Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        return success, message
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
    
    def _read_last_n_lines(self, n):
        """Efficiently read the last N lines of a file by reading backwards."""
        buffer = b''
        lines_found = []
        block_size = 8192
        
        with open(self.log_file, 'rb') as f:
            # Go to end of file
            f.seek(0, 2)
            file_size = f.tell()
            
            if file_size == 0:
                return []
            
            # Read backwards until we have enough lines
            position = file_size
            
            while position > 0 and len(lines_found) < n:
                # Determine how much to read
                chunk_size = min(block_size, position)
                position -= chunk_size
                
                # Read chunk
                f.seek(position)
                chunk = f.read(chunk_size)
                
                # Prepend to buffer
                buffer = chunk + buffer
                
                # Try to decode and count lines
                try:
                    decoded = buffer.decode('utf-8', errors='ignore')
                    # Split into lines and filter empty
                    all_lines = [line for line in decoded.split('\n') if line.strip()]
                    
                    # Check if we have enough
                    if len(all_lines) >= n:
                        # Return exactly the last N lines
                        return all_lines[-n:]
                    
                    # Keep reading, store what we have
                    lines_found = all_lines
                    
                except Exception:
                    continue
            
            # Return what we found (might be less than N if file is small)
            return lines_found
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        # First, read existing log file
        if os.path.exists(self.log_file):
            if self.tail_lines:
                # Read only last N lines
                lines = self._read_last_n_lines(self.tail_lines)
                total = len(lines)
                
                for i, line in enumerate(lines):
                    self._process_line(line)
                    self.load_progress = (i + 1) / total * 100
                    if (i + 1) % 100 == 0:
                        time.sleep(0.001)
                
                self.initial_lines = self.total_lines
            else:
                # Read entire file
                file_size = os.path.getsize(self.log_file)
                bytes_read = 0
                
                with open(self.log_file, 'r', errors='ignore') as f:
                    for line in f:
                        self._process_line(line.strip())
                        bytes_read += len(line.encode('utf-8'))
                        self.load_progress = (bytes_read / file_size) * 100
                        if self.total_lines % 1000 == 0:
                            time.sleep(0.001)
                
                self.initial_lines = self.total_lines
        
        self.load_complete = True
        
        # Switch to live mode
        self.stats.set_live_mode()
        
        # Then follow the file for new entries
        with open(self.log_file, 'r', errors='ignore') as f:
            # Seek to end
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if line:
                    self._process_line(line.strip())
                else:
                    time.sleep(0.1)
    
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
        
        self.stats.add_event(timestamp, ip, is_bot, bot_name)
        self.total_lines += 1
        if is_bot:
            self.bot_lines += 1
            # Track bot statistics
            if bot_name:
                if bot_name not in self.bot_tracking:
                    self.bot_tracking[bot_name] = {'last_seen': timestamp, 'count': 0}
                self.bot_tracking[bot_name]['last_seen'] = timestamp
                self.bot_tracking[bot_name]['count'] += 1
        
        # Update QPS
        self.qps_counter += 1
        current_time = time.time()
        if current_time - self.last_qps_update >= 1.0:
            self.qps = self.qps_counter / (current_time - self.last_qps_update)
            self.qps_counter = 0
            self.last_qps_update = current_time


class BotMonitorUI:
    """Curses-based UI for bot monitoring."""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.current_screen = 0
        self.screens = ['Bot Names', 'Bot IPs', 'Bot Ratio', 'Bot Database']
        self.bot_db_scroll = 0  # Scroll position for bot database screen
        self.bot_db_sort = 0  # Sort mode: 0=name, 1=last_seen, 2=count
        
    def run(self, stdscr):
        """Main UI loop."""
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(1)   # Non-blocking input
        stdscr.timeout(1000)  # Refresh every second
        
        # Initialize colors
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)
        
        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            # Draw header
            self._draw_header(stdscr, width)
            
            # Draw current screen
            if self.current_screen == 0:
                self._draw_bot_names_screen(stdscr, height, width)
            elif self.current_screen == 1:
                self._draw_bot_ips_screen(stdscr, height, width)
            elif self.current_screen == 2:
                self._draw_bot_ratio_screen(stdscr, height, width)
            elif self.current_screen == 3:
                self._draw_bot_database_screen(stdscr, height, width)
            
            # Draw footer
            self._draw_footer(stdscr, height, width)
            
            stdscr.refresh()
            
            # Handle input
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                break
            elif key == ord('1'):
                self.current_screen = 0
                self.bot_db_scroll = 0
            elif key == ord('2'):
                self.current_screen = 1
                self.bot_db_scroll = 0
            elif key == ord('3'):
                self.current_screen = 2
                self.bot_db_scroll = 0
            elif key == ord('4'):
                self.current_screen = 3
                self.bot_db_scroll = 0
            elif key == curses.KEY_LEFT:
                self.current_screen = (self.current_screen - 1) % len(self.screens)
                self.bot_db_scroll = 0
            elif key == curses.KEY_RIGHT:
                self.current_screen = (self.current_screen + 1) % len(self.screens)
                self.bot_db_scroll = 0
            elif key == curses.KEY_UP:
                if self.current_screen == 3:  # Bot database screen
                    self.bot_db_scroll = max(0, self.bot_db_scroll - 1)
            elif key == curses.KEY_DOWN:
                if self.current_screen == 3:  # Bot database screen
                    self.bot_db_scroll += 1
            elif key == curses.KEY_PPAGE:  # Page Up
                if self.current_screen == 3:
                    self.bot_db_scroll = max(0, self.bot_db_scroll - 10)
            elif key == curses.KEY_NPAGE:  # Page Down
                if self.current_screen == 3:
                    self.bot_db_scroll += 10
            elif key == ord('s') or key == ord('S'):
                if self.current_screen == 3:  # Bot database screen
                    self.bot_db_sort = (self.bot_db_sort + 1) % 3
                    self.bot_db_scroll = 0  # Reset scroll when sorting changes
    
    def _draw_header(self, stdscr, width):
        """Draw header bar with statistics."""
        # Mode indicator - only show if loading is complete
        if self.monitor.load_complete:
            mode = "LIVE" if self.monitor.stats.live_mode else "HISTORICAL"
            header_text = f" Apache Bot Monitor - {self.screens[self.current_screen]} [{mode}] "
        else:
            header_text = f" Apache Bot Monitor - {self.screens[self.current_screen]} "
        
        stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
        stdscr.addstr(0, 0, header_text.ljust(width))
        stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        
        # Bot detection status
        bot_status = "Full DB" if self.monitor.bot_detector.loaded else "Fallback"
        patterns = len(self.monitor.bot_detector.bots) if self.monitor.bot_detector.loaded else len(self.monitor.bot_detector.fallback_bots)
        
        # Statistics line - show initial vs live if in tail mode
        if self.monitor.tail_lines and self.monitor.load_complete:
            live_lines = self.monitor.total_lines - self.monitor.initial_lines
            stats_text = (
                f"QPS: {self.monitor.qps:.2f} | "
                f"Loaded: {self.monitor.initial_lines:,} | "
                f"Live: +{live_lines:,} | "
                f"Bots: {self.monitor.bot_lines:,} ({(self.monitor.bot_lines/max(1, self.monitor.total_lines)*100):.1f}%) | "
                f"Patterns: {patterns} ({bot_status})"
            )
        else:
            stats_text = (
                f"QPS: {self.monitor.qps:.2f} | "
                f"Total: {self.monitor.total_lines:,} | "
                f"Bots: {self.monitor.bot_lines:,} ({(self.monitor.bot_lines/max(1, self.monitor.total_lines)*100):.1f}%) | "
                f"Patterns: {patterns} ({bot_status})"
            )
        stdscr.addstr(1, 2, stats_text[:width-4])
        stdscr.addstr(2, 0, "─" * width)
    
    def _draw_footer(self, stdscr, height, width):
        """Draw footer with navigation help."""
        if self.current_screen == 3:  # Bot database screen
            sort_names = ["Name", "Last Seen", "Count"]
            footer = f" [S] Sort: {sort_names[self.bot_db_sort]}  [↑↓] Scroll  [1-4] Switch  [Q] Quit "
        elif self.monitor.stats.live_mode:
            footer = " [1] Names  [2] IPs  [3] Ratios  [4] Database  [↑↓] Scroll  [←/→] Navigate  [Q] Quit "
        else:
            footer = " [1-4] Switch Screen  [←/→] Navigate  [Q] Quit "
        try:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(height - 1, 0, footer.center(width)[:width])
            stdscr.attroff(curses.color_pair(5))
        except:
            pass
    
    def _draw_bot_names_screen(self, stdscr, height, width):
        """Draw top bot names screen."""
        row = 4
        
        if self.monitor.stats.live_mode:
            windows = [('minute', 'Past Minute'), ('hour', 'Past Hour'), ('day', 'Past Day')]
        else:
            windows = [('minute', 'Last Minute'), ('hour', 'Last Hour'), ('day', 'Last Day')]
        col_width = width // 3
        
        # Show loading message if still loading
        if not self.monitor.load_complete:
            loading_msg = "Loading log file..."
            progress_msg = f"{int(self.monitor.load_progress)}% complete"
            lines_msg = f"{self.monitor.total_lines:,} lines processed"
            
            stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(height // 2 - 2, (width - len(loading_msg)) // 2, loading_msg)
            stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(height // 2, (width - len(progress_msg)) // 2, progress_msg)
            stdscr.addstr(height // 2 + 1, (width - len(lines_msg)) // 2, lines_msg)
            
            # Draw a progress bar
            bar_width = min(50, width - 20)
            bar_x = (width - bar_width) // 2
            filled = int(bar_width * self.monitor.load_progress / 100)
            stdscr.attron(curses.color_pair(1) | curses.A_REVERSE)
            stdscr.addstr(height // 2 + 3, bar_x, " " * filled)
            stdscr.attroff(curses.color_pair(1) | curses.A_REVERSE)
            stdscr.addstr(height // 2 + 3, bar_x + filled, "░" * (bar_width - filled))
            return
        
        for idx, (window, title) in enumerate(windows):
            col = idx * col_width
            
            # Title
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, col + 2, title)
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
            
            # Table header
            stdscr.addstr(row + 1, col + 2, "─" * (col_width - 4))
            stdscr.addstr(row + 2, col + 2, "Bot Name".ljust(col_width - 12) + "Count")
            stdscr.addstr(row + 3, col + 2, "─" * (col_width - 4))
            
            # Top bots
            top_bots = self.monitor.stats.get_top_bots(window, 10)
            for i, (bot_name, count) in enumerate(top_bots):
                if row + 4 + i < height - 2:
                    name_str = bot_name[:col_width - 15] if len(bot_name) > col_width - 15 else bot_name
                    stdscr.attron(curses.color_pair(1))
                    stdscr.addstr(row + 4 + i, col + 2, f"{i+1:2d}. {name_str.ljust(col_width - 16)}{count:5d}")
                    stdscr.attroff(curses.color_pair(1))
    
    def _draw_bot_ips_screen(self, stdscr, height, width):
        """Draw top bot IPs screen."""
        row = 4
        
        if self.monitor.stats.live_mode:
            windows = [('minute', 'Past Minute'), ('hour', 'Past Hour'), ('day', 'Past Day')]
        else:
            windows = [('minute', 'Last Minute'), ('hour', 'Last Hour'), ('day', 'Last Day')]
        col_width = width // 3
        
        # Show loading message if still loading
        if not self.monitor.load_complete:
            loading_msg = "Loading log file..."
            progress_msg = f"{int(self.monitor.load_progress)}% complete"
            lines_msg = f"{self.monitor.total_lines:,} lines processed"
            
            stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(height // 2 - 2, (width - len(loading_msg)) // 2, loading_msg)
            stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(height // 2, (width - len(progress_msg)) // 2, progress_msg)
            stdscr.addstr(height // 2 + 1, (width - len(lines_msg)) // 2, lines_msg)
            
            # Draw a progress bar
            bar_width = min(50, width - 20)
            bar_x = (width - bar_width) // 2
            filled = int(bar_width * self.monitor.load_progress / 100)
            stdscr.attron(curses.color_pair(1) | curses.A_REVERSE)
            stdscr.addstr(height // 2 + 3, bar_x, " " * filled)
            stdscr.attroff(curses.color_pair(1) | curses.A_REVERSE)
            stdscr.addstr(height // 2 + 3, bar_x + filled, "░" * (bar_width - filled))
            return
        
        for idx, (window, title) in enumerate(windows):
            col = idx * col_width
            
            # Title
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, col + 2, title)
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
            
            # Table header
            stdscr.addstr(row + 1, col + 2, "─" * (col_width - 4))
            stdscr.addstr(row + 2, col + 2, "IP Address".ljust(col_width - 12) + "Count")
            stdscr.addstr(row + 3, col + 2, "─" * (col_width - 4))
            
            # Top IPs
            top_ips = self.monitor.stats.get_top_bot_ips(window, 10)
            for i, (ip, count) in enumerate(top_ips):
                if row + 4 + i < height - 2:
                    stdscr.attron(curses.color_pair(2))
                    stdscr.addstr(row + 4 + i, col + 2, f"{i+1:2d}. {ip.ljust(col_width - 16)}{count:5d}")
                    stdscr.attroff(curses.color_pair(2))
    
    def _draw_bot_ratio_screen(self, stdscr, height, width):
        """Draw bot vs non-bot ratio screen."""
        row = 4
        
        if self.monitor.stats.live_mode:
            windows = [('minute', 'Past Minute'), ('hour', 'Past Hour'), ('day', 'Past Day')]
        else:
            windows = [('minute', 'Last Minute'), ('hour', 'Last Hour'), ('day', 'Last Day')]
        col_width = width // 3
        
        # Show loading message if still loading
        if not self.monitor.load_complete:
            loading_msg = "Loading log file..."
            progress_msg = f"{int(self.monitor.load_progress)}% complete"
            lines_msg = f"{self.monitor.total_lines:,} lines processed"
            bots_msg = f"{self.monitor.bot_lines:,} bots detected"
            
            stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(height // 2 - 3, (width - len(loading_msg)) // 2, loading_msg)
            stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(height // 2 - 1, (width - len(progress_msg)) // 2, progress_msg)
            stdscr.addstr(height // 2, (width - len(lines_msg)) // 2, lines_msg)
            stdscr.addstr(height // 2 + 1, (width - len(bots_msg)) // 2, bots_msg)
            
            # Draw a progress bar
            bar_width = min(50, width - 20)
            bar_x = (width - bar_width) // 2
            filled = int(bar_width * self.monitor.load_progress / 100)
            stdscr.attron(curses.color_pair(1) | curses.A_REVERSE)
            stdscr.addstr(height // 2 + 3, bar_x, " " * filled)
            stdscr.attroff(curses.color_pair(1) | curses.A_REVERSE)
            stdscr.addstr(height // 2 + 3, bar_x + filled, "░" * (bar_width - filled))
            return
        
        for idx, (window, title) in enumerate(windows):
            col = idx * col_width
            
            # Title
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, col + 2, title)
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
            
            bots, non_bots, total = self.monitor.stats.get_bot_ratio(window)
            
            # Stats
            stdscr.addstr(row + 2, col + 2, f"Total: {total}")
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(row + 3, col + 2, f"Bots: {bots}")
            stdscr.attroff(curses.color_pair(3))
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(row + 4, col + 2, f"Non-Bots: {non_bots}")
            stdscr.attroff(curses.color_pair(1))
            
            if total > 0:
                bot_pct = (bots / total) * 100
                stdscr.addstr(row + 5, col + 2, f"Bot %: {bot_pct:.1f}%")
                
                # Draw simple bar chart
                bar_width = col_width - 6
                bot_bar_len = int((bots / total) * bar_width)
                non_bot_bar_len = bar_width - bot_bar_len
                
                stdscr.addstr(row + 7, col + 2, "Distribution:")
                stdscr.attron(curses.color_pair(3) | curses.A_REVERSE)
                stdscr.addstr(row + 8, col + 2, " " * bot_bar_len)
                stdscr.attroff(curses.color_pair(3) | curses.A_REVERSE)
                stdscr.attron(curses.color_pair(1) | curses.A_REVERSE)
                stdscr.addstr(row + 8, col + 2 + bot_bar_len, " " * non_bot_bar_len)
                stdscr.attroff(curses.color_pair(1) | curses.A_REVERSE)
                
                # Legend
                stdscr.attron(curses.color_pair(3))
                stdscr.addstr(row + 10, col + 2, "■ Bots")
                stdscr.attroff(curses.color_pair(3))
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(row + 11, col + 2, "■ Non-Bots")
                stdscr.attroff(curses.color_pair(1))
    
    def _draw_bot_database_screen(self, stdscr, height, width):
        """Draw bot database browser screen."""
        row = 4
        
        # Show loading message if still loading
        if not self.monitor.load_complete:
            loading_msg = "Loading log file..."
            progress_msg = f"{int(self.monitor.load_progress)}% complete"
            lines_msg = f"{self.monitor.total_lines:,} lines processed"
            
            stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(height // 2 - 2, (width - len(loading_msg)) // 2, loading_msg)
            stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(height // 2, (width - len(progress_msg)) // 2, progress_msg)
            stdscr.addstr(height // 2 + 1, (width - len(lines_msg)) // 2, lines_msg)
            
            # Draw a progress bar
            bar_width = min(50, width - 20)
            bar_x = (width - bar_width) // 2
            filled = int(bar_width * self.monitor.load_progress / 100)
            stdscr.attron(curses.color_pair(1) | curses.A_REVERSE)
            stdscr.addstr(height // 2 + 3, bar_x, " " * filled)
            stdscr.attroff(curses.color_pair(1) | curses.A_REVERSE)
            stdscr.addstr(height // 2 + 3, bar_x + filled, "░" * (bar_width - filled))
            return
        
        # Get detected bots with their stats
        detected_bots = []
        for bot_name, stats in self.monitor.bot_tracking.items():
            detected_bots.append({
                'name': bot_name,
                'last_seen': stats['last_seen'],
                'count': stats['count']
            })
        
        # Sort according to current sort mode
        sort_names = ["Name (A-Z)", "Last Seen (Recent)", "Count (High-Low)"]
        if self.bot_db_sort == 0:  # Name
            detected_bots.sort(key=lambda x: x['name'])
        elif self.bot_db_sort == 1:  # Last seen
            detected_bots.sort(key=lambda x: x['last_seen'], reverse=True)
        elif self.bot_db_sort == 2:  # Count
            detected_bots.sort(key=lambda x: x['count'], reverse=True)
        
        # Header
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        header = f"Detected Bots - Sorted by {sort_names[self.bot_db_sort]} ({len(detected_bots)} unique bots)"
        stdscr.addstr(row, 2, header[:width-4])
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        stdscr.addstr(row + 1, 2, "─" * (width - 4))
        
        # Column headers
        stdscr.attron(curses.A_BOLD)
        col_header = "#".ljust(6) + "Bot Name".ljust(35) + "Count".ljust(10) + "Last Seen"
        stdscr.addstr(row + 2, 2, col_header[:width-4])
        stdscr.attroff(curses.A_BOLD)
        stdscr.addstr(row + 3, 2, "─" * (width - 4))
        
        # Calculate how many lines we can show
        max_lines = height - row - 6
        
        if len(detected_bots) == 0:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(height // 2, (width - 40) // 2, "No bots detected yet. Waiting for traffic...")
            stdscr.attroff(curses.color_pair(2))
            return
        
        # Clamp scroll position
        max_scroll = max(0, len(detected_bots) - max_lines)
        self.bot_db_scroll = max(0, min(self.bot_db_scroll, max_scroll))
        
        # Display bots starting from scroll position
        for i in range(max_lines):
            idx = self.bot_db_scroll + i
            if idx >= len(detected_bots):
                break
            
            bot = detected_bots[idx]
            bot_name = bot['name']
            count = bot['count']
            last_seen = bot['last_seen']
            
            # Format timestamp
            if self.monitor.stats.live_mode:
                # Show relative time for live mode
                time_diff = datetime.now() - last_seen
                if time_diff.total_seconds() < 60:
                    time_str = f"{int(time_diff.total_seconds())}s ago"
                elif time_diff.total_seconds() < 3600:
                    time_str = f"{int(time_diff.total_seconds() / 60)}m ago"
                elif time_diff.total_seconds() < 86400:
                    time_str = f"{int(time_diff.total_seconds() / 3600)}h ago"
                else:
                    time_str = f"{int(time_diff.total_seconds() / 86400)}d ago"
            else:
                # Show actual timestamp for historical mode
                time_str = last_seen.strftime("%Y-%m-%d %H:%M:%S")
            
            # Truncate long names
            display_name = bot_name[:33] if len(bot_name) > 33 else bot_name
            
            # Alternate colors for readability
            if idx % 2 == 0:
                stdscr.attron(curses.color_pair(1))
            else:
                stdscr.attron(curses.color_pair(2))
            
            line = f"{idx + 1:5d}. {display_name.ljust(35)}{count:<10,}{time_str}"
            stdscr.addstr(row + 4 + i, 2, line[:width - 4])
            
            if idx % 2 == 0:
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.attroff(curses.color_pair(2))
        
        # Scroll indicator
        if len(detected_bots) > max_lines:
            scroll_info = f"Showing {self.bot_db_scroll + 1}-{min(self.bot_db_scroll + max_lines, len(detected_bots))} of {len(detected_bots)}"
            stdscr.addstr(height - 2, 2, scroll_info)
            
            # Navigation hint
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(height - 2, width - 40, "↑↓ Scroll  PgUp/PgDn Page  [S] Sort")
            stdscr.attroff(curses.color_pair(4))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Apache Combined Log Bot Monitor - Real-time bot traffic analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /var/log/apache2/access.log
  %(prog)s /var/log/apache2/access.log --tail 10000
  %(prog)s access.log -n 50000
        """
    )
    parser.add_argument('log_file', help='Path to Apache access log file')
    parser.add_argument('-n', '--tail', type=int, metavar='LINES',
                        help='Only load the last N lines (useful for large files)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.log_file):
        print(f"Error: Log file '{args.log_file}' not found.")
        sys.exit(1)
    
    # Get file size info
    file_size = os.path.getsize(args.log_file)
    file_size_mb = file_size / (1024 * 1024)
    
    print("=" * 70)
    print("Apache Bot Monitor")
    print("=" * 70)
    print(f"Log file: {args.log_file}")
    print(f"File size: {file_size_mb:.2f} MB")
    
    if args.tail:
        print(f"Mode: Tail mode - LAST {args.tail:,} LINES ONLY")
    else:
        print(f"Mode: Full file mode - ALL LINES")
    
    print("\nLoading bot database from monperrus/crawler-user-agents...")
    
    monitor = LogMonitor(args.log_file, tail_lines=args.tail)
    success, message = monitor.start()
    
    if success:
        print(f"✓ {message}")
    else:
        print(f"⚠ Warning: {message}")
        print(f"✓ Using built-in fallback bot patterns ({len(monitor.bot_detector.fallback_bots)} patterns)")
        print("\nNote: For better bot detection, ensure internet connectivity.")
        print("The bot database will be cached at ~/.bot_monitor_cache.json")
    
    print("\n" + "─" * 70)
    print("Processing log file...")
    print()
    
    # Give the monitor a moment to start
    time.sleep(0.5)
    
    print("─" * 70)
    print("Starting interactive monitor...")
    print("Loading will continue in the background.")
    print()
    
    # Start UI immediately - it will show loading progress
    ui = BotMonitorUI(monitor)
    
    try:
        curses.wrapper(ui.run)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        
        # Show final statistics
        print("\n" + "=" * 70)
        print("Monitor stopped.")
        print("=" * 70)
        if args.tail:
            live_lines = monitor.total_lines - monitor.initial_lines
            print(f"Initial load: {monitor.initial_lines:,} lines (last {args.tail:,} from file)")
            print(f"Live monitoring: +{live_lines:,} new lines")
            print(f"Total processed: {monitor.total_lines:,} lines")
        else:
            print(f"Total requests processed: {monitor.total_lines:,}")
        print(f"Bot requests detected: {monitor.bot_lines:,} ({(monitor.bot_lines/max(1, monitor.total_lines)*100):.1f}%)")
        print("=" * 70)


if __name__ == "__main__":
    main()
