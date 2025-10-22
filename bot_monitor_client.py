#!/usr/bin/env python3
"""
Apache Bot Monitor Client
Connects to the daemon and displays a curses-based dashboard.
"""

import curses
import socket
import json
import time
import sys
import os
import psutil
import ipaddress
from collections import defaultdict
from datetime import datetime
from configparser import ConfigParser


class DaemonClient:
    """Client to connect to daemon."""
    
    def __init__(self, socket_path):
        self.socket_path = socket_path
    
    def _send_request(self, command):
        """Send a request and get response."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(self.socket_path)
            sock.sendall((command + '\n').encode('utf-8'))
            
            # Read response
            data = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\n' in chunk:  # Complete response received
                    break
            
            sock.close()
            
            if data:
                return json.loads(data.decode('utf-8'))
            return None
        except socket.timeout:
            return None
        except Exception as e:
            return None
    
    def connect(self):
        """Test connection to daemon."""
        try:
            result = self._send_request('GET_STATS')
            return result is not None
        except Exception as e:
            print(f"Failed to connect to daemon: {e}")
            print(f"Is the daemon running? Socket: {self.socket_path}")
            return False
    
    def get_stats(self):
        """Get statistics from daemon."""
        return self._send_request('GET_STATS')
    
    def get_bot_details(self, bot_name):
        """Get detailed information about a bot."""
        result = self._send_request(f'GET_BOT_DETAILS:{bot_name}')
        if result:
            return result.get('details', {})
        return {}
    
    def get_alert_config(self):
        """Get current alert configuration."""
        result = self._send_request('GET_ALERT_CONFIG')
        if result:
            return result.get('config', {})
        return {}
    
    def update_alert_config(self, config):
        """Update alert configuration."""
        config_json = json.dumps(config)
        result = self._send_request(f'UPDATE_ALERT_CONFIG:{config_json}')
        return result
    
    def lookup_ip(self, ip_address):
        """Lookup detailed IP information."""
        result = self._send_request(f'LOOKUP_IP:{ip_address}')
        if result:
            return result.get('ip_info', {})
        return {}
    
    def send_test_email(self):
        """Send a test email."""
        return self._send_request('SEND_TEST_EMAIL')
    
    def close(self):
        """Close connection (no-op now since we connect per request)."""
        pass


def normalize_ip(ip_str):
    """Normalize IP to /24 for IPv4 or /48 for IPv6."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            # Get /24 network
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network)
        else:  # IPv6
            # Get /48 network
            network = ipaddress.ip_network(f"{ip}/48", strict=False)
            return str(network)
    except:
        return ip_str


class BotMonitorUI:
    """Curses-based UI."""
    
    def __init__(self, client):
        self.client = client
        self.current_screen = 0
        self.screens = ['Bot Names', 'Bot IPs', 'Bot Ratios', 'Detected Bots', 'Bot Attacks', 'Alert Settings']
        self.scroll = 0
        self.sort_mode = 0  # For detected bots: 0=name, 1=last_seen, 2=count
        self.attack_sort = 0  # For attacks: 0=time, 1=qps, 2=duration
        self.stats = None
        self.last_update = 0
        self.paused = False
        self.showing_details = False
        self.selected_bot = None
        self.selected_ip = None
        self.bot_list = []  # For navigation
        self.ip_list = []  # For IP navigation
        self.selected_index = 0
        self.alert_config = None
        self.editing_field = None  # For alert settings editing
        self.edit_buffer = ""
        self.process = psutil.Process()  # For monitoring client memory/CPU
        self.test_email_result = None  # Store test email result
        self.test_email_time = 0  # When test email was sent
        self.test_email_sending = False  # Flag for showing "sending" message
        self.ip_lookup_loading = False  # Flag for IP lookup in progress
        self.ip_info_cache = {}  # Cache for IP lookup results
    
    def run(self, stdscr):
        """Main UI loop."""
        curses.curs_set(0)
        stdscr.nodelay(1)
        stdscr.timeout(1000)  # Refresh every 1 second (was 100ms)
        
        # Initialize colors
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Header/title bar
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Overlay background (dark blue)
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)  # Popup window (black)
        
        while True:
            # Update stats periodically (every 1 second) - but not when paused
            current_time = time.time()
            if not self.paused and current_time - self.last_update >= 1.0:
                new_stats = self.client.get_stats()
                if new_stats:
                    self.stats = new_stats
                self.last_update = current_time
            
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            if self.showing_details and self.selected_bot:
                self._draw_bot_details(stdscr, height, width)
            elif self.selected_ip:
                self._draw_ip_details(stdscr, height, width)
            else:
                # Draw header
                self._draw_header(stdscr, width)
                
                # Draw current screen
                if self.current_screen == 0:
                    self._draw_bot_names_screen(stdscr, height, width)
                elif self.current_screen == 1:
                    self._draw_bot_ips_screen(stdscr, height, width)
                elif self.current_screen == 2:
                    self._draw_bot_ratios_screen(stdscr, height, width)
                elif self.current_screen == 3:
                    self._draw_detected_bots_screen(stdscr, height, width)
                elif self.current_screen == 4:
                    self._draw_bot_attacks_screen(stdscr, height, width)
                elif self.current_screen == 5:
                    self._draw_alert_settings_screen(stdscr, height, width)
                
                # Draw footer
                self._draw_footer(stdscr, height, width)
            
            stdscr.refresh()
            
            # Handle input
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                if self.showing_details or self.selected_ip:
                    self.showing_details = False
                    self.selected_ip = None
                    self.paused = False  # Resume updates
                else:
                    break
            elif key == 27:  # ESC
                self.showing_details = False
                self.selected_ip = None
                self.paused = False  # Resume updates
            elif key == ord('\n') or key == curses.KEY_ENTER or key == 10:  # Enter
                if self.current_screen == 3 and not self.showing_details:  # Detected Bots screen
                    if self.bot_list and 0 <= self.selected_index < len(self.bot_list):
                        self.selected_bot = self.bot_list[self.selected_index]['name']
                        self.showing_details = True
                        self.paused = True  # Pause updates
                elif self.current_screen == 1:  # Bot IPs screen
                    if self.ip_list and 0 <= self.selected_index < len(self.ip_list):
                        self.selected_ip = self.ip_list[self.selected_index]
                        self.paused = True  # Pause updates
            elif key == ord('1'):
                self.current_screen = 0
                self.scroll = 0
            elif key == ord('2'):
                self.current_screen = 1
                self.scroll = 0
            elif key == ord('3'):
                self.current_screen = 2
                self.scroll = 0
            elif key == ord('4'):
                self.current_screen = 3
                self.scroll = 0
                self.selected_index = 0
            elif key == ord('5'):
                self.current_screen = 4
                self.scroll = 0
            elif key == ord('6'):
                self.current_screen = 5
                self.scroll = 0
                if not self.alert_config:
                    self.alert_config = self.client.get_alert_config()
            elif key == curses.KEY_LEFT:
                self.current_screen = (self.current_screen - 1) % len(self.screens)
                self.scroll = 0
                self.selected_index = 0
            elif key == curses.KEY_RIGHT:
                self.current_screen = (self.current_screen + 1) % len(self.screens)
                self.scroll = 0
                self.selected_index = 0
            elif key == curses.KEY_UP:
                if self.current_screen == 3:  # Detected bots
                    self.selected_index = max(0, self.selected_index - 1)
                    if self.selected_index < self.scroll:
                        self.scroll = self.selected_index
                elif self.current_screen == 1:  # Bot IPs
                    self.selected_index = max(0, self.selected_index - 1)
                elif self.current_screen == 4:  # Attacks
                    self.scroll = max(0, self.scroll - 1)
                elif self.current_screen == 5:  # Alert Settings
                    self.scroll = max(0, self.scroll - 1)
            elif key == curses.KEY_DOWN:
                if self.current_screen == 3:  # Detected bots
                    self.selected_index = min(len(self.bot_list) - 1, self.selected_index + 1)
                elif self.current_screen == 1:  # Bot IPs
                    self.selected_index = min(len(self.ip_list) - 1, self.selected_index + 1)
                elif self.current_screen == 4:  # Attacks
                    self.scroll += 1
                elif self.current_screen == 5:  # Alert Settings
                    self.scroll += 1
            elif key == curses.KEY_PPAGE:
                if self.current_screen in [3, 4]:
                    if self.current_screen == 3:
                        self.selected_index = max(0, self.selected_index - 10)
                        if self.selected_index < self.scroll:
                            self.scroll = self.selected_index
                    else:
                        self.scroll = max(0, self.scroll - 10)
            elif key == curses.KEY_NPAGE:
                if self.current_screen in [3, 4]:
                    if self.current_screen == 3:
                        self.selected_index = min(len(self.bot_list) - 1, self.selected_index + 10)
                    else:
                        self.scroll += 10
            elif key == ord('s') or key == ord('S'):
                if self.current_screen == 3:
                    self.sort_mode = (self.sort_mode + 1) % 3
                    self.scroll = 0
                    self.selected_index = 0
                elif self.current_screen == 4:
                    self.attack_sort = (self.attack_sort + 1) % 3
                    self.scroll = 0
            elif key == ord('t') or key == ord('T'):
                if self.current_screen == 5:  # Alert Settings screen
                    # Set sending flag and send test email
                    self.test_email_sending = True
                    stdscr.refresh()  # Force immediate display update
                    self.test_email_result = self.client.send_test_email()
                    self.test_email_time = time.time()
                    self.test_email_sending = False
    
    def _draw_header(self, stdscr, width):
        """Draw header bar."""
        if not self.stats:
            header_text = f" Apache Bot Monitor - {self.screens[self.current_screen]} [CONNECTING...] "
        else:
            # Check if loading fields exist, if not assume we're still loading
            if 'loading_complete' not in self.stats:
                status = "LOADING..."
            else:
                loading_complete = self.stats.get('loading_complete', False)
                loading_progress = self.stats.get('loading_progress', 0)
                if not loading_complete:
                    status = f"LOADING {loading_progress}%"
                else:
                    status = "LIVE"
            header_text = f" Apache Bot Monitor - {self.screens[self.current_screen]} [{status}] "
        
        stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
        stdscr.addstr(0, 0, header_text.ljust(width))
        stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        
        if self.stats:
            stats = self.stats['stats']
            qps = stats.get('qps', 0)
            total = stats.get('total_requests', 0)
            bots = stats.get('bot_requests', 0)
            bot_pct = (bots / max(1, total)) * 100
            bot_db_count = self.stats.get('bot_db_count', 0)
            
            # System stats
            system_stats = self.stats.get('system_stats', {})
            daemon_mem = system_stats.get('memory_mb', 0)
            daemon_cpu = system_stats.get('cpu_percent', 0)
            
            try:
                client_mem = self.process.memory_info().rss / 1024 / 1024
                client_cpu = self.process.cpu_percent()
            except:
                client_mem = 0
                client_cpu = 0
            
            # Build stats line with color coding
            col = 2
            
            # QPS
            stdscr.attron(curses.color_pair(4) | curses.A_DIM)
            stdscr.addstr(1, col, "QPS:")
            stdscr.attroff(curses.color_pair(4) | curses.A_DIM)
            col += 5
            stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(1, col, f"{qps:.2f}")
            stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            col += 8
            
            # Total
            stdscr.attron(curses.color_pair(4) | curses.A_DIM)
            stdscr.addstr(1, col, "Total:")
            stdscr.attroff(curses.color_pair(4) | curses.A_DIM)
            col += 7
            stdscr.addstr(1, col, f"{total:,}")
            col += len(f"{total:,}") + 3
            
            # Bots
            stdscr.attron(curses.color_pair(4) | curses.A_DIM)
            stdscr.addstr(1, col, "Bots:")
            stdscr.attroff(curses.color_pair(4) | curses.A_DIM)
            col += 6
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(1, col, f"{bots:,} ({bot_pct:.1f}%)")
            stdscr.attroff(curses.color_pair(3))
            col += len(f"{bots:,} ({bot_pct:.1f}%)") + 3
            
            # Bot DB
            stdscr.attron(curses.color_pair(4) | curses.A_DIM)
            stdscr.addstr(1, col, "Bot DB:")
            stdscr.attroff(curses.color_pair(4) | curses.A_DIM)
            col += 8
            stdscr.addstr(1, col, f"{bot_db_count:,}")
            col += len(f"{bot_db_count:,}") + 3
            
            # Memory/CPU (Daemon)
            stdscr.attron(curses.color_pair(4) | curses.A_DIM)
            stdscr.addstr(1, col, "D:")
            stdscr.attroff(curses.color_pair(4) | curses.A_DIM)
            col += 3
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(1, col, f"{daemon_mem:.0f}MB/{daemon_cpu:.1f}%")
            stdscr.attroff(curses.color_pair(2))
            col += len(f"{daemon_mem:.0f}MB/{daemon_cpu:.1f}%") + 3
            
            # Memory/CPU (Client)
            stdscr.attron(curses.color_pair(4) | curses.A_DIM)
            stdscr.addstr(1, col, "C:")
            stdscr.attroff(curses.color_pair(4) | curses.A_DIM)
            col += 3
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(1, col, f"{client_mem:.0f}MB/{client_cpu:.1f}%")
            stdscr.attroff(curses.color_pair(2))
        
        stdscr.addstr(2, 0, "─" * width)
    
    def _draw_footer(self, stdscr, height, width):
        """Draw footer with help."""
        if self.current_screen == 1:
            footer = " [↑↓] Select IP  [Enter] Details  [1-6] Switch  [Q] Quit "
        elif self.current_screen == 3:
            sort_names = ["Name", "Last Seen", "Count"]
            footer = f" [S] Sort: {sort_names[self.sort_mode]}  [↑↓] Select  [Enter] Details  [1-6] Switch  [Q] Quit "
        elif self.current_screen == 4:
            sort_names = ["Time", "QPS", "Duration"]
            footer = f" [S] Sort: {sort_names[self.attack_sort]}  [↑↓] Scroll  [1-6] Switch  [Q] Quit "
        elif self.current_screen == 5:
            footer = " [T] Send Test Email  [↑↓] Scroll  [1-6] Switch  [Q] Quit "
        else:
            footer = " [1] Names  [2] IPs  [3] Ratios  [4] Bots  [5] Attacks  [6] Alerts  [←/→] Nav  [Q] Quit "
        
        try:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(height - 1, 0, footer.center(width)[:width])
            stdscr.attroff(curses.color_pair(5))
        except:
            pass
    
    def _draw_bot_names_screen(self, stdscr, height, width):
        """Draw top bot names screen."""
        if not self.stats:
            return
        
        row = 4
        windows = [('minute', 'Past Minute'), ('hour', 'Past Hour'), ('day', 'Past Day')]
        col_width = width // 3
        
        bot_counts = self.stats['stats']['bot_counts']
        loading_complete = self.stats.get('loading_complete', True)
        
        for idx, (window, title) in enumerate(windows):
            col = idx * col_width
            
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, col + 2, title)
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
            
            stdscr.addstr(row + 1, col + 2, "─" * (col_width - 4))
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(row + 2, col + 2, "Bot Name".ljust(col_width - 12) + "Count")
            stdscr.attroff(curses.color_pair(4))
            stdscr.addstr(row + 3, col + 2, "─" * (col_width - 4))
            
            top_bots = sorted(bot_counts.get(window, {}).items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Show "Still loading..." if not complete and no data yet
            if not loading_complete and len(top_bots) == 0:
                stdscr.attron(curses.color_pair(2) | curses.A_DIM)
                stdscr.addstr(row + 5, col + 4, "Still loading...")
                stdscr.attroff(curses.color_pair(2) | curses.A_DIM)
            else:
                for i, (bot_name, count) in enumerate(top_bots):
                    if row + 4 + i < height - 2:
                        name_str = bot_name[:col_width - 15] if len(bot_name) > col_width - 15 else bot_name
                        stdscr.attron(curses.color_pair(1))
                        stdscr.addstr(row + 4 + i, col + 2, f"{i+1:2d}. {name_str.ljust(col_width - 16)}{count:5d}")
                        stdscr.attroff(curses.color_pair(1))
    
    def _draw_alert_settings_screen(self, stdscr, height, width):
        """Draw alert settings screen."""
        if not self.alert_config:
            self.alert_config = self.client.get_alert_config()
        
        if not self.alert_config:
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(height // 2, (width - 40) // 2, "Failed to load alert configuration")
            stdscr.attroff(curses.color_pair(3))
            return
        
        # Get email sent count from stats
        email_sent_count = 0
        if self.stats:
            email_sent_count = self.stats.get('email_sent_count', 0)
        
        # Build all content lines first
        content_lines = []
        
        # Header
        content_lines.append(("Alert Settings & Configuration", curses.color_pair(4) | curses.A_BOLD))
        content_lines.append(("─" * min(width - 4, 70), 0))
        content_lines.append(("", 0))
        
        # Attack Detection Settings
        content_lines.append(("Attack Detection:", curses.color_pair(4) | curses.A_BOLD))
        
        enabled = self.alert_config.get('enabled', False)
        status_color = curses.color_pair(1) if enabled else curses.color_pair(3)
        status_text = "ENABLED" if enabled else "DISABLED"
        content_lines.append((f"  Status: {status_text}", status_color | curses.A_BOLD))
        
        content_lines.append((f"  QPS Threshold: {self.alert_config.get('qps_threshold', 0)} requests/sec", 0))
        content_lines.append((f"  Time Window: {self.alert_config.get('time_window', 0)} seconds", 0))
        content_lines.append((f"  Minimum Duration: {self.alert_config.get('min_duration', 0)} seconds", 0))
        content_lines.append((f"  Cooldown Period: {self.alert_config.get('cooldown', 0)} seconds", 0))
        content_lines.append(("", 0))
        
        # Email Alerting Settings
        content_lines.append(("Email Alerting:", curses.color_pair(4) | curses.A_BOLD))
        
        email_enabled = self.alert_config.get('email_enabled', False)
        email_status_color = curses.color_pair(1) if email_enabled else curses.color_pair(3)
        email_status_text = "ENABLED" if email_enabled else "DISABLED"
        content_lines.append((f"  Status: {email_status_text}", email_status_color | curses.A_BOLD))
        
        content_lines.append((f"  SMTP Host: {self.alert_config.get('smtp_host', 'N/A')}", 0))
        content_lines.append((f"  SMTP Port: {self.alert_config.get('smtp_port', 0)}", 0))
        content_lines.append((f"  From Address: {self.alert_config.get('from_address', 'N/A')}", 0))
        
        to_addresses = self.alert_config.get('to_addresses', 'N/A')
        if len(to_addresses) > width - 20:
            to_addresses = to_addresses[:width-23] + "..."
        content_lines.append((f"  To Addresses: {to_addresses}", 0))
        content_lines.append(("", 0))
        
        # Email Statistics
        content_lines.append(("Email Statistics:", curses.color_pair(4) | curses.A_BOLD))
        content_lines.append((f"  Alert Emails Sent: {email_sent_count}", curses.color_pair(2)))
        content_lines.append(("", 0))
        
        # Test Email Section
        content_lines.append(("Test Email:", curses.color_pair(4) | curses.A_BOLD))
        content_lines.append(("  Press [T] to send a test email", 0))
        
        # Show sending status
        if self.test_email_sending:
            content_lines.append(("  ⏳ Sending test email...", curses.color_pair(2) | curses.A_BOLD))
        # Show test email result if recent (last 5 seconds)
        elif self.test_email_result and time.time() - self.test_email_time < 5:
            status = self.test_email_result.get('status', 'unknown')
            message = self.test_email_result.get('message', 'Unknown error')
            
            if status == 'ok':
                content_lines.append((f"  ✓ {message}", curses.color_pair(1) | curses.A_BOLD))
            else:
                content_lines.append((f"  ✗ {message}", curses.color_pair(3) | curses.A_BOLD))
        content_lines.append(("", 0))
        
        # How it works
        content_lines.append(("How Attack Detection Works:", curses.color_pair(2) | curses.A_BOLD))
        content_lines.append((f"  • Monitors bot request rates over a {self.alert_config.get('time_window', 60)}s window", 0))
        content_lines.append((f"  • Triggers alert when QPS exceeds {self.alert_config.get('qps_threshold', 10)}", 0))
        content_lines.append((f"  • Only records attacks lasting {self.alert_config.get('min_duration', 30)}s or longer", 0))
        content_lines.append((f"  • Waits {self.alert_config.get('cooldown', 300)}s before alerting again for same bot", 0))
        content_lines.append(("  • Email alerts sent immediately when attack detected (if enabled)", 0))
        content_lines.append(("", 0))
        
        # Note
        content_lines.append(("Note: To permanently change settings, edit /etc/bot_monitor.conf", curses.color_pair(2) | curses.A_DIM))
        content_lines.append(("and restart the daemon: sudo systemctl restart bot_monitor", curses.color_pair(2) | curses.A_DIM))
        
        # Calculate display area
        start_row = 4
        max_display_lines = height - start_row - 2  # Leave room for footer
        total_lines = len(content_lines)
        
        # Adjust scroll bounds
        max_scroll = max(0, total_lines - max_display_lines)
        self.scroll = max(0, min(self.scroll, max_scroll))
        
        # Draw content with scrolling
        for i in range(max_display_lines):
            line_idx = self.scroll + i
            if line_idx >= total_lines:
                break
            
            text, attr = content_lines[line_idx]
            row = start_row + i
            
            try:
                if attr == 0:
                    stdscr.addstr(row, 2, text[:width-4])
                elif isinstance(attr, int) and attr > 100:  # Has color pair
                    stdscr.attron(attr)
                    stdscr.addstr(row, 2, text[:width-4])
                    stdscr.attroff(attr)
                else:
                    stdscr.attron(attr)
                    stdscr.addstr(row, 2, text[:width-4])
                    stdscr.attroff(attr)
            except:
                pass
        
        # Draw scroll indicator if needed
        if max_scroll > 0:
            try:
                indicator_row = height - 2
                if self.scroll < max_scroll:
                    stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
                    stdscr.addstr(indicator_row, width - 10, "▼ More")
                    stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
                if self.scroll > 0:
                    stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
                    stdscr.addstr(indicator_row, 2, "▲ More")
                    stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            except:
                pass
    
    
    def _draw_ip_details(self, stdscr, height, width):
        """Draw IP details popup."""
        ip_network = self.selected_ip[0] if isinstance(self.selected_ip, tuple) else self.selected_ip
        
        # Get first IP from network for lookup
        try:
            network = ipaddress.ip_network(ip_network)
            lookup_ip = str(network.network_address)
        except:
            lookup_ip = ip_network
        
        # Check cache first, otherwise fetch (and show loading)
        if ip_network in self.ip_info_cache:
            ip_info = self.ip_info_cache[ip_network]
        else:
            # Show loading popup first
            self._draw_loading_popup(stdscr, height, width, "Loading IP Information...", ip_network)
            stdscr.refresh()
            
            # Fetch IP info
            ip_info = self.client.lookup_ip(lookup_ip)
            
            # Cache the result
            self.ip_info_cache[ip_network] = ip_info
        
        # Draw semi-transparent background
        try:
            for y in range(height):
                try:
                    stdscr.addstr(y, 0, " " * (width - 1), curses.color_pair(6))
                except:
                    pass
        except:
            pass
        
        # Calculate popup size
        popup_width = min(width - 4, 90)
        popup_height = min(height - 4, 20)
        popup_x = (width - popup_width) // 2
        popup_y = (height - popup_height) // 2
        
        # Ensure popup fits
        if popup_width < 20 or popup_height < 10:
            return
        
        # Draw popup
        try:
            for y in range(popup_height):
                if popup_y + y < height:
                    stdscr.addstr(popup_y + y, popup_x, " " * (popup_width - 1), curses.color_pair(7))
        except:
            pass
        
        # Title
        try:
            stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
            title = f" IP Details: {ip_network} "
            if popup_y < height:
                stdscr.addstr(popup_y, popup_x + (popup_width - len(title)) // 2, title[:popup_width-2])
            stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        except:
            pass
        
        row = popup_y + 2
        
        # Display information
        info_lines = []
        info_lines.append(("IP Network Information:", curses.A_BOLD))
        info_lines.append((f"  Network: {ip_network}", 0))
        
        if ip_info and len(ip_info) > 0:
            if 'hostname' in ip_info and ip_info['hostname']:
                info_lines.append((f"  Hostname: {ip_info['hostname']}", 0))
            
            if 'asn' in ip_info and ip_info['asn']:
                info_lines.append(("", 0))
                info_lines.append(("ASN Information:", curses.A_BOLD))
                info_lines.append((f"  ASN: {ip_info.get('asn', 'N/A')}", 0))
                if 'asn_name' in ip_info and ip_info['asn_name']:
                    info_lines.append((f"  ASN Name: {ip_info['asn_name']}", 0))
                if 'bgp_prefix' in ip_info and ip_info['bgp_prefix']:
                    info_lines.append((f"  BGP Prefix: {ip_info['bgp_prefix']}", 0))
                if 'country' in ip_info and ip_info['country']:
                    info_lines.append((f"  Country: {ip_info['country']}", 0))
                if 'registry' in ip_info and ip_info['registry']:
                    info_lines.append((f"  Registry: {ip_info['registry']}", 0))
            
            if 'spamhaus' in ip_info and ip_info['spamhaus']:
                info_lines.append(("", 0))
                info_lines.append(("Reputation Check (Spamhaus):", curses.A_BOLD))
                spamhaus_status = ip_info['spamhaus']
                
                # Check if any IPs are listed in the /24
                if 'spamhaus_listed_count' in ip_info:
                    listed_count = ip_info.get('spamhaus_listed_count', 0)
                    if listed_count > 0:
                        # Show warning with count
                        info_lines.append((f"  Status: {listed_count} IP(s) in /24 LISTED ⚠", curses.A_BOLD | curses.color_pair(3)))
                        
                        # Show the listed IPs if available
                        if 'spamhaus_listed_ips' in ip_info:
                            listed_ips = ip_info['spamhaus_listed_ips']
                            display_ips = listed_ips[:10]  # Show first 10
                            for ip in display_ips:
                                info_lines.append((f"    • {ip}", curses.color_pair(3)))
                            if len(listed_ips) > 10:
                                info_lines.append((f"    ... and {len(listed_ips) - 10} more", curses.A_DIM))
                    else:
                        info_lines.append((f"  Status: NOT LISTED", 0))
                else:
                    # Old format or IPv6
                    if 'LISTED' in spamhaus_status:
                        info_lines.append((f"  Status: {spamhaus_status} ⚠", curses.A_BOLD | curses.color_pair(3)))
                    else:
                        info_lines.append((f"  Status: {spamhaus_status}", 0))
            
            # If ip_info dict is empty or has no useful data
            if not any(ip_info.get(k) for k in ['hostname', 'asn', 'spamhaus']):
                info_lines.append(("  No additional information available", curses.A_DIM))
        else:
            info_lines.append(("  No information available for this IP", curses.A_DIM))
        
        # Draw info
        for i, (line, attr) in enumerate(info_lines):
            if row + i >= popup_y + popup_height - 2:
                break
            try:
                if row + i < height:
                    if isinstance(attr, int) and attr > 100:  # Has color pair
                        stdscr.attron(attr)
                        stdscr.addstr(row + i, popup_x + 2, line[:popup_width-4])
                        stdscr.attroff(attr)
                    else:
                        stdscr.attron(curses.color_pair(7) | attr)
                        stdscr.addstr(row + i, popup_x + 2, line[:popup_width-4])
                        stdscr.attroff(curses.color_pair(7) | attr)
            except:
                pass
        
        # Footer
        try:
            footer = " Press ESC or Q to close "
            if popup_y + popup_height - 1 < height:
                stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
                stdscr.addstr(popup_y + popup_height - 1, popup_x + (popup_width - len(footer)) // 2, footer[:popup_width-2])
                stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        except:
            pass
    
    def _draw_loading_popup(self, stdscr, height, width, message, subtitle=""):
        """Draw a loading popup message."""
        # Draw semi-transparent background
        try:
            for y in range(height):
                try:
                    stdscr.addstr(y, 0, " " * (width - 1), curses.color_pair(6))
                except:
                    pass
        except:
            pass
        
        # Calculate popup size
        popup_width = min(width - 4, 60)
        popup_height = 8
        popup_x = (width - popup_width) // 2
        popup_y = (height - popup_height) // 2
        
        # Draw popup
        try:
            for y in range(popup_height):
                if popup_y + y < height:
                    stdscr.addstr(popup_y + y, popup_x, " " * (popup_width - 1), curses.color_pair(7))
        except:
            pass
        
        # Title
        try:
            stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
            if popup_y < height:
                stdscr.addstr(popup_y, popup_x + (popup_width - len(message)) // 2, message[:popup_width-2])
            stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        except:
            pass
        
        # Subtitle if provided
        if subtitle:
            try:
                stdscr.attron(curses.color_pair(7))
                if popup_y + 2 < height:
                    stdscr.addstr(popup_y + 2, popup_x + (popup_width - len(subtitle)) // 2, subtitle[:popup_width-2])
                stdscr.attroff(curses.color_pair(7))
            except:
                pass
        
        # Spinner/indicator
        try:
            indicator = "⏳ Please wait..."
            if popup_y + 4 < height:
                stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
                stdscr.addstr(popup_y + 4, popup_x + (popup_width - len(indicator)) // 2, indicator)
                stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
        except:
            pass
    
    def _draw_alert_settings_screen(self, stdscr, height, width):
        """Draw alert settings screen."""
        if not self.alert_config:
            self.alert_config = self.client.get_alert_config()
        
        if not self.alert_config:
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(height // 2, (width - 40) // 2, "Failed to load alert configuration")
            stdscr.attroff(curses.color_pair(3))
            return
        
        row = 4
        
        # Header
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        header = "Alert Settings & Configuration"
        stdscr.addstr(row, 2, header)
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        stdscr.addstr(row + 1, 2, "─" * (width - 4))
        
        # Attack Detection Settings
        row += 3
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(row, 2, "Attack Detection:")
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        row += 1
        enabled = self.alert_config.get('enabled', False)
        status_color = curses.color_pair(1) if enabled else curses.color_pair(3)
        status_text = "ENABLED" if enabled else "DISABLED"
        
        stdscr.addstr(row, 4, "Status: ")
        stdscr.attron(status_color | curses.A_BOLD)
        stdscr.addstr(status_text)
        stdscr.attroff(status_color | curses.A_BOLD)
        
        row += 1
        stdscr.addstr(row, 4, f"QPS Threshold: {self.alert_config.get('qps_threshold', 0)} requests/sec")
        row += 1
        stdscr.addstr(row, 4, f"Time Window: {self.alert_config.get('time_window', 0)} seconds")
        row += 1
        stdscr.addstr(row, 4, f"Minimum Duration: {self.alert_config.get('min_duration', 0)} seconds")
        row += 1
        stdscr.addstr(row, 4, f"Cooldown Period: {self.alert_config.get('cooldown', 0)} seconds")
        
        # Email Alerting Settings
        row += 3
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(row, 2, "Email Alerting:")
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        row += 1
        email_enabled = self.alert_config.get('email_enabled', False)
        email_status_color = curses.color_pair(1) if email_enabled else curses.color_pair(3)
        email_status_text = "ENABLED" if email_enabled else "DISABLED"
        
        stdscr.addstr(row, 4, "Status: ")
        stdscr.attron(email_status_color | curses.A_BOLD)
        stdscr.addstr(email_status_text)
        stdscr.attroff(email_status_color | curses.A_BOLD)
        
        row += 1
        stdscr.addstr(row, 4, f"SMTP Host: {self.alert_config.get('smtp_host', 'N/A')}")
        row += 1
        stdscr.addstr(row, 4, f"SMTP Port: {self.alert_config.get('smtp_port', 0)}")
        row += 1
        stdscr.addstr(row, 4, f"From Address: {self.alert_config.get('from_address', 'N/A')}")
        row += 1
        to_addresses = self.alert_config.get('to_addresses', 'N/A')
        if len(to_addresses) > width - 20:
            to_addresses = to_addresses[:width-23] + "..."
        stdscr.addstr(row, 4, f"To Addresses: {to_addresses}")
        
        # How it works
        row += 3
        stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
        stdscr.addstr(row, 2, "How Attack Detection Works:")
        stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
        
        row += 1
        help_text = [
            f"• Monitors bot request rates over a {self.alert_config.get('time_window', 60)}s window",
            f"• Triggers alert when QPS exceeds {self.alert_config.get('qps_threshold', 10)}",
            f"• Only records attacks lasting {self.alert_config.get('min_duration', 30)}s or longer",
            f"• Waits {self.alert_config.get('cooldown', 300)}s before alerting again for same bot",
            "• Email alerts sent immediately when attack detected (if enabled)"
        ]
        
        for line in help_text:
            if row < height - 4:
                stdscr.addstr(row, 4, line[:width-8])
                row += 1
        
        # Note
        row += 2
        if row < height - 3:
            stdscr.attron(curses.color_pair(2) | curses.A_DIM)
            stdscr.addstr(row, 2, "Note: To permanently change settings, edit /etc/bot_monitor.conf")
            stdscr.attroff(curses.color_pair(2) | curses.A_DIM)
            row += 1
            stdscr.attron(curses.color_pair(2) | curses.A_DIM)
            stdscr.addstr(row, 2, "and restart the daemon: sudo systemctl restart bot_monitor")
            stdscr.attroff(curses.color_pair(2) | curses.A_DIM)
    
    def _draw_bot_ips_screen(self, stdscr, height, width):
        """Draw top bot IPs screen."""
        if not self.stats:
            return
        
        row = 4
        windows = [('minute', 'Past Minute'), ('hour', 'Past Hour'), ('day', 'Past Day')]
        col_width = width // 3
        
        bot_ip_counts = self.stats['stats']['bot_ip_counts']
        loading_complete = self.stats.get('loading_complete', True)
        
        # Build normalized IP list for the first window (for selection)
        window_data = bot_ip_counts.get('minute', {})
        
        # Normalize IPs
        normalized_ips = defaultdict(int)
        for ip, count in window_data.items():
            normalized = normalize_ip(ip)
            normalized_ips[normalized] += count
        
        # Build selectable list
        self.ip_list = sorted(normalized_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        
        for idx, (window, title) in enumerate(windows):
            col = idx * col_width
            
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, col + 2, title)
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
            
            stdscr.addstr(row + 1, col + 2, "─" * (col_width - 4))
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(row + 2, col + 2, "IP Network".ljust(col_width - 12) + "Count")
            stdscr.attroff(curses.color_pair(4))
            stdscr.addstr(row + 3, col + 2, "─" * (col_width - 4))
            
            # Get IPs for this window
            window_ips = bot_ip_counts.get(window, {})
            normalized_window = defaultdict(int)
            for ip, count in window_ips.items():
                normalized = normalize_ip(ip)
                normalized_window[normalized] += count
            
            top_ips = sorted(normalized_window.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Show "Still loading..." if not complete and no data yet
            if not loading_complete and len(top_ips) == 0:
                stdscr.attron(curses.color_pair(2) | curses.A_DIM)
                stdscr.addstr(row + 5, col + 4, "Still loading...")
                stdscr.attroff(curses.color_pair(2) | curses.A_DIM)
            else:
                for i, (ip_net, count) in enumerate(top_ips):
                    if row + 4 + i < height - 2:
                        # Highlight if selected (only first column is selectable)
                        if idx == 0 and i == self.selected_index and self.current_screen == 1:
                            stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
                            line = f"{i+1:2d}. {ip_net.ljust(col_width - 16)}{count:5d}"
                            stdscr.addstr(row + 4 + i, col + 2, line[:col_width-4])
                            stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
                        else:
                            stdscr.attron(curses.color_pair(2))
                            stdscr.addstr(row + 4 + i, col + 2, f"{i+1:2d}. {ip_net.ljust(col_width - 16)}{count:5d}")
                            stdscr.attroff(curses.color_pair(2))
    
    def _draw_bot_ratios_screen(self, stdscr, height, width):
        """Draw bot vs non-bot ratio screen."""
        if not self.stats:
            return
        
        row = 4
        windows = [('minute', 'Past Minute'), ('hour', 'Past Hour'), ('day', 'Past Day')]
        col_width = width // 3
        
        window_totals = self.stats['stats']['window_totals']
        window_bots = self.stats['stats']['window_bots']
        
        for idx, (window, title) in enumerate(windows):
            col = idx * col_width
            
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, col + 2, title)
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
            
            total = window_totals.get(window, 0)
            bots = window_bots.get(window, 0)
            non_bots = total - bots
            
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
                
                stdscr.attron(curses.color_pair(3))
                stdscr.addstr(row + 10, col + 2, "■ Bots")
                stdscr.attroff(curses.color_pair(3))
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(row + 11, col + 2, "■ Non-Bots")
                stdscr.attroff(curses.color_pair(1))
    
    def _draw_alert_settings_screen(self, stdscr, height, width):
        """Draw alert settings screen."""
        if not self.alert_config:
            self.alert_config = self.client.get_alert_config()
        
        if not self.alert_config:
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(height // 2, (width - 40) // 2, "Failed to load alert configuration")
            stdscr.attroff(curses.color_pair(3))
            return
        
        row = 4
        max_row = height - 3
        
        if row < max_row:
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, 2, "Alert Settings & Configuration")
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        row += 1
        if row < max_row:
            stdscr.addstr(row, 2, "─" * min(width - 4, 70))
        
        row += 2
        if row < max_row:
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, 2, "Attack Detection:")
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        row += 1
        if row < max_row:
            enabled = self.alert_config.get('enabled', False)
            status_color = curses.color_pair(1) if enabled else curses.color_pair(3)
            status_text = "ENABLED" if enabled else "DISABLED"
            stdscr.addstr(row, 4, "Status: ")
            stdscr.attron(status_color | curses.A_BOLD)
            stdscr.addstr(status_text)
            stdscr.attroff(status_color | curses.A_BOLD)
        
        row += 1
        if row < max_row:
            stdscr.addstr(row, 4, f"QPS Threshold: {self.alert_config.get('qps_threshold', 0)} requests/sec")
        row += 1
        if row < max_row:
            stdscr.addstr(row, 4, f"Time Window: {self.alert_config.get('time_window', 0)} seconds")
        row += 1
        if row < max_row:
            stdscr.addstr(row, 4, f"Minimum Duration: {self.alert_config.get('min_duration', 0)} seconds")
        row += 1
        if row < max_row:
            stdscr.addstr(row, 4, f"Cooldown Period: {self.alert_config.get('cooldown', 0)} seconds")
        
        row += 2
        if row < max_row:
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(row, 2, "Email Alerting:")
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        row += 1
        if row < max_row:
            email_enabled = self.alert_config.get('email_enabled', False)
            email_status_color = curses.color_pair(1) if email_enabled else curses.color_pair(3)
            email_status_text = "ENABLED" if email_enabled else "DISABLED"
            stdscr.addstr(row, 4, "Status: ")
            stdscr.attron(email_status_color | curses.A_BOLD)
            stdscr.addstr(email_status_text)
            stdscr.attroff(email_status_color | curses.A_BOLD)
        
        row += 1
        if row < max_row:
            stdscr.addstr(row, 4, f"SMTP Host: {self.alert_config.get('smtp_host', 'N/A')}")
        row += 1
        if row < max_row:
            stdscr.addstr(row, 4, f"SMTP Port: {self.alert_config.get('smtp_port', 0)}")
        row += 1
        if row < max_row:
            stdscr.addstr(row, 4, f"From Address: {self.alert_config.get('from_address', 'N/A')}")
        row += 1
        if row < max_row:
            to_addresses = self.alert_config.get('to_addresses', 'N/A')
            if len(to_addresses) > width - 20:
                to_addresses = to_addresses[:width-23] + "..."
            stdscr.addstr(row, 4, f"To Addresses: {to_addresses}")
        
        row += 2
        if row < max_row:
            stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(row, 2, "How Attack Detection Works:")
            stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
        
        row += 1
        help_text = [
            f"• Monitors bot request rates over a {self.alert_config.get('time_window', 60)}s window",
            f"• Triggers alert when QPS exceeds {self.alert_config.get('qps_threshold', 10)}",
            f"• Only records attacks lasting {self.alert_config.get('min_duration', 30)}s or longer",
            f"• Waits {self.alert_config.get('cooldown', 300)}s before alerting again for same bot",
            "• Email alerts sent immediately when attack detected (if enabled)"
        ]
        
        for line in help_text:
            if row < max_row:
                stdscr.addstr(row, 4, line[:width-8])
                row += 1
        
        row += 1
        if row < max_row:
            stdscr.attron(curses.color_pair(2) | curses.A_DIM)
            stdscr.addstr(row, 2, "Note: To permanently change settings, edit /etc/bot_monitor.conf")
            stdscr.attroff(curses.color_pair(2) | curses.A_DIM)
        row += 1
        if row < max_row:
            stdscr.attron(curses.color_pair(2) | curses.A_DIM)
            stdscr.addstr(row, 2, "and restart the daemon: sudo systemctl restart bot_monitor")
            stdscr.attroff(curses.color_pair(2) | curses.A_DIM)
    
    def _draw_detected_bots_screen(self, stdscr, height, width):
        """Draw detected bots screen."""
        if not self.stats:
            return
        
        row = 4
        bot_tracking = self.stats['stats']['bot_tracking']
        
        # Build bot list
        detected_bots = []
        for bot_name, stats in bot_tracking.items():
            detected_bots.append({
                'name': bot_name,
                'last_seen': datetime.fromisoformat(stats['last_seen']) if isinstance(stats['last_seen'], str) else stats['last_seen'],
                'count': stats['count']
            })
        
        # Sort
        sort_names = ["Name (A-Z)", "Last Seen (Recent)", "Count (High-Low)"]
        if self.sort_mode == 0:
            detected_bots.sort(key=lambda x: x['name'])
        elif self.sort_mode == 1:
            detected_bots.sort(key=lambda x: x['last_seen'], reverse=True)
        elif self.sort_mode == 2:
            detected_bots.sort(key=lambda x: x['count'], reverse=True)
        
        self.bot_list = detected_bots
        
        # Header
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        header = f"Detected Bots - Sorted by {sort_names[self.sort_mode]} ({len(detected_bots)} unique bots)"
        stdscr.addstr(row, 2, header[:width-4])
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        stdscr.addstr(row + 1, 2, "─" * (width - 4))
        stdscr.attron(curses.color_pair(4))
        col_header = "#".ljust(6) + "Bot Name".ljust(35) + "Count".ljust(10) + "Last Seen"
        stdscr.addstr(row + 2, 2, col_header[:width-4])
        stdscr.attroff(curses.color_pair(4))
        stdscr.addstr(row + 3, 2, "─" * (width - 4))
        
        max_lines = height - row - 6
        
        if len(detected_bots) == 0:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(height // 2, (width - 40) // 2, "No bots detected yet...")
            stdscr.attroff(curses.color_pair(2))
            return
        
        # Adjust scroll to keep selection visible
        if self.selected_index >= self.scroll + max_lines:
            self.scroll = self.selected_index - max_lines + 1
        if self.selected_index < self.scroll:
            self.scroll = self.selected_index
        
        # Display bots
        for i in range(max_lines):
            idx = self.scroll + i
            if idx >= len(detected_bots):
                break
            
            bot = detected_bots[idx]
            bot_name = bot['name']
            count = bot['count']
            last_seen = bot['last_seen']
            
            # Format timestamp
            time_diff = datetime.now() - last_seen
            if time_diff.total_seconds() < 5:
                time_str = "Just now"
            elif time_diff.total_seconds() < 60:
                time_str = f"{int(time_diff.total_seconds())}s ago"
            elif time_diff.total_seconds() < 3600:
                time_str = f"{int(time_diff.total_seconds() / 60)}m ago"
            elif time_diff.total_seconds() < 86400:
                time_str = f"{int(time_diff.total_seconds() / 3600)}h ago"
            else:
                time_str = f"{int(time_diff.total_seconds() / 86400)}d ago"
            
            display_name = bot_name[:33] if len(bot_name) > 33 else bot_name
            
            # Highlight selected
            if idx == self.selected_index:
                stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
                line = f"{idx + 1:5d}. {display_name.ljust(35)}{count:<10,}{time_str}".ljust(width - 4)
                stdscr.addstr(row + 4 + i, 2, line[:width - 4])
                stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
            else:
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
            scroll_info = f"Showing {self.scroll + 1}-{min(self.scroll + max_lines, len(detected_bots))} of {len(detected_bots)}"
            stdscr.addstr(height - 2, 2, scroll_info)
    
    def _draw_bot_attacks_screen(self, stdscr, height, width):
        """Draw bot attacks screen."""
        if not self.stats:
            return
        
        row = 4
        attacks = self.stats['attacks']
        current_attacks = attacks.get('current', [])
        attack_history = attacks.get('history', [])
        
        # Header
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        header = f"Bot Attacks - {len(current_attacks)} Active, {len(attack_history)} Historical"
        stdscr.addstr(row, 2, header[:width-4])
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        stdscr.addstr(row + 1, 2, "─" * (width - 4))
        
        # Current attacks
        if current_attacks:
            stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(row + 3, 2, "⚠ ACTIVE ATTACKS:")
            stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            
            for i, attack in enumerate(current_attacks):
                if row + 4 + i >= height - 6:
                    break
                bot_name = attack['bot_name']
                start_time = datetime.fromisoformat(attack['start_time']) if isinstance(attack['start_time'], str) else attack['start_time']
                duration = (datetime.now() - start_time).total_seconds()
                peak_qps = attack['peak_qps']
                
                stdscr.attron(curses.color_pair(3))
                attack_line = f"  {bot_name}: Peak QPS {peak_qps:.1f}, Duration {int(duration)}s"
                stdscr.addstr(row + 4 + i, 2, attack_line[:width-4])
                stdscr.attroff(curses.color_pair(3))
        else:
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(row + 3, 2, "✓ No active attacks")
            stdscr.attroff(curses.color_pair(1))
        
        # Attack history
        start_row = row + 6 + len(current_attacks)
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(start_row, 2, "Attack History:")
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
        
        stdscr.addstr(start_row + 1, 2, "─" * (width - 4))
        stdscr.attron(curses.color_pair(4))
        col_header = "Time".ljust(20) + "Bot Name".ljust(30) + "Peak QPS".ljust(12) + "Duration"
        stdscr.addstr(start_row + 2, 2, col_header[:width-4])
        stdscr.attroff(curses.color_pair(4))
        stdscr.addstr(start_row + 3, 2, "─" * (width - 4))
        
        if not attack_history:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(start_row + 5, 2, "No attack history yet")
            stdscr.attroff(curses.color_pair(2))
            return
        
        # Sort history
        sort_names = ["Time", "QPS", "Duration"]
        if self.attack_sort == 0:  # Time
            attack_history.sort(key=lambda x: x.get('start_time', ''), reverse=True)
        elif self.attack_sort == 1:  # QPS
            attack_history.sort(key=lambda x: x.get('peak_qps', 0), reverse=True)
        elif self.attack_sort == 2:  # Duration
            attack_history.sort(key=lambda x: x.get('duration', 0), reverse=True)
        
        max_lines = height - start_row - 6
        max_scroll = max(0, len(attack_history) - max_lines)
        self.scroll = max(0, min(self.scroll, max_scroll))
        
        for i in range(max_lines):
            idx = self.scroll + i
            if idx >= len(attack_history):
                break
            
            attack = attack_history[idx]
            bot_name = attack['bot_name']
            start_time = datetime.fromisoformat(attack['start_time']) if isinstance(attack['start_time'], str) else attack['start_time']
            peak_qps = attack['peak_qps']
            duration = attack.get('duration', 0)
            
            time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")[:19]
            display_name = bot_name[:28] if len(bot_name) > 28 else bot_name
            
            if idx % 2 == 0:
                stdscr.attron(curses.color_pair(1))
            else:
                stdscr.attron(curses.color_pair(2))
            
            line = f"{time_str.ljust(20)}{display_name.ljust(30)}{peak_qps:<12.1f}{int(duration)}s"
            stdscr.addstr(start_row + 4 + i, 2, line[:width-4])
            
            if idx % 2 == 0:
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.attroff(curses.color_pair(2))
        
        # Scroll indicator
        if len(attack_history) > max_lines:
            scroll_info = f"Showing {self.scroll + 1}-{min(self.scroll + max_lines, len(attack_history))} of {len(attack_history)}"
            stdscr.addstr(height - 2, 2, scroll_info)
    
    def _draw_bot_details(self, stdscr, height, width):
        """Draw bot details popup."""
        details = self.client.get_bot_details(self.selected_bot)
        
        # Draw semi-transparent background (with bounds checking)
        try:
            for y in range(height):
                try:
                    stdscr.addstr(y, 0, " " * (width - 1), curses.color_pair(6))
                except:
                    pass
        except:
            pass
        
        # Calculate popup size
        popup_width = min(width - 4, 100)
        popup_height = min(height - 4, 25)
        popup_x = (width - popup_width) // 2
        popup_y = (height - popup_height) // 2
        
        # Ensure popup fits on screen
        if popup_width < 20 or popup_height < 10:
            return  # Screen too small for popup
        
        # Draw popup border
        try:
            for y in range(popup_height):
                if popup_y + y < height:
                    stdscr.addstr(popup_y + y, popup_x, " " * (popup_width - 1), curses.color_pair(7))
        except:
            pass
        
        # Title
        try:
            stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
            title = f" Bot Details: {self.selected_bot} "
            if popup_y < height and popup_x + (popup_width - len(title)) // 2 < width:
                stdscr.addstr(popup_y, popup_x + (popup_width - len(title)) // 2, title[:popup_width-2])
            stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        except:
            pass
        
        row = popup_y + 2
        
        # Get bot stats
        bot_stats = None
        if self.stats:
            bot_tracking = self.stats['stats']['bot_tracking']
            bot_stats = bot_tracking.get(self.selected_bot, {})
        
        # Display information
        info_lines = []
        
        if bot_stats:
            info_lines.append(("Our Statistics:", curses.A_BOLD))
            info_lines.append((f"  Total Requests: {bot_stats.get('count', 0):,}", 0))
            
            first_seen = bot_stats.get('first_seen')
            if first_seen:
                if isinstance(first_seen, str):
                    first_seen = datetime.fromisoformat(first_seen)
                info_lines.append((f"  First Seen: {first_seen.strftime('%Y-%m-%d %H:%M:%S')}", 0))
            
            last_seen = bot_stats.get('last_seen')
            if last_seen:
                if isinstance(last_seen, str):
                    last_seen = datetime.fromisoformat(last_seen)
                info_lines.append((f"  Last Seen: {last_seen.strftime('%Y-%m-%d %H:%M:%S')}", 0))
            
            info_lines.append(("", 0))
        
        if details:
            info_lines.append(("Bot Information:", curses.A_BOLD))
            
            if details.get('url'):
                info_lines.append((f"  URL: {details['url']}", 0))
            if details.get('category'):
                info_lines.append((f"  Category: {details['category']}", 0))
            if details.get('producer'):
                info_lines.append((f"  Producer: {details['producer']}", 0))
            if details.get('description'):
                info_lines.append((f"  Description: {details['description']}", 0))
            if details.get('pattern'):
                info_lines.append((f"  Pattern: {details['pattern'][:popup_width-15]}", 0))
        else:
            info_lines.append(("No additional information available", curses.A_DIM))
        
        # Draw info
        for i, (line, attr) in enumerate(info_lines):
            if row + i >= popup_y + popup_height - 2:
                break
            try:
                if row + i < height and popup_x + 2 < width:
                    stdscr.attron(curses.color_pair(7) | attr)
                    stdscr.addstr(row + i, popup_x + 2, line[:popup_width-4])
                    stdscr.attroff(curses.color_pair(7) | attr)
            except:
                pass
        
        # Footer
        try:
            footer = " Press ESC or Q to close "
            if popup_y + popup_height - 1 < height and popup_x + (popup_width - len(footer)) // 2 < width:
                stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
                stdscr.addstr(popup_y + popup_height - 1, popup_x + (popup_width - len(footer)) // 2, footer[:popup_width-2])
                stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        except:
            pass


def load_config():
    """Load configuration."""
    config = ConfigParser()
    config_paths = [
        os.path.expanduser('~/.bot_monitor.conf'),
        '/etc/bot_monitor.conf'
    ]
    
    for path in config_paths:
        if os.path.exists(path):
            config.read(path)
            return config
    
    # Defaults
    config.add_section('daemon')
    config.set('daemon', 'socket_path', '/tmp/bot_monitor.sock')
    return config


def main():
    """Main entry point."""
    config = load_config()
    socket_path = config.get('daemon', 'socket_path')
    
    print("Apache Bot Monitor Client")
    print("=" * 70)
    print(f"Connecting to daemon at: {socket_path}")
    
    client = DaemonClient(socket_path)
    if not client.connect():
        print("\nMake sure the daemon is running:")
        print("  sudo bot_monitor_daemon.py")
        sys.exit(1)
    
    print("✓ Connected!")
    print("Starting dashboard...")
    time.sleep(1)
    
    ui = BotMonitorUI(client)
    
    try:
        curses.wrapper(ui.run)
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
        print("\nDisconnected from daemon.")


if __name__ == "__main__":
    main()
