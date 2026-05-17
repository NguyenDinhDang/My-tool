"Advanced WiFi Security Analyzer - LAB ONLY"

from scapy.all import *
from collections import defaultdict
import threading
import time
from datetime import datetime
import re
import base64
import json
import sqlite3
import sys
import platform
import subprocess
from colorama import Fore, Style, init
from scapy.all import show_interfaces, get_if_list

init(autoreset=True)

def get_windows_adapters():
    """Get Windows network adapter names and their GUID mappings"""
    try:
        # Use PowerShell to get adapter GUIDs
        ps_cmd = """Get-NetAdapter | Select-Object Name, InterfaceGuid | ConvertTo-Json"""
        result = subprocess.run(
            ['powershell', '-Command', ps_cmd],
            capture_output=True,
            text=True
        )
        
        adapters = {}
        if result.returncode == 0 and result.stdout:
            try:
                import json as json_lib
                data = json_lib.loads(result.stdout)
                if isinstance(data, list):
                    for item in data:
                        adapters[item['Name']] = item['InterfaceGuid']
                elif isinstance(data, dict):
                    adapters[data['Name']] = data['InterfaceGuid']
            except:
                pass
        
        # Fallback: parse ipconfig
        if not adapters:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'adapter' in line.lower() and ':' in line:
                    name = line.split(':')[0].replace('adapter', '').strip()
                    if name:
                        adapters[name] = None
        
        return adapters
    except:
        return {}

def find_interface(name):
    """Find the scapy interface name by Windows adapter name"""
    interfaces = get_if_list()
    adapters = get_windows_adapters()
    
    # Try exact match first (for device GUID names)
    if name in interfaces:
        return name
    
    # Try to match Windows adapter name
    for adapter_name, guid in adapters.items():
        if name.lower() == adapter_name.lower():
            # Found the adapter, now find its Npcap device
            if guid:
                guid_str = str(guid).strip('{}')
                npcap_name = f"\\Device\\NPF_{{{guid_str}}}"
                if npcap_name in interfaces:
                    return npcap_name
            # Try matching by name in Npcap devices
            for iface in interfaces:
                if adapter_name.lower() in iface.lower():
                    return iface
    
    # Try partial matching
    name_lower = name.lower()
    for iface in interfaces:
        if name_lower in iface.lower():
            return iface
    
    return None

# Display available interfaces at startup for Windows
if platform.system() == "Windows":
    print(f"{Fore.CYAN}Available Network Interfaces:")
    print("="*60)
    adapters = get_windows_adapters()
    if adapters:
        for name in adapters:
            print(f"  - {name}")
    interfaces = get_if_list()
    print(f"\n{Fore.YELLOW}Npcap Device Names:")
    for iface in interfaces[:5]:  # Show first 5 for brevity
        print(f"  {iface}")
    if len(interfaces) > 5:
        print(f"  ... and {len(interfaces)-5} more")
    print("="*60)
    print(f"Use friendly name (e.g., 'Wi-Fi') or device GUID with -i flag\n")
else:
    show_interfaces()

class AdvancedWifiAnalyzer:
    def __init__(self, interface, output_db="capture.db"):
        self.interface = interface
        self.output_db = output_db
        self.packets = []
        self.stats = {
            'total': 0,
            'http': 0,
            'https': 0,
            'dns': 0,
            'credentials': 0,
            'files': 0
        }
        
        # Tracking
        self.devices = defaultdict(lambda: {
            'packets': 0,
            'protocols': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        self.sessions = defaultdict(list)
        self.credentials_found = []
        self.dns_queries = []
        self.http_requests = []
        
        # Thread lock for database access
        self.db_lock = threading.Lock()
        
        self.setup_database()
        
    def setup_database(self):
        """Tạo database để lưu kết quả phân tích"""
        import os
        
        # Remove locked database file if it exists
        if os.path.exists(self.output_db):
            try:
                os.remove(self.output_db)
                print(f"{Fore.YELLOW}[*] Removed previous database lock...")
            except:
                pass
        
        # Remove WAL files if they exist
        for wal_file in [f"{self.output_db}-wal", f"{self.output_db}-shm"]:
            if os.path.exists(wal_file):
                try:
                    os.remove(wal_file)
                except:
                    pass
        
        # Create new connection with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.conn = sqlite3.connect(self.output_db, check_same_thread=False, timeout=30.0)
                self.conn.execute("PRAGMA journal_mode=DELETE")
                self.conn.execute("PRAGMA synchronous=NORMAL")
                self.conn.execute("PRAGMA cache_size=-64000")
                self.cursor = self.conn.cursor()
                break
            except sqlite3.OperationalError as e:
                if attempt < max_retries - 1:
                    time.sleep(0.5 * (attempt + 1))
                else:
                    print(f"{Fore.RED}[ERROR] Failed to create database: {e}")
                    raise
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                src_mac TEXT,
                dst_mac TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                length INTEGER,
                info TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                source TEXT,
                username TEXT,
                password TEXT,
                url TEXT,
                method TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS http_traffic (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                method TEXT,
                host TEXT,
                path TEXT,
                user_agent TEXT,
                cookies TEXT
            )
        ''')
        
        self.conn.commit()
        
    def extract_credentials_http(self, packet):
        """Phát hiện credentials trong HTTP POST requests"""
        if packet.haslayer(Raw):
            load = packet[Raw].load
            try:
                payload = load.decode('utf-8', errors='ignore')
                
                # Tìm POST data
                if 'POST' in payload:
                    # Common credential patterns
                    patterns = {
                        'username': r'(?:user(?:name)?|login|email)=([^&\s]+)',
                        'password': r'(?:pass(?:word)?|pwd)=([^&\s]+)',
                        'token': r'(?:token|auth)=([^&\s]+)'
                    }
                    
                    creds = {}
                    for key, pattern in patterns.items():
                        match = re.search(pattern, payload, re.IGNORECASE)
                        if match:
                            creds[key] = match.group(1)
                    
                    if creds:
                        timestamp = datetime.now().isoformat()
                        url = re.search(r'Host: ([^\r\n]+)', payload)
                        host = url.group(1) if url else 'Unknown'
                        
                        self.credentials_found.append({
                            'timestamp': timestamp,
                            'type': 'HTTP POST',
                            'credentials': creds,
                            'url': host
                        })
                        
                        with self.db_lock:
                            self.cursor.execute('''
                                INSERT INTO credentials 
                                (timestamp, source, username, password, url, method)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (
                                timestamp,
                                packet[IP].src if packet.haslayer(IP) else 'N/A',
                                creds.get('username', ''),
                                creds.get('password', ''),
                                host,
                                'HTTP POST'
                            ))
                            self.conn.commit()
                        
                        self.stats['credentials'] += 1
                        return True
                        
            except Exception as e:
                pass
        return False
    
    def analyze_http_traffic(self, packet):
        """Phân tích chi tiết HTTP traffic"""
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            load = packet[Raw].load
            try:
                payload = load.decode('utf-8', errors='ignore')
                
                # HTTP Request
                if any(method in payload for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                    method = payload.split()[0]
                    
                    # Extract headers
                    host = re.search(r'Host: ([^\r\n]+)', payload)
                    path = re.search(r'^(?:GET|POST|PUT|DELETE) ([^\s]+)', payload)
                    user_agent = re.search(r'User-Agent: ([^\r\n]+)', payload)
                    cookies = re.search(r'Cookie: ([^\r\n]+)', payload)
                    
                    http_data = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'method': method,
                        'host': host.group(1) if host else '',
                        'path': path.group(1) if path else '',
                        'user_agent': user_agent.group(1) if user_agent else '',
                        'cookies': cookies.group(1) if cookies else ''
                    }
                    
                    self.http_requests.append(http_data)
                    
                    with self.db_lock:
                        self.cursor.execute('''
                            INSERT INTO http_traffic 
                            (timestamp, src_ip, dst_ip, method, host, path, user_agent, cookies)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            http_data['timestamp'],
                            http_data['src_ip'],
                            http_data['dst_ip'],
                            http_data['method'],
                            http_data['host'],
                            http_data['path'],
                            http_data['user_agent'],
                            http_data['cookies']
                        ))
                        self.conn.commit()
                    
                    self.stats['http'] += 1
                    
                    print(f"{Fore.YELLOW}[HTTP] {method} {http_data['host']}{http_data['path']}")
                    if cookies:
                        print(f"{Fore.RED}  └─ Cookies detected: {cookies.group(1)[:50]}...")
                        
            except Exception as e:
                pass
    
    def analyze_http_headers(self, packet):
        """Phân tích chi tiết HTTP headers"""
        if packet.haslayer(Raw):
            load = packet[Raw].load
            try:
                payload = load.decode('utf-8', errors='ignore')
                
                if 'HTTP/' in payload:
                    headers = {}
                    lines = payload.split('\r\n')
                    
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip()] = value.strip()
                    
                    # Extract useful information
                    content_type = headers.get('Content-Type', '')
                    server = headers.get('Server', '')
                    referer = headers.get('Referer', '')
                    
                    if server:
                        print(f"{Fore.BLUE}[SERVER] {server}")
                    
                    if content_type:
                        if 'text/html' in content_type:
                            print(f"{Fore.CYAN}[HTML] Content detected")
                        elif 'application/json' in content_type:
                            print(f"{Fore.MAGENTA}[JSON] Data transmission")
                    
                    return headers
                    
            except Exception as e:
                pass
        return {}
    
    def extract_form_data(self, packet):
        """Trích xuất dữ liệu form từ POST requests"""
        if packet.haslayer(Raw):
            load = packet[Raw].load
            try:
                payload = load.decode('utf-8', errors='ignore')
                
                # Check if it's form data
                if 'application/x-www-form-urlencoded' in payload or '&' in payload:
                    # Extract body after headers
                    if '\r\n\r\n' in payload:
                        body = payload.split('\r\n\r\n', 1)[1]
                        
                        # Parse form data
                        form_data = {}
                        pairs = body.split('&')
                        
                        for pair in pairs:
                            if '=' in pair:
                                key, value = pair.split('=', 1)
                                form_data[key] = value
                        
                        # Check for sensitive fields
                        sensitive_fields = ['password', 'pwd', 'pass', 'secret', 'token', 'key', 'auth']
                        for field in sensitive_fields:
                            for key in form_data:
                                if field.lower() in key.lower():
                                    print(f"{Fore.RED}[SENSITIVE] {key} field detected in form")
                        
                        return form_data
                        
            except Exception as e:
                pass
        return {}
    
    def analyze_ssl_tls(self, packet):
        """Phân tích SSL/TLS handshake và certificate"""
        if packet.haslayer(TCP):
            # Check for SSL/TLS handshake (port 443)
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                if packet.haslayer(Raw):
                    load = packet[Raw].load
                    try:
                        # Check for TLS Record header (0x16 = Handshake)
                        if load[0:1] == b'\x16':
                            tls_version = int.from_bytes(load[1:3], 'big')
                            if tls_version == 0x0301:
                                print(f"{Fore.BLUE}[TLS] TLS 1.0 detected")
                            elif tls_version == 0x0302:
                                print(f"{Fore.BLUE}[TLS] TLS 1.1 detected")
                            elif tls_version == 0x0303:
                                print(f"{Fore.GREEN}[TLS] TLS 1.2 detected")
                            elif tls_version == 0x0303:  # 0x0303 is TLS 1.2, 0x0304 is TLS 1.3
                                print(f"{Fore.GREEN}[TLS] TLS 1.3 detected")
                    except:
                        pass
    
    def analyze_http_methods(self, packet):
        """Phân tích các HTTP methods và request types"""
        if packet.haslayer(Raw):
            load = packet[Raw].load
            try:
                payload = load.decode('utf-8', errors='ignore')
                
                # Detect HTTP methods
                methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
                
                for method in methods:
                    if payload.startswith(method + ' '):
                        if method == 'POST':
                            print(f"{Fore.YELLOW}[HTTP-POST] Potential form submission")
                        elif method == 'GET':
                            # Check for query parameters
                            if '?' in payload:
                                print(f"{Fore.YELLOW}[HTTP-GET] Query parameters detected")
                        elif method in ['PUT', 'DELETE', 'PATCH']:
                            print(f"{Fore.RED}[HTTP-{method}] Potential data modification")
                        return method
                
            except Exception as e:
                pass
        return None
    
    def analyze_http_responses(self, packet):
        """Phân tích HTTP responses và status codes"""
        if packet.haslayer(Raw):
            load = packet[Raw].load
            try:
                payload = load.decode('utf-8', errors='ignore')
                
                # Check for HTTP response
                if payload.startswith('HTTP/'):
                    # Extract status code
                    parts = payload.split(' ', 2)
                    if len(parts) >= 2:
                        try:
                            status_code = int(parts[1])
                            
                            if 200 <= status_code < 300:
                                print(f"{Fore.GREEN}[HTTP-{status_code}] Success response")
                            elif 300 <= status_code < 400:
                                print(f"{Fore.CYAN}[HTTP-{status_code}] Redirect")
                            elif 400 <= status_code < 500:
                                print(f"{Fore.YELLOW}[HTTP-{status_code}] Client error")
                            elif 500 <= status_code < 600:
                                print(f"{Fore.RED}[HTTP-{status_code}] Server error")
                            
                            return status_code
                        except:
                            pass
                    
            except Exception as e:
                pass
        return None

        """Phân tích DNS queries"""
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode()
            
            dns_data = {
                'timestamp': datetime.now().isoformat(),
                'query': query,
                'src_ip': packet[IP].src if packet.haslayer(IP) else 'N/A',
                'type': packet[DNSQR].qtype
            }
            
            self.dns_queries.append(dns_data)
            self.stats['dns'] += 1
            
            print(f"{Fore.CYAN}[DNS] {dns_data['src_ip']} -> {query}")
    
    def detect_file_transfers(self, packet):
        """Phát hiện file transfers"""
        if packet.haslayer(Raw):
            load = packet[Raw].load
            
            # Detect common file signatures
            file_signatures = {
                b'\x89PNG': 'PNG Image',
                b'GIF89a': 'GIF Image',
                b'GIF87a': 'GIF Image',
                b'\xff\xd8\xff': 'JPEG Image',
                b'%PDF': 'PDF Document',
                b'PK\x03\x04': 'ZIP Archive',
                b'\x1f\x8b': 'GZIP Archive'
            }
            
            for signature, file_type in file_signatures.items():
                if load.startswith(signature):
                    print(f"{Fore.MAGENTA}[FILE] {file_type} transfer detected")
                    self.stats['files'] += 1
                    return True
        return False
    
    def track_device(self, packet):
        """Track devices trên network"""
        mac = None
        ip = None
        
        if packet.haslayer(Ether):
            mac = packet[Ether].src
        elif packet.haslayer(Dot11):
            mac = packet[Dot11].addr2
            
        if packet.haslayer(IP):
            ip = packet[IP].src
        
        if mac:
            device = self.devices[mac]
            device['packets'] += 1
            device['last_seen'] = datetime.now()
            
            if not device['first_seen']:
                device['first_seen'] = datetime.now()
                print(f"{Fore.GREEN}[NEW DEVICE] {mac} {f'({ip})' if ip else ''}")
            
            if ip:
                device['ip'] = ip
            
            if packet.haslayer(TCP):
                device['protocols'].add('TCP')
            elif packet.haslayer(UDP):
                device['protocols'].add('UDP')
    
    def analyze_sessions(self, packet):
        """Phân tích TCP sessions"""
        if packet.haslayer(TCP) and packet.haslayer(IP):
            session_key = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            
            self.sessions[session_key].append({
                'timestamp': datetime.now(),
                'flags': packet[TCP].flags,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack,
                'size': len(packet)
            })
    
    def packet_handler(self, packet):
        """Main packet handler"""
        self.stats['total'] += 1
        
        try:
            # Track device
            self.track_device(packet)
            
            # Analyze different protocols
            if packet.haslayer(IP):
                # HTTP Analysis
                if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    self.analyze_http_traffic(packet)
                    self.analyze_http_headers(packet)
                    self.analyze_http_methods(packet)
                    self.extract_form_data(packet)
                    self.extract_credentials_http(packet)
                
                # HTTPS Analysis
                if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                    self.stats['https'] += 1
                    self.analyze_ssl_tls(packet)
                    self.analyze_http_responses(packet)
                
                # DNS Analysis
                if packet.haslayer(UDP) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
                    self.analyze_dns(packet)
                
                # Session tracking
                self.analyze_sessions(packet)
            
            # File transfer detection
            self.detect_file_transfers(packet)
            
            # Store packet info
            if packet.haslayer(IP):
                with self.db_lock:
                    try:
                        self.cursor.execute('''
                            INSERT INTO packets 
                            (timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol, length, info)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            datetime.now().isoformat(),
                            packet[Ether].src if packet.haslayer(Ether) else '',
                            packet[Ether].dst if packet.haslayer(Ether) else '',
                            packet[IP].src,
                            packet[IP].dst,
                            packet[IP].proto,
                            len(packet),
                            packet.summary()
                        ))
                        
                        if self.stats['total'] % 100 == 0:
                            self.conn.commit()
                    except Exception as db_err:
                        print(f"{Fore.RED}[DB ERROR] {db_err}")
                    
        except Exception as e:
            print(f"{Fore.RED}[ERROR] {e}")
    
    def print_stats(self):
        """In thống kê"""
        while True:
            time.sleep(10)
            print(f"\n{Fore.WHITE}{'='*60}")
            print(f"{Fore.WHITE}STATISTICS:")
            print(f"  Total Packets: {self.stats['total']}")
            print(f"  HTTP Requests: {self.stats['http']}")
            print(f"  HTTPS Connections: {self.stats['https']}")
            print(f"  DNS Queries: {self.stats['dns']}")
            print(f"  Credentials Found: {Fore.RED}{self.stats['credentials']}")
            print(f"  Files Detected: {self.stats['files']}")
            print(f"  Devices Tracked: {len(self.devices)}")
            print(f"{Fore.WHITE}{'='*60}\n")
    
    def start(self, packet_count=0):
        """Bắt đầu capture"""
        print(f"{Fore.GREEN}[*] Starting Advanced WiFi Analyzer")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Database: {self.output_db}")
        print(f"[*] Press Ctrl+C to stop\n")
        
        # Start stats thread
        stats_thread = threading.Thread(target=self.print_stats, daemon=True)
        stats_thread.start()
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,
                count=packet_count if packet_count > 0 else 0
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Stopping capture...")
            self.generate_report()
    
    def generate_report(self):
        """Tạo báo cáo chi tiết"""
        self.conn.commit()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print("FINAL REPORT")
        print(f"{'='*60}")
        
        print(f"\n{Fore.CYAN}CAPTURED STATISTICS:")
        for key, value in self.stats.items():
            print(f"  {key.upper()}: {value}")
        
        print(f"\n{Fore.YELLOW}DEVICES DISCOVERED:")
        for mac, info in self.devices.items():
            print(f"  MAC: {mac}")
            print(f"    IP: {info.get('ip', 'Unknown')}")
            print(f"    Packets: {info['packets']}")
            print(f"    Protocols: {', '.join(info['protocols'])}")
            print(f"    First Seen: {info['first_seen']}")
            print(f"    Last Seen: {info['last_seen']}\n")
        
        if self.credentials_found:
            print(f"\n{Fore.RED}⚠️  CREDENTIALS FOUND:")
            for cred in self.credentials_found:
                print(f"  [{cred['timestamp']}] {cred['type']}")
                print(f"    URL: {cred['url']}")
                print(f"    Data: {cred['credentials']}\n")
        
        print(f"\n{Fore.WHITE}TOP 10 DNS QUERIES:")
        dns_counts = defaultdict(int)
        for dns in self.dns_queries:
            dns_counts[dns['query']] += 1
        
        for query, count in sorted(dns_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {count}x {query}")
        
        print(f"\n{Fore.GREEN}Data saved to: {self.output_db}")
        print("Use SQLite browser to analyze further.")
        
        self.conn.close()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced WiFi Security Analyzer - LAB ONLY'
    )
    parser.add_argument('-i', '--interface', required=True,
                       help='Network interface in monitor mode')
    parser.add_argument('-o', '--output', default='capture.db',
                       help='Output database file')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets (0 = unlimited)')
    
    args = parser.parse_args()
    
    # LEGAL WARNING
    print(f"{Fore.RED}{'='*60}")
    print("⚠️  CẢNH BÁO PHÁP LÝ")
    print("="*60)
    print("Công cụ này CHỈ được sử dụng:")
    print("  1. Trong môi trường LAB của bạn")
    print("  2. Trên mạng BẠN SỞ HỮU")
    print("  3. Với SỰ CHO PHÉP RÕ RÀNG bằng văn bản")
    print("\nViệc sử dụng trái phép là PHẠM TỘI HÌNH SỰ")
    print(f"{'='*60}\n")
    
    confirm = input("Tôi xác nhận đây là môi trường LAB hợp pháp (YES/no): ")
    if confirm != "YES":
        print("Cancelled.")
        return
    
    # Validate and convert interface on Windows
    if platform.system() == "Windows":
        resolved_iface = find_interface(args.interface)
        if resolved_iface:
            if resolved_iface != args.interface:
                print(f"{Fore.YELLOW}Resolved interface '{args.interface}' to: {resolved_iface}\n")
            args.interface = resolved_iface
        else:
            print(f"{Fore.RED}Error: Interface '{args.interface}' not found!")
            print(f"{Fore.CYAN}Available adapters:")
            adapters = get_windows_adapters()
            for name in adapters:
                print(f"  - {name}")
            print(f"\n{Fore.CYAN}Or use a Npcap device GUID from:")
            interfaces = get_if_list()
            for i in interfaces[:10]:
                print(f"  {i}")
            return
    
    analyzer = AdvancedWifiAnalyzer(args.interface, args.output)
    analyzer.start(args.count)

if __name__ == "__main__":
    main()