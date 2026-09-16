#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
LEGAL DISCLAIMER / TUYÊN BỐ MIỄN TRỪ TRÁCH NHIỆM PHÁP LÝ
==============================================================================
Dự án này được tạo ra ĐỘC QUYỀN vì mục đích giáo dục, nghiên cứu an toàn thông
tin và phục vụ học thuật trong môi trường phòng thí nghiệm khép kín (Local Lab).

1. Yêu cầu cấp phép: Tuyệt đối KHÔNG sử dụng công cụ này để quét, bắt gói tin,
   hoặc can thiệp vào bất kỳ hệ thống nào mà không có sự đồng ý bằng văn bản.
2. Không khuyến khích hành vi phi pháp: Nghiêm cấm mọi hành vi lạm dụng mã nguồn.
3. Miễn trừ trách nhiệm: Tác giả (Đặng Đình Nguyên) KHÔNG chịu bất kỳ trách nhiệm
   pháp lý nào đối với các thiệt hại phát sinh từ việc sử dụng công cụ này.
==============================================================================
"""

from scapy.all import *
from collections import defaultdict
import threading
import time
from datetime import datetime
import sqlite3
from colorama import Fore, init
import hashlib
import json
import re

init(autoreset=True)

class AdvancedSecurityTechniques:
    def __init__(self):
        self.techniques = {
            '1': 'ARP Cache Poisoning Detection',
            '2': 'SSL/TLS Fingerprinting',
            '3': 'OS Fingerprinting (Passive)',
            '4': 'Session Hijacking Detection',
            '5': 'DNS Tunneling Detection',
            '6': 'Port Scan Detection',
            '7': 'HTTP Parameter Pollution Detection',
            '8': 'Traffic Pattern Analysis',
            '9': 'Rogue DHCP Detection',
            '10': 'MAC Address Spoofing Detection'
        }
        
        self.arp_table = {}
        self.ssl_fingerprints = defaultdict(list)
        self.os_signatures = defaultdict(dict)
        self.tcp_sessions = defaultdict(list)
        self.dns_tunnels = defaultdict(list)
        self.port_scan_attempts = defaultdict(lambda: {'ports': set(), 'time': []})
        
    def display_menu(self):
        """Hiển thị menu techniques"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"ADVANCED NETWORK SECURITY TECHNIQUES")
        print(f"{'='*70}\n")
        
        for key, value in self.techniques.items():
            print(f"{Fore.YELLOW}{key}. {Fore.WHITE}{value}")
        
        print(f"\n{Fore.RED}0. Exit")
        print(f"{Fore.CYAN}{'='*70}\n")

# ============================================================
# 1. ARP CACHE POISONING DETECTION
# ============================================================
class ARPPoisonDetector:
    """
    Phát hiện ARP Spoofing/Poisoning
    Kỹ thuật: MITM (Man-in-the-Middle) attacks
    """
    def __init__(self):
        self.arp_table = {}
        self.suspicious_changes = []
        
    def analyze_arp(self, packet):
        """Phân tích ARP packets"""
        if packet.haslayer(ARP):
            arp = packet[ARP]
            
            # ARP Reply hoặc Gratuitous ARP
            if arp.op == 2:  # is-at (reply)
                ip = arp.psrc
                mac = arp.hwsrc
                
                # Check if IP already exists with different MAC
                if ip in self.arp_table:
                    old_mac = self.arp_table[ip]
                    if old_mac != mac:
                        self.suspicious_changes.append({
                            'timestamp': datetime.now().isoformat(),
                            'ip': ip,
                            'old_mac': old_mac,
                            'new_mac': mac,
                            'severity': 'HIGH'
                        })
                        
                        print(f"{Fore.RED}[!] ARP SPOOFING DETECTED!")
                        print(f"    IP: {ip}")
                        print(f"    Old MAC: {old_mac}")
                        print(f"    New MAC: {mac}")
                        print(f"    Possible MITM Attack!\n")
                        
                        return True
                
                self.arp_table[ip] = mac
                print(f"{Fore.GREEN}[ARP] {ip} -> {mac}")
        
        return False
    
    def start_monitoring(self, interface, duration=60):
        """Bắt đầu monitor ARP"""
        print(f"{Fore.CYAN}[*] Starting ARP Poison Detection...")
        print(f"[*] Monitoring for {duration} seconds\n")
        
        sniff(
            iface=interface,
            prn=self.analyze_arp,
            filter="arp",
            timeout=duration,
            store=0
        )
        
        print(f"\n{Fore.YELLOW}[*] Detection complete")
        print(f"[*] Suspicious changes: {len(self.suspicious_changes)}")

# ============================================================
# 2. SSL/TLS FINGERPRINTING
# ============================================================
class SSLFingerprinter:
    """
    Nhận dạng SSL/TLS handshake để fingerprint clients/servers
    Technique: JA3/JA3S fingerprinting
    """
    def __init__(self):
        self.ssl_sessions = defaultdict(dict)
        self.ja3_hashes = defaultdict(list)
        
    def extract_ja3(self, packet):
        """Extract JA3 fingerprint từ TLS ClientHello"""
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = bytes(packet[Raw].load)
                
                # Check for TLS ClientHello (0x16 0x03)
                if payload[0] == 0x16 and payload[1] == 0x03:
                    
                    # Parse TLS version
                    tls_version = f"{payload[1]}.{payload[2]}"
                    
                    # Extract cipher suites (simplified)
                    # Real implementation would parse the full TLS handshake
                    
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Create simplified fingerprint
                    fingerprint = hashlib.md5(payload[:100]).hexdigest()
                    
                    self.ja3_hashes[src_ip].append(fingerprint)
                    
                    print(f"{Fore.MAGENTA}[SSL] {src_ip} -> {dst_ip}")
                    print(f"      TLS Version: {tls_version}")
                    print(f"      Fingerprint: {fingerprint[:16]}...")
                    
                    # Detect anomalies
                    if len(set(self.ja3_hashes[src_ip])) > 5:
                        print(f"{Fore.RED}      [!] Multiple SSL fingerprints from same IP!")
                        print(f"      [!] Possible bot/scanner activity\n")
                    
            except Exception as e:
                pass
    
    def start_fingerprinting(self, interface, duration=60):
        """Bắt đầu SSL fingerprinting"""
        print(f"{Fore.CYAN}[*] Starting SSL/TLS Fingerprinting...")
        print(f"[*] Duration: {duration} seconds\n")
        
        sniff(
            iface=interface,
            prn=self.extract_ja3,
            filter="tcp port 443",
            timeout=duration,
            store=0
        )
        
        print(f"\n{Fore.YELLOW}[*] Fingerprinting complete")
        print(f"[*] Unique IPs: {len(self.ja3_hashes)}")

# ============================================================
# 3. PASSIVE OS FINGERPRINTING
# ============================================================
class OSFingerprinter:
    """
    Nhận dạng OS dựa trên network behavior (KHÔNG gửi packets)
    Dựa vào: TTL, Window Size, TCP Options
    """
    def __init__(self):
        self.os_db = {
            # TTL patterns
            64: ['Linux', 'MacOS', 'iOS', 'Android'],
            128: ['Windows'],
            255: ['Cisco', 'Network Device'],
            
            # Window Size patterns (simplified)
        }
        
        self.detected_os = defaultdict(lambda: {
            'ttl': None,
            'window_size': None,
            'options': [],
            'likely_os': 'Unknown'
        })
    
    def analyze_packet(self, packet):
        """Phân tích packet để fingerprint OS"""
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            ttl = packet[IP].ttl
            
            if packet[TCP].flags & 0x02:  # SYN packet
                window_size = packet[TCP].window
                
                # Determine OS based on TTL
                likely_os = "Unknown"
                if ttl <= 64:
                    likely_os = "Linux/Unix/Mac"
                elif ttl <= 128:
                    likely_os = "Windows"
                elif ttl > 200:
                    likely_os = "Network Device"
                
                # Store fingerprint
                self.detected_os[src_ip] = {
                    'ttl': ttl,
                    'window_size': window_size,
                    'likely_os': likely_os,
                    'timestamp': datetime.now()
                }
                
                print(f"{Fore.CYAN}[OS] {src_ip}")
                print(f"     TTL: {ttl} | Window: {window_size}")
                print(f"     Likely OS: {Fore.YELLOW}{likely_os}\n")
    
    def start_fingerprinting(self, interface, duration=60):
        """Bắt đầu OS fingerprinting"""
        print(f"{Fore.CYAN}[*] Starting Passive OS Fingerprinting...")
        print(f"[*] Duration: {duration} seconds\n")
        
        sniff(
            iface=interface,
            prn=self.analyze_packet,
            filter="tcp[tcpflags] & tcp-syn != 0",
            timeout=duration,
            store=0
        )
        
        print(f"\n{Fore.YELLOW}[*] Results:")
        for ip, data in self.detected_os.items():
            print(f"  {ip}: {data['likely_os']}")

# ============================================================
# 4. SESSION HIJACKING DETECTION
# ============================================================
class SessionHijackDetector:
    """
    Phát hiện TCP Session Hijacking
    Detect: Unusual sequence numbers, duplicate ACKs
    """
    def __init__(self):
        self.tcp_sessions = defaultdict(lambda: {
            'seq_nums': [],
            'ack_nums': [],
            'last_seen': None
        })
        self.hijack_attempts = []
    
    def analyze_tcp_session(self, packet):
        """Phân tích TCP session"""
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            session_key = f"{src_ip}:{sport}-{dst_ip}:{dport}"
            
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            
            session = self.tcp_sessions[session_key]
            
            # Detect sequence number anomalies
            if session['seq_nums']:
                last_seq = session['seq_nums'][-1]
                
                # Huge jump in sequence number
                if seq < last_seq - 100000 or seq > last_seq + 100000:
                    print(f"{Fore.RED}[!] POSSIBLE SESSION HIJACK!")
                    print(f"    Session: {session_key}")
                    print(f"    Expected seq: ~{last_seq}")
                    print(f"    Received seq: {seq}")
                    print(f"    Anomaly detected!\n")
                    
                    self.hijack_attempts.append({
                        'timestamp': datetime.now(),
                        'session': session_key,
                        'expected': last_seq,
                        'received': seq
                    })
            
            # Store sequence numbers
            session['seq_nums'].append(seq)
            session['ack_nums'].append(ack)
            session['last_seen'] = datetime.now()
            
            # Keep only recent sequences
            if len(session['seq_nums']) > 100:
                session['seq_nums'] = session['seq_nums'][-100:]
                session['ack_nums'] = session['ack_nums'][-100:]
    
    def start_detection(self, interface, duration=60):
        """Bắt đầu detection"""
        print(f"{Fore.CYAN}[*] Starting Session Hijack Detection...")
        print(f"[*] Duration: {duration} seconds\n")
        
        sniff(
            iface=interface,
            prn=self.analyze_tcp_session,
            filter="tcp",
            timeout=duration,
            store=0
        )
        
        print(f"\n{Fore.YELLOW}[*] Detection complete")
        print(f"[*] Hijack attempts detected: {len(self.hijack_attempts)}")

# ============================================================
# 5. DNS TUNNELING DETECTION
# ============================================================
class DNSTunnelDetector:
    """
    Phát hiện DNS Tunneling (data exfiltration qua DNS)
    Red flags: Unusual query patterns, long domains, high entropy
    """
    def __init__(self):
        self.dns_stats = defaultdict(lambda: {
            'queries': [],
            'avg_length': 0,
            'entropy_score': 0
        })
        self.suspicious_domains = []
    
    def calculate_entropy(self, string):
        """Tính Shannon entropy"""
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
    
    def analyze_dns(self, packet):
        """Phân tích DNS queries"""
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode().rstrip('.')
            src_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'
            
            # Calculate metrics
            query_length = len(query)
            entropy = self.calculate_entropy(query)
            
            # Store stats
            stats = self.dns_stats[src_ip]
            stats['queries'].append(query)
            
            # Red flags for DNS tunneling
            suspicious = False
            reasons = []
            
            # 1. Very long subdomain
            if query_length > 60:
                suspicious = True
                reasons.append(f"Long query ({query_length} chars)")
            
            # 2. High entropy (random-looking)
            if entropy > 4.5:
                suspicious = True
                reasons.append(f"High entropy ({entropy:.2f})")
            
            # 3. Excessive queries from same IP
            if len(stats['queries']) > 50:
                suspicious = True
                reasons.append("High query rate")
            
            # 4. Suspicious TLDs
            suspicious_tlds = ['.tk', '.xyz', '.top']
            if any(query.endswith(tld) for tld in suspicious_tlds):
                suspicious = True
                reasons.append("Suspicious TLD")
            
            if suspicious:
                print(f"{Fore.RED}[!] POSSIBLE DNS TUNNEL DETECTED!")
                print(f"    Source: {src_ip}")
                print(f"    Query: {query[:50]}...")
                print(f"    Reasons: {', '.join(reasons)}\n")
                
                self.suspicious_domains.append({
                    'timestamp': datetime.now(),
                    'src_ip': src_ip,
                    'query': query,
                    'length': query_length,
                    'entropy': entropy,
                    'reasons': reasons
                })
            else:
                print(f"{Fore.GREEN}[DNS] {query}")
    
    def start_detection(self, interface, duration=60):
        """Bắt đầu detection"""
        print(f"{Fore.CYAN}[*] Starting DNS Tunnel Detection...")
        print(f"[*] Looking for: long queries, high entropy, suspicious patterns")
        print(f"[*] Duration: {duration} seconds\n")
        
        sniff(
            iface=interface,
            prn=self.analyze_dns,
            filter="udp port 53",
            timeout=duration,
            store=0
        )
        
        print(f"\n{Fore.YELLOW}[*] Detection complete")
        print(f"[*] Suspicious domains: {len(self.suspicious_domains)}")
        
        if self.suspicious_domains:
            print(f"\n{Fore.RED}Top suspicious domains:")
            for domain in self.suspicious_domains[:5]:
                print(f"  • {domain['query'][:40]}... (Entropy: {domain['entropy']:.2f})")

# ============================================================
# 6. PORT SCAN DETECTION
# ============================================================
class PortScanDetector:
    """
    Phát hiện Port Scanning
    Techniques: SYN scan, Connect scan, XMAS scan, NULL scan
    """
    def __init__(self):
        self.scan_attempts = defaultdict(lambda: {
            'ports': set(),
            'timestamps': [],
            'scan_type': None
        })
        self.alert_threshold = 10  # ports in 60 seconds
    
    def analyze_packet(self, packet):
        """Phân tích packets để detect scans"""
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            scan_data = self.scan_attempts[src_ip]
            scan_data['ports'].add(dst_port)
            scan_data['timestamps'].append(datetime.now())
            
            # Detect scan type
            scan_type = None
            if flags == 0x02:  # SYN
                scan_type = "SYN Scan"
            elif flags == 0x00:  # NULL
                scan_type = "NULL Scan"
            elif flags == 0x29:  # XMAS (FIN, PSH, URG)
                scan_type = "XMAS Scan"
            elif flags == 0x01:  # FIN
                scan_type = "FIN Scan"
            
            if scan_type:
                scan_data['scan_type'] = scan_type
            
            # Check if threshold exceeded
            recent_timestamps = [
                ts for ts in scan_data['timestamps']
                if (datetime.now() - ts).seconds < 60
            ]
            
            if len(scan_data['ports']) > self.alert_threshold:
                print(f"{Fore.RED}[!] PORT SCAN DETECTED!")
                print(f"    Source: {src_ip}")
                print(f"    Ports scanned: {len(scan_data['ports'])}")
                print(f"    Scan type: {scan_type or 'Unknown'}")
                print(f"    Ports: {sorted(list(scan_data['ports']))[:10]}...\n")
    
    def start_detection(self, interface, duration=60):
        """Bắt đầu detection"""
        print(f"{Fore.CYAN}[*] Starting Port Scan Detection...")
        print(f"[*] Alert threshold: {self.alert_threshold} ports/minute")
        print(f"[*] Duration: {duration} seconds\n")
        
        sniff(
            iface=interface,
            prn=self.analyze_packet,
            filter="tcp",
            timeout=duration,
            store=0
        )
        
        print(f"\n{Fore.YELLOW}[*] Detection complete")
        print(f"[*] Scan attempts from {len(self.scan_attempts)} IPs")

# ============================================================
# MAIN DEMO
# ============================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced Network Security Techniques Demo'
    )
    parser.add_argument('-i', '--interface', required=True,
                       help='Network interface')
    parser.add_argument('-t', '--technique', type=int, choices=range(1, 11),
                       help='Technique number (1-10)')
    parser.add_argument('-d', '--duration', type=int, default=60,
                       help='Duration in seconds')
    
    args = parser.parse_args()
    
    techniques_obj = AdvancedSecurityTechniques()
    
    if not args.technique:
        techniques_obj.display_menu()
        choice = input(f"{Fore.GREEN}Select technique (0-10): ")
        args.technique = int(choice)
    
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"Executing: {techniques_obj.techniques.get(str(args.technique), 'Unknown')}")
    print(f"{'='*70}\n")
    
    # Execute selected technique
    if args.technique == 1:
        detector = ARPPoisonDetector()
        detector.start_monitoring(args.interface, args.duration)
    
    elif args.technique == 2:
        fingerprinter = SSLFingerprinter()
        fingerprinter.start_fingerprinting(args.interface, args.duration)
    
    elif args.technique == 3:
        fingerprinter = OSFingerprinter()
        fingerprinter.start_fingerprinting(args.interface, args.duration)
    
    elif args.technique == 4:
        detector = SessionHijackDetector()
        detector.start_detection(args.interface, args.duration)
    
    elif args.technique == 5:
        detector = DNSTunnelDetector()
        detector.start_detection(args.interface, args.duration)
    
    elif args.technique == 6:
        detector = PortScanDetector()
        detector.start_detection(args.interface, args.duration)
    
    else:
        print(f"{Fore.YELLOW}Technique under development...")

if __name__ == "__main__":
    print(f"{Fore.RED}{'='*70}")
    print("⚠️  EDUCATIONAL PURPOSE ONLY")
    print("These techniques should ONLY be used in:")
    print("  • Your own lab environment")
    print("  • Networks you own")
    print("  • With explicit written permission")
    print(f"{'='*70}\n")
    
    main()