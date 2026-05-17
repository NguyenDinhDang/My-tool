#!/usr/bin/env python3
"""
Advanced Web Security Scanner - Công cụ kiểm thử bảo mật nâng cao
CHỈ sử dụng cho website của bạn hoặc có được phép rõ ràng!
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
import re
from bs4 import BeautifulSoup
import argparse
from colorama import Fore, Style, init
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore')

init(autoreset=True)

class AdvancedWebScanner:
    def __init__(self, target_url, threads=5):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Security Scanner'
        })
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.threads = threads
        
    def banner(self):
        print(f"""{Fore.CYAN}
╔══════════════════════════════════════════╗
║  Advanced Web Security Scanner v2.0      ║
║  Chỉ dùng cho mục đích hợp pháp          ║
╚══════════════════════════════════════════╝
{Style.RESET_ALL}""")
        
    def crawl_website(self, max_pages=50):
        """Crawl website để tìm tất cả URLs"""
        print(f"\n{Fore.YELLOW}[*] Đang crawl website (max {max_pages} trang)...")
        
        to_crawl = [self.target_url]
        crawled = set()
        
        while to_crawl and len(crawled) < max_pages:
            url = to_crawl.pop(0)
            if url in crawled:
                continue
                
            try:
                response = self.session.get(url, timeout=5, verify=False)
                crawled.add(url)
                self.crawled_urls.add(url)
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Tìm tất cả links
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    parsed = urlparse(full_url)
                    
                    if parsed.netloc == self.domain and full_url not in crawled:
                        to_crawl.append(full_url)
                        
            except Exception as e:
                pass
                
        print(f"{Fore.GREEN}[✓] Crawled {len(crawled)} trang")
        return list(crawled)
    
    def check_ssl_advanced(self):
        """Kiểm tra SSL/TLS chi tiết"""
        print(f"\n{Fore.YELLOW}[*] Kiểm tra SSL/TLS nâng cao...")
        
        try:
            if not self.target_url.startswith('https://'):
                self.vulnerabilities.append({
                    'type': 'SSL',
                    'severity': 'HIGH',
                    'detail': 'Website không sử dụng HTTPS - Dữ liệu truyền không mã hóa'
                })
                print(f"{Fore.RED}[!] CRITICAL: Không dùng HTTPS")
                return
            
            # Kiểm tra redirect HTTP -> HTTPS
            http_url = self.target_url.replace('https://', 'http://')
            try:
                resp = requests.get(http_url, allow_redirects=False, timeout=5)
                if resp.status_code not in [301, 302, 307, 308]:
                    self.vulnerabilities.append({
                        'type': 'SSL',
                        'severity': 'MEDIUM',
                        'detail': 'HTTP không tự động redirect sang HTTPS'
                    })
                    print(f"{Fore.YELLOW}[!] Không có HTTP->HTTPS redirect")
                else:
                    print(f"{Fore.GREEN}[✓] HTTP redirect sang HTTPS")
            except:
                pass
                
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi: {e}")
    
    def check_security_headers_advanced(self):
        """Kiểm tra security headers chi tiết"""
        print(f"\n{Fore.YELLOW}[*] Kiểm tra Security Headers chi tiết...")
        
        try:
            response = self.session.get(self.target_url, timeout=5, verify=False)
            headers = response.headers
            
            # Headers quan trọng với giải thích
            critical_headers = {
                'Strict-Transport-Security': {
                    'desc': 'HSTS - Bắt buộc HTTPS',
                    'severity': 'HIGH',
                    'recommendation': 'max-age=31536000; includeSubDomains'
                },
                'Content-Security-Policy': {
                    'desc': 'CSP - Ngăn XSS, injection attacks',
                    'severity': 'HIGH',
                    'recommendation': "default-src 'self'"
                },
                'X-Frame-Options': {
                    'desc': 'Chống Clickjacking',
                    'severity': 'MEDIUM',
                    'recommendation': 'DENY hoặc SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'desc': 'Ngăn MIME sniffing',
                    'severity': 'MEDIUM',
                    'recommendation': 'nosniff'
                },
                'Referrer-Policy': {
                    'desc': 'Kiểm soát thông tin referrer',
                    'severity': 'LOW',
                    'recommendation': 'strict-origin-when-cross-origin'
                },
                'Permissions-Policy': {
                    'desc': 'Kiểm soát browser features',
                    'severity': 'LOW',
                    'recommendation': 'geolocation=(), microphone=()'
                }
            }
            
            for header, info in critical_headers.items():
                if header not in headers:
                    self.vulnerabilities.append({
                        'type': 'Security Headers',
                        'severity': info['severity'],
                        'detail': f"Thiếu {header} - {info['desc']}",
                        'recommendation': f"Thêm: {header}: {info['recommendation']}"
                    })
                    print(f"{Fore.RED}[!] Thiếu: {header}")
                else:
                    print(f"{Fore.GREEN}[✓] Có: {header} = {headers[header][:50]}")
            
            # Kiểm tra headers nguy hiểm
            dangerous_headers = {
                'Server': 'Tiết lộ thông tin server',
                'X-Powered-By': 'Tiết lộ công nghệ backend'
            }
            
            for header, desc in dangerous_headers.items():
                if header in headers:
                    self.vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'LOW',
                        'detail': f"Header {header} tiết lộ: {headers[header]} - {desc}"
                    })
                    print(f"{Fore.YELLOW}[!] Phát hiện: {header}: {headers[header]}")
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi: {e}")
    
    def check_xss_advanced(self):
        """Kiểm tra XSS nâng cao với nhiều payloads"""
        print(f"\n{Fore.YELLOW}[*] Kiểm tra XSS nâng cao...")
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '\'><script>alert(String.fromCharCode(88,83,83))</script>',
            '<ScRiPt>alert("XSS")</ScRiPt>',
        ]
        
        tested_forms = 0
        
        for url in list(self.crawled_urls)[:10]:  # Test top 10 URLs
            try:
                response = self.session.get(url, timeout=5, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms[:2]:  # Test 2 forms per page
                    tested_forms += 1
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    inputs = form.find_all(['input', 'textarea'])
                    
                    full_action = urljoin(url, action)
                    
                    for payload in xss_payloads[:3]:  # Test 3 payloads
                        data = {}
                        for input_field in inputs:
                            name = input_field.get('name')
                            input_type = input_field.get('type', 'text')
                            if name and input_type not in ['submit', 'button']:
                                data[name] = payload
                        
                        if not data:
                            continue
                            
                        try:
                            if method == 'post':
                                test_response = self.session.post(full_action, data=data, timeout=5, verify=False)
                            else:
                                test_response = self.session.get(full_action, params=data, timeout=5, verify=False)
                            
                            # Kiểm tra reflection
                            if payload in test_response.text and '<' in test_response.text:
                                self.vulnerabilities.append({
                                    'type': 'XSS',
                                    'severity': 'CRITICAL',
                                    'detail': f'Reflected XSS tại {full_action}',
                                    'payload': payload,
                                    'recommendation': 'Sanitize và encode tất cả user input'
                                })
                                print(f"{Fore.RED}[!] XSS DETECTED: {full_action[:60]}")
                                break
                        except:
                            pass
                            
            except Exception as e:
                pass
        
        print(f"{Fore.BLUE}[i] Đã test {tested_forms} forms")
    
    def check_sql_injection_advanced(self):
        """Kiểm tra SQL Injection nâng cao"""
        print(f"\n{Fore.YELLOW}[*] Kiểm tra SQL Injection nâng cao...")
        
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND '1'='2",
            "1' WAITFOR DELAY '0:0:5'--",
            "' OR 1=1--",
            "' OR 'x'='x",
            "1'; DROP TABLE users--",
        ]
        
        sql_errors = [
            'SQL syntax',
            'mysql_fetch',
            'num_rows',
            'ORA-01756',
            'PostgreSQL',
            'Microsoft SQL',
            'ODBC SQL',
            'SQLite',
            'Warning: mysql',
            'valid MySQL result',
            'MySqlClient',
            'com.mysql.jdbc',
            'org.postgresql',
            'Unclosed quotation',
            'quoted string not properly terminated',
        ]
        
        tested_params = 0
        
        for url in list(self.crawled_urls)[:15]:
            parsed = urlparse(url)
            if not parsed.query:
                continue
                
            params = parse_qs(parsed.query)
            
            for param_name in list(params.keys())[:3]:
                tested_params += 1
                for payload in sql_payloads[:3]:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    try:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        response = self.session.get(test_url, params=test_params, timeout=5, verify=False)
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                self.vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'CRITICAL',
                                    'detail': f'SQLi tại param "{param_name}" in {url[:60]}',
                                    'error_found': error,
                                    'payload': payload,
                                    'recommendation': 'Sử dụng Prepared Statements/Parameterized Queries'
                                })
                                print(f"{Fore.RED}[!] SQLi DETECTED: {param_name} in {url[:50]}")
                                break
                    except:
                        pass
        
        print(f"{Fore.BLUE}[i] Đã test {tested_params} parameters")
    
    def check_sensitive_files(self):
        """Kiểm tra các file/thư mục nhạy cảm"""
        print(f"\n{Fore.YELLOW}[*] Kiểm tra files/directories nhạy cảm...")
        
        sensitive_paths = [
            # Admin panels
            '/admin', '/admin.php', '/administrator', '/wp-admin', '/phpmyadmin',
            '/admin/login', '/admin/login.php', '/login', '/login.php',
            # Backup files
            '/backup', '/backups', '/.backup', '/db_backup', 
            '/backup.sql', '/database.sql', '/dump.sql',
            # Config files
            '/.env', '/config.php', '/configuration.php', '/settings.php',
            '/wp-config.php', '/.git/config', '/.svn/entries',
            # Info disclosure
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            '/.git', '/.svn', '/.DS_Store', '/web.config',
            # Directories
            '/uploads', '/images', '/files', '/documents', '/assets',
            '/tmp', '/temp', '/cache', '/logs',
        ]
        
        found_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for path in sensitive_paths:
                url = urljoin(self.target_url, path)
                future = executor.submit(self._check_url_exists, url)
                futures[future] = (url, path)
            
            for future in as_completed(futures):
                url, path = futures[future]
                try:
                    exists, status, indicators = future.result()
                    if exists:
                        found_count += 1
                        severity = 'CRITICAL' if any(x in path for x in ['.env', '.git', 'config', 'backup', 'sql']) else 'MEDIUM'
                        self.vulnerabilities.append({
                            'type': 'Sensitive Files',
                            'severity': severity,
                            'detail': f'Phát hiện: {path} (Status: {status})',
                            'indicators': indicators,
                            'recommendation': 'Hạn chế truy cập hoặc xóa file/thư mục'
                        })
                        print(f"{Fore.RED}[!] Found: {path} [{status}]")
                except:
                    pass
        
        print(f"{Fore.BLUE}[i] Tìm thấy {found_count} sensitive paths")
    
    def _check_url_exists(self, url):
        """Helper để kiểm tra URL có tồn tại không"""
        try:
            response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)
            status = response.status_code
            
            if status == 200:
                indicators = []
                text_lower = response.text.lower()
                
                if 'index of' in text_lower:
                    indicators.append('Directory listing')
                if len(response.text) > 100:
                    indicators.append('Has content')
                if 'login' in text_lower or 'password' in text_lower:
                    indicators.append('Login page')
                    
                return True, status, indicators
            elif status in [301, 302, 307]:
                return True, status, ['Redirect']
            elif status == 403:
                return True, status, ['Forbidden - exists but blocked']
                
        except:
            pass
        return False, None, []
    
    def check_cors_misconfiguration(self):
        """Kiểm tra CORS misconfiguration"""
        print(f"\n{Fore.YELLOW}[*] Kiểm tra CORS configuration...")
        
        dangerous_origins = [
            'https://evil.com',
            'null',
            'http://localhost',
        ]
        
        for origin in dangerous_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(self.target_url, headers=headers, timeout=5, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin or acao == '*':
                    severity = 'CRITICAL' if acac == 'true' else 'HIGH'
                    self.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'severity': severity,
                        'detail': f'CORS cho phép origin: {origin}',
                        'headers': f'ACAO: {acao}, ACAC: {acac}',
                        'recommendation': 'Chỉ cho phép trusted origins'
                    })
                    print(f"{Fore.RED}[!] CORS misconfigured: allows {origin}")
            except:
                pass
    
    def check_subdomain_takeover(self):
        """Kiểm tra khả năng subdomain takeover"""
        print(f"\n{Fore.YELLOW}[*] Kiểm tra Subdomain Takeover...")
        
        takeover_signatures = {
            'github.io': 'There isn\'t a GitHub Pages site here',
            'herokuapp.com': 'No such app',
            'amazonaws.com': 'NoSuchBucket',
            'azurewebsites.net': 'Error 404',
            'cloudfront.net': 'Bad request',
        }
        
        try:
            response = self.session.get(self.target_url, timeout=5, verify=False)
            
            for service, signature in takeover_signatures.items():
                if service in self.domain.lower() and signature.lower() in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Subdomain Takeover',
                        'severity': 'CRITICAL',
                        'detail': f'Có thể bị subdomain takeover qua {service}',
                        'signature': signature,
                        'recommendation': 'Xóa DNS record hoặc claim lại service'
                    })
                    print(f"{Fore.RED}[!] TAKEOVER RISK: {service}")
        except:
            pass
    
    def generate_detailed_report(self):
        """Tạo báo cáo chi tiết"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}BÁO CÁO AUDIT BẢO MẬT CHI TIẾT")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        print(f"{Fore.WHITE}Target: {self.target_url}")
        print(f"Crawled: {len(self.crawled_urls)} pages")
        print(f"Total Issues: {len(self.vulnerabilities)}\n")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[✓] Không phát hiện lỗ hổng rõ ràng")
            return
        
        # Nhóm theo severity
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for vuln in self.vulnerabilities:
            by_severity[vuln['severity']].append(vuln)
        
        severity_colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE
        }
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            vulns = by_severity[severity]
            if vulns:
                color = severity_colors[severity]
                print(f"\n{color}{'='*60}")
                print(f"{severity} ({len(vulns)} issues)")
                print(f"{'='*60}{Style.RESET_ALL}")
                
                for i, vuln in enumerate(vulns, 1):
                    print(f"\n{color}[{i}] {vuln['type']}")
                    print(f"    {vuln['detail']}")
                    if 'recommendation' in vuln:
                        print(f"{Fore.CYAN}    → Fix: {vuln['recommendation']}")
                    if 'payload' in vuln:
                        print(f"{Fore.YELLOW}    → Payload: {vuln['payload'][:50]}")
        
        # Tổng kết
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"TỔNG KẾT")
        print(f"{'='*60}")
        print(f"{Fore.RED}Critical: {len(by_severity['CRITICAL'])}")
        print(f"{Fore.RED}High: {len(by_severity['HIGH'])}")
        print(f"{Fore.YELLOW}Medium: {len(by_severity['MEDIUM'])}")
        print(f"{Fore.BLUE}Low: {len(by_severity['LOW'])}")
        
        # Export JSON
        json_file = 'security_report.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.target_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'crawled_urls': list(self.crawled_urls),
                'vulnerabilities': self.vulnerabilities,
                'summary': {
                    'critical': len(by_severity['CRITICAL']),
                    'high': len(by_severity['HIGH']),
                    'medium': len(by_severity['MEDIUM']),
                    'low': len(by_severity['LOW'])
                }
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.GREEN}[✓] Báo cáo JSON đã lưu: {json_file}")
    
    def full_scan(self):
        """Chạy full scan"""
        self.banner()
        print(f"{Fore.GREEN}[*] Target: {self.target_url}")
        print(f"{Fore.GREEN}[*] Threads: {self.threads}\n")
        
        start_time = time.time()
        
        # Crawl
        self.crawl_website(max_pages=30)
        
        # Run all checks
        self.check_ssl_advanced()
        self.check_security_headers_advanced()
        self.check_cors_misconfiguration()
        self.check_subdomain_takeover()
        self.check_sensitive_files()
        self.check_xss_advanced()
        self.check_sql_injection_advanced()
        
        elapsed = time.time() - start_time
        
        # Report
        self.generate_detailed_report()
        
        print(f"\n{Fore.CYAN}Thời gian scan: {elapsed:.2f}s")
        print(f"{Fore.YELLOW}\n⚠  CHÚ Ý: Đây là scan tự động, cần kiểm tra thủ công để xác nhận!")

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Security Scanner')
    parser.add_argument('url', help='URL của website (VD: https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Số threads (default: 5)')
    
    args = parser.parse_args()
    
    print(f"{Fore.RED}\n{'='*60}")
    print(f"⚠  CẢNH BÁO PHÁP LÝ")
    print(f"{'='*60}")
    print(f"{Fore.YELLOW}Công cụ này CHỈ được sử dụng cho:")
    print(f"  1. Website của bạn")
    print(f"  2. Website mà bạn có GIẤY PHÉP kiểm thử")
    print(f"{Fore.RED}\nSử dụng trái phép là PHẠM TỘI!\n")
    
    confirm = input(f"{Fore.CYAN}Tôi có quyền hợp pháp để scan website này (yes/no): ")
    if confirm.lower() != 'yes':
        print(f"{Fore.RED}Đã hủy.")
        return
    
    scanner = AdvancedWebScanner(args.url, threads=args.threads)
    scanner.full_scan()

if __name__ == "__main__":
    main()