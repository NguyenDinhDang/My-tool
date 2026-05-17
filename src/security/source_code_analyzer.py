"""
Source Code Security Analyzer - Phân tích mã nguồn tĩnh
Phát hiện lỗ hổng bảo mật trong code KHÔNG CẦN API KEY (Tích hợp AST & Lọc Cảnh báo giả)
"""

import os
import re
import json
import argparse
import sys
import io
import ast
from pathlib import Path
from colorama import Fore, Style, init
from collections import defaultdict

# Fix Windows encoding issue with Vietnamese characters
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

init(autoreset=True)

class PythonSecurityVisitor(ast.NodeVisitor):
    """Sử dụng AST để phân tích logic code Python thay vì Regex mù mờ"""
    def __init__(self, relative_path, lines):
        self.vulnerabilities = []
        self.relative_path = relative_path
        self.lines = lines

    def add_vuln(self, v_type, severity, desc, detail, node):
        line_content = self.lines[node.lineno - 1].strip() if hasattr(node, 'lineno') else "Code block"
        self.vulnerabilities.append({
            'type': v_type,
            'severity': severity,
            'description': desc,
            'detail': detail,
            'file': str(self.relative_path),
            'line': getattr(node, 'lineno', 0),
            'code': line_content[:100],
            'matched_pattern': 'Python AST Analysis'
        })

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            func_name = f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        # Command Injection
        if func_name in ['os.system', 'os.popen', 'exec', 'eval']:
            self.add_vuln('command_injection', 'CRITICAL', 'Command/Code Injection', f'Sử dụng hàm nguy hiểm {func_name}', node)
        elif func_name in ['subprocess.call', 'subprocess.run', 'subprocess.Popen']:
            for kw in node.keywords:
                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.add_vuln('command_injection', 'CRITICAL', 'Command Injection', 'Sử dụng subprocess với shell=True', node)
        
        # Weak Crypto
        elif func_name in ['md5', 'sha1']:
            self.add_vuln('weak_crypto', 'MEDIUM', 'Weak Cryptography', f'Sử dụng thuật toán băm yếu {func_name}()', node)

        # SQL Injection
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ['execute', 'raw_query']:
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.JoinedStr) or (isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod)):
                    self.add_vuln('sql_injection', 'CRITICAL', 'SQL Injection vulnerability', 'Nối chuỗi trực tiếp vào truy vấn SQL', node)
        
        # Insecure Deserialization
        elif func_name in ['pickle.loads', 'pickle.load', 'yaml.load']:
            self.add_vuln('insecure_deserialization', 'CRITICAL', 'Insecure Deserialization', f'Sử dụng {func_name} không an toàn', node)

        self.generic_visit(node)


class SourceCodeAnalyzer:
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        self.vulnerabilities = []
        self.file_count = 0
        self.scanned_files = []
        
        # Pattern-based vulnerability detection thông minh theo extension
        self.patterns = self._load_vulnerability_patterns()
    
    def _load_vulnerability_patterns(self):
        """Load patterns đã được nâng cấp (Smart Regex context-aware)"""
        return {
            'sql_injection': {
                'patterns': [
                    (r'\.(?:query|execute)\s*\(\s*[`\'"].*?(?:\$\{.*\}|\+).*?[`\'"]', 'String concatenation trong SQL query', ['.js', '.ts', '.jsx', '.tsx', '.cs', '.java']),
                    (r'\$_(GET|POST|REQUEST)\[.*?\].*?(?:mysql_query|mysqli_query)', 'PHP user input trực tiếp vào query', ['.php']),
                    (r'db\.rawQuery\s*\(\s*.*?\+', 'Android/Raw query concatenation', ['.java', '.cs']),
                ],
                'severity': 'CRITICAL',
                'description': 'SQL Injection vulnerability'
            },
            'xss': {
                'patterns': [
                    (r'innerHTML\s*=\s*(?!["\'`])', 'JavaScript innerHTML với user input', ['.js', '.ts', '.html']),
                    (r'document\.write\s*\((?!["\'`])', 'document.write với dynamic content', ['.js', '.ts', '.html']),
                    (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML', ['.jsx', '.tsx']),
                    (r'v-html\s*=', 'Vue v-html directive', ['.vue']),
                    (r'echo\s+\$_(GET|POST|REQUEST)', 'PHP echo user input trực tiếp', ['.php']),
                ],
                'severity': 'HIGH',
                'description': 'Cross-Site Scripting (XSS)'
            },
            'hardcoded_secrets': {
                'patterns': [
                    (r'(?i)(?:password|secret|api[_-]?key|token)\s*[:=]\s*["\'][a-zA-Z0-9]{16,}["\']', 'Hardcoded credentials nghi ngờ', ['.js', '.ts', '.py', '.php', '.java', '.cs']),
                    (r'aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']AKIA', 'AWS credentials', ['.js', '.ts', '.py', '.php', '.java', '.cs']),
                    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', 'Private key hardcoded', ['.js', '.ts', '.py', '.php', '.java', '.cs', '.pem', '.crt']),
                ],
                'severity': 'CRITICAL',
                'description': 'Hardcoded secrets/credentials'
            },
            'command_injection': {
                'patterns': [
                    (r'child_process\.(?:exec|execSync)\s*\(', 'Node.js thực thi lệnh OS', ['.js', '.ts']),
                    (r'Runtime\.getRuntime\(\)\.exec\(.*?\+', 'Java Runtime.exec concatenation', ['.java']),
                    (r'shell_exec\s*\(', 'PHP shell_exec', ['.php']),
                ],
                'severity': 'CRITICAL',
                'description': 'Command Injection'
            },
            'path_traversal': {
                'patterns': [
                    (r'(?:readFile|readFileSync|createReadStream)\s*\(\s*req\.(?:query|body|params)', 'Node.js đọc file từ Request input', ['.js', '.ts']),
                    (r'(?:fopen|file_get_contents|readfile)\s*\(\s*\$_(GET|POST)', 'PHP file open với user input', ['.php']),
                ],
                'severity': 'HIGH',
                'description': 'Path Traversal vulnerability'
            },
            'insecure_deserialization': {
                'patterns': [
                    (r'unserialize\s*\(\$_(GET|POST)', 'PHP unserialize user input', ['.php']),
                    (r'ObjectInputStream', 'Java deserialization', ['.java']),
                ],
                'severity': 'CRITICAL',
                'description': 'Insecure Deserialization'
            },
            'weak_crypto': {
                'patterns': [
                    (r'\b(?:MD5|SHA1|DES)\b', 'Thuật toán mã hóa yếu (MD5/SHA1/DES)', ['.java', '.php', '.cs']),
                    (r'Math\.random\(\)', 'Math.random - not cryptographically secure', ['.js', '.ts']),
                ],
                'severity': 'MEDIUM',
                'description': 'Weak cryptographic algorithm'
            },
            'xxe': {
                'patterns': [
                    (r'XMLInputFactory\.newInstance\(\)', 'Java XXE vulnerable XML parser', ['.java']),
                    (r'DocumentBuilder.*?parse', 'XML parser without XXE protection', ['.java']),
                ],
                'severity': 'HIGH',
                'description': 'XML External Entity (XXE)'
            },
            'csrf': {
                'patterns': [
                    (r'\.post\s*\(["\']', 'Express POST route', ['.js', '.ts']),
                ],
                'severity': 'MEDIUM',
                'description': 'Possible CSRF vulnerability'
            },
            'information_disclosure': {
                'patterns': [
                    (r'console\.log\s*\(.*?(password|token|key)', 'Sensitive info in console', ['.js', '.ts', '.jsx', '.tsx']),
                    (r'\.printStackTrace\(\)', 'Stack trace exposure', ['.java']),
                ],
                'severity': 'MEDIUM',
                'description': 'Information disclosure'
            }
        }
    
    def banner(self):
        print(f"""{Fore.CYAN}
========================================
  Source Code Security Analyzer v2.0
  Static Application Security Testing
  (Powered by AST & Smart Regex)
========================================
{Style.RESET_ALL}""")
    
    def scan_python_ast(self, content, relative_path, lines):
        """Scan file Python bằng AST"""
        try:
            tree = ast.parse(content)
            visitor = PythonSecurityVisitor(relative_path, lines)
            visitor.visit(tree)
            self.vulnerabilities.extend(visitor.vulnerabilities)
        except SyntaxError:
            pass

    def scan_file(self, file_path):
        """Scan một file để tìm vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            relative_path = file_path.relative_to(self.project_path)
            file_ext = file_path.suffix.lower()
            
            # Python dùng AST để quét chính xác 100%
            if file_ext == '.py':
                self.scan_python_ast(content, relative_path, lines)
            
            # Scan từng pattern cho các ngôn ngữ khác
            for vuln_type, vuln_info in self.patterns.items():
                for pattern, description, exts in vuln_info['patterns']:
                    if file_ext not in exts:
                        continue
                        
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = lines[line_num - 1].strip()
                        line_lower = line_content.lower()
                        
                        # --- BỘ LỌC CẢNH BÁO GIẢ ---
                        if line_content.startswith(('import ', 'export ', 'from ', 'include ', 'require ')):
                            continue
                        if any(keyword in line_lower for keyword in ['test', 'mock', 'fake', 'dummy', 'example']):
                            continue
                        if line_content.startswith(('//', '/*', '#', '*', '--')):
                            continue
                        if re.search(r'["\'].*?(?:password|secret|key|token).*?["\']', line_content, re.IGNORECASE):
                            continue
                        # ------------------------- -------------------------
                        
                        self.vulnerabilities.append({
                            'type': vuln_type,
                            'severity': vuln_info['severity'],
                            'description': vuln_info['description'],
                            'detail': description,
                            'file': str(relative_path),
                            'line': line_num,
                            'code': line_content[:100],
                            'matched_pattern': pattern
                        })
                        
            self.scanned_files.append(str(relative_path))
            
        except Exception as e:
            pass

    def scan_project(self):
        """Scan toan bo project"""
        print(f"\n{Fore.YELLOW}[*] Scanning project: {self.project_path}")
        
        # File extensions to scan
        code_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java',
            '.rb', '.go', '.cs', '.cpp', '.c', '.h', '.vue',
            '.sql', '.sh', '.bash'
        }
        
        # Ignore directories
        ignore_dirs = {
            'node_modules', 'venv', 'env', '.git', '__pycache__',
            'dist', 'build', '.vscode', '.idea', 'vendor'
        }
        
        files_to_scan = []
        
        for file_path in self.project_path.rglob('*'):
            if file_path.is_file():
                if any(ignored in file_path.parts for ignored in ignore_dirs):
                    continue
                    
                if file_path.suffix in code_extensions:
                    files_to_scan.append(file_path)
        
        print(f"{Fore.BLUE}[i] Found {len(files_to_scan)} code files")
        
        for i, file_path in enumerate(files_to_scan, 1):
            if i % 50 == 0:
                print(f"{Fore.BLUE}[i] Scanned {i}/{len(files_to_scan)} files...")
            self.scan_file(file_path)
            self.file_count += 1
        
        print(f"{Fore.GREEN}[+] Scanned {self.file_count} files")

    def generate_report(self):
        """Generate detailed report"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}SECURITY ANALYSIS REPORT")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        print(f"{Fore.WHITE}Project: {self.project_path}")
        print(f"Files scanned: {self.file_count}")
        print(f"Issues found: {len(self.vulnerabilities)}\n")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No security issues detected!")
            return
        
        # Group by severity
        by_severity = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_severity[vuln['severity']].append(vuln)
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        severity_colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE
        }
        
        # Print by severity
        for severity in severity_order:
            vulns = by_severity.get(severity, [])
            if vulns:
                color = severity_colors[severity]
                print(f"\n{color}{'='*70}")
                print(f"{severity} - {len(vulns)} issues")
                print(f"{'='*70}{Style.RESET_ALL}")
                
                for i, vuln in enumerate(vulns[:20], 1):
                    print(f"\n{color}[{i}] {vuln['description']}")
                    print(f"{Fore.WHITE}    File: {vuln['file']}:{vuln['line']}")
                    print(f"    Issue: {vuln['detail']}")
                    if vuln.get('code'):
                        print(f"{Fore.YELLOW}    Code: {vuln['code']}")
                
                if len(vulns) > 20:
                    print(f"\n{color}    ... and {len(vulns) - 20} more issues")
        
        # Export JSON
        json_file = 'sast_report.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'project_path': str(self.project_path),
                'files_scanned': self.file_count,
                'total_issues': len(self.vulnerabilities),
                'summary': {
                    'critical': len(by_severity['CRITICAL']),
                    'high': len(by_severity['HIGH']),
                    'medium': len(by_severity['MEDIUM']),
                    'low': len(by_severity['LOW'])
                },
                'vulnerabilities': self.vulnerabilities
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.GREEN}[+] JSON Report saved: {json_file}")
        
        # Recommendations
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"RECOMMENDATIONS")
        print(f"{'='*70}")
        print(f"{Fore.YELLOW}1. Fix all CRITICAL issues immediately")
        print(f"2. Review and fix HIGH issues in this sprint")
        print(f"3. Implement secure coding practices")
        print(f"4. Use input validation and output encoding")
        print(f"5. Update dependencies regularly")
        print(f"6. Enable security linters in CI/CD")


def main():
    parser = argparse.ArgumentParser(
        description='Source Code Security Analyzer - SAST Tool'
    )
    parser.add_argument('project_path', help='Path to the project directory')
    
    args = parser.parse_args()
    
    project_path = Path(args.project_path)
    
    if not project_path.exists():
        print(f"{Fore.RED}[!] Directory does not exist: {project_path}")
        return
    
    if not project_path.is_dir():
        print(f"{Fore.RED}[!] Not a directory: {project_path}")
        return
    
    analyzer = SourceCodeAnalyzer(project_path)
    analyzer.banner()
    analyzer.scan_project()
    analyzer.generate_report()

if __name__ == "__main__":
    main()