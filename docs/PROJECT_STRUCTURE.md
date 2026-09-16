# Project Architecture & Directory Structure

```text
.
|-- README.md                   # Tài liệu giới thiệu, hướng dẫn sử dụng & Legal Disclaimer
|-- LICENSE                     # Giấy phép mã nguồn mở MIT (Tác giả: Đặng Đình Nguyên)
|-- requirements.txt            # Danh sách thư viện phụ thuộc của toàn bộ dự án
|-- .gitignore                  # Cấu hình loại trừ cache, cơ sở dữ liệu và dữ liệu nhạy cảm
|-- toolkit.py                  # CLI Launcher cho các công cụ tự động hóa & chuyển đổi tài liệu
|-- security_scanner.py         # All-in-One Web Security Scanner (Hợp nhất 6 Phase an ninh)
|
|-- network/                    # BỘ CÔNG CỤ PHÂN TÍCH MẠNG & WIFI (LAB ONLY)
|   |-- __init__.py
|   |-- advanced_techniques.py  # Phát hiện ARP Poisoning, SSL/TLS, Port Scan, DNS Tunneling
|   |-- advanced_wifi_analyzer.py # Bắt và phân tích gói tin mạng WiFi (Yêu cầu Npcap trên Windows)
|   `-- demo_wifi.py            # Mô phỏng phân loại gói tin mạng nội bộ an toàn
|
|-- app_security/               # BỘ CÔNG CỤ AN NINH ỨNG DỤNG (SAST & DAST)
|   |-- __init__.py
|   |-- source_code_analyzer.py # Phân tích tĩnh mã nguồn (SAST) phát hiện SQLi, Secrets, XSS...
|   `-- web_security_scanner.py # Launcher cho Web Security Scanner engine
|
|-- system/                     # BỘ CÔNG CỤ AN NINH HỆ THỐNG & ENDPOINT
|   |-- __init__.py
|   `-- usb_scanner_windows.py  # Quét an ninh ổ đĩa USB trên Windows tích hợp Defender Engine
|
|-- core/                       # Core Engine của Web Security Scanner
|   |-- config.py               # Quản lý cấu hình quét, scope, timeout, request budget
|   |-- scope.py                # Kiểm soát chặt chẽ URL trong phạm vi cho phép
|   |-- rate_limiter.py         # Bộ đếm request toàn cục & giới hạn tốc độ (RPS)
|   |-- http_client.py          # HTTP Client an toàn (mask secret, stream size limit)
|   |-- request.py              # Data model Request
|   `-- response.py             # Data model Response (kèm cookies, headers, redirect chain)
|
|-- crawler/                    # Thu thập bề mặt tấn công (BFS Crawler đa tầng)
|   |-- crawler.py              # Bộ điều phối thu thập liên kết tự động
|   |-- parser.py               # Trích xuất URL, HTML forms, input parameters
|   |-- js_discovery.py         # Phân tích tĩnh file JavaScript tìm endpoint ẩn
|   `-- endpoint_discovery.py   # Thăm dò các file thông dụng (robots.txt, sitemap.xml)
|
|-- fingerprint/                # Nhận diện công nghệ và máy chủ mục tiêu
|   |-- server.py               # Nhận diện Web Server (Nginx, Apache, Werkzeug, IIS...)
|   |-- technology.py           # Nhận diện ngôn ngữ & thư viện (PHP, Python, ASP.NET...)
|   `-- framework.py            # Nhận diện Framework (Flask, Django, Express, Laravel...)
|
|-- models/                     # Mô hình dữ liệu chuẩn hóa
|   |-- endpoint.py             # Endpoint Model (url, method, params, form details)
|   |-- finding.py              # Finding Model (type, severity, evidence, remediation)
|   `-- result.py               # ScanResult Model tổng hợp và xuất báo cáo
|
|-- checks/                     # 20 module kiểm tra an ninh (Khai báo RISK_LEVEL minh bạch)
|   |-- headers.py              # [safe] Kiểm tra Security Headers
|   |-- cookies.py              # [safe] Kiểm tra Cookie Security Flags
|   |-- tls.py                  # [safe] Kiểm tra chứng chỉ HTTPS / TLS
|   |-- cors.py                 # [safe] Kiểm tra cấu hình lỏng lẻo CORS
|   |-- sensitive_files.py      # [safe] Thăm dò tệp tin nhạy cảm (.git, .env, backup...)
|   |-- information_disclosure.py # [safe] Phát hiện rò rỉ thông tin trong response
|   |-- http_methods.py         # [safe] Kiểm tra phương thức HTTP rủi ro
|   |-- xss.py                  # [safe/active] Reflected & DOM XSS (safe), Stored XSS (active)
|   |-- sqli.py                 # [safe/active] Error, Boolean, Union SQLi (safe), Time-based (active)
|   |-- nosqli.py               # [safe] NoSQL Operator Injection
|   |-- command_injection.py    # [active_only] OS Command Injection (Time delay có kiểm soát)
|   |-- traversal.py            # [active_only] Path Traversal (Whitelist safe files)
|   |-- ssrf.py                 # [active_only] SSRF (Yêu cầu --callback-url)
|   |-- redirect.py             # [active_only] Open Redirect (domain .invalid)
|   |-- csrf.py                 # [active_only] Phân tích Anti-CSRF Token
|   |-- idor.py                 # [active_only] IDOR (yêu cầu 2 phiên độc lập)
|   |-- jwt.py                  # [active_only] JWT Weak Algorithm & Expiration
|   |-- upload.py               # [active_only] File Upload Filter Testing
|   |-- api.py                  # [active_only] API & GraphQL Introspection
|   `-- rate_limit.py           # [active_only] Rate Limiting Burst Probe
|
|-- reporting/                  # Báo cáo kết quả và che dấu dữ liệu nhạy cảm
|   |-- masker.py               # Tự động mask Bearer tokens, cookies, passwords
|   |-- console.py              # Hiển thị terminal màu sắc trực quan
|   |-- json_report.py          # Xuất báo cáo định dạng JSON chuẩn
|   `-- html_report.py          # Xuất báo cáo giao diện HTML tương tác
|
|-- src/                        # Các công cụ bổ trợ
|   |-- autoFill_form.py        # Tự động điền form (Standard Selenium, không anti-detect)
|   |-- md2word.py              # Chuyển đổi Markdown sang Word (.docx)
|   |-- quickstart.py           # Wizard khởi động nhanh
|   `-- toolkit_cli.py          # CLI framework Click
|
|-- Pentest/                    # Ứng dụng web mẫu dùng cho kiểm thử cục bộ (Flask Vuln Lab)
|   |-- app.py
|   `-- templates/
|
`-- docs/                       # Tài liệu hướng dẫn chi tiết
    |-- PROJECT_STRUCTURE.md
    |-- SECURITY_TOOLS_GUIDE.txt
    `-- MERMAID_GUIDE.md
```

## Kiểm Thử Tự Động Toàn Diện (45 Tests)

```bash
# Chạy toàn bộ test suite:
pytest -v
```
