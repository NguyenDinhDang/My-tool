# Security Automation Toolkit & Defensive Security Suite

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Defensive%20%2F%20Educational-green.svg)](README.md)
[![Tests](https://img.shields.io/badge/Tests-45%20Passed-brightgreen.svg)](test_security_scanner.py)

Bộ công cụ Python chuyên nghiệp phục vụ **học tập, nghiên cứu và thực hành phòng thủ an ninh mạng (Defensive / Educational)** trong môi trường phòng thí nghiệm khép kín. Dự án cung cấp hệ thống kiểm tra an ninh toàn diện bao gồm: Web Application Security Scanner, Static Application Security Testing (SAST), Network Traffic Analysis và Endpoint/USB Security Inspection.

---

## ⚠️ Legal Disclaimer / Tuyên Bố Miễn Trừ Trách Nhiệm Pháp Lý

Dự án này được tạo ra **ĐỘC QUYỀN vì mục đích giáo dục, nghiên cứu an toàn thông tin và phục vụ học thuật trong môi trường phòng thí nghiệm khép kín (Local Lab/Virtual Environment)**.

1. **Yêu cầu cấp phép:** Tuyệt đối KHÔNG sử dụng bất kỳ công cụ hoặc kỹ thuật nào trong kho mã nguồn này để quét, bắt gói tin, kiểm tra hoặc can thiệp vào bất kỳ hệ thống, mạng lưới hoặc thiết bị nào mà không có sự đồng ý rõ ràng bằng văn bản từ chủ sở hữu hợp pháp.
2. **Không khuyến khích hành vi phi pháp:** Mọi hành vi lạm dụng mã nguồn này vào mục đích xâm nhập trái phép, phá hoại, thu thập thông tin hoặc vi phạm luật an ninh mạng tại quốc gia sở tại đều bị nghiêm cấm hoàn toàn.
3. **Miễn trừ trách nhiệm:** Tác giả (Đặng Đình Nguyên) KHÔNG chịu bất kỳ trách nhiệm pháp lý hoặc bồi thường nào đối với mọi thiệt hại, tổn thất dữ liệu, sự cố hệ thống hoặc các hậu quả pháp lý trực tiếp/gián tiếp phát sinh từ việc sử dụng hoặc lạm dụng repository này. Người dùng hoàn toàn tự chịu trách nhiệm trước pháp luật đối với mọi hành động của mình.

---

## 7 Nguyên Tắc An Toàn Bắt Buộc (Mandatory Safety Principles)

Mọi module trong hệ thống đều tuân thủ nghiêm ngặt 7 nguyên tắc an toàn:

1. **Xác nhận pháp lý bắt buộc**: Phải gõ lại chính xác domain target để xác nhận quyền kiểm thử trước khi scanner thực hiện bất kỳ kết nối nào.
2. **Safe Mode là mặc định tuyệt đối**: Khi kích hoạt, scanner luôn mặc định chạy Safe Mode (chỉ đọc, marker vô hại). Chế độ Active Mode đòi hỏi lựa chọn tường minh và xác nhận cảnh báo lần thứ 2.
3. **Global Request Budget toàn cục**: `RateLimiter` kiểm soát giới hạn request tối đa (500 ở Safe, 1500 ở Active). Khi chạm ngưỡng ngân sách, phiên quét dừng an toàn và kết xuất báo cáo mà không crash.
4. **Không tự ý hạ cấp kiểm tra**: Khi thiếu điều kiện tiên quyết (thiếu auth token, thiếu callback URL), module trả về `NOT_TESTED` thay vì thực hiện request không an toàn.
5. **Che giấu dữ liệu nhạy cảm (Secret Masking)**: Tự động lọc và che giấu Bearer tokens, cookies, JWT, API keys, credentials trong bằng chứng và báo cáo.
6. **Minh bạch cấp độ rủi ro**: Tất cả các module kiểm tra đều công khai hằng số `RISK_LEVEL = "safe"` hoặc `"active_only"`.
7. **Tuyệt đối không sử dụng Destructive Payload**: Không dùng `DROP`/`DELETE`, không reverse shell, không làm quá tải dịch vụ hay gây ảnh hưởng tới tính toàn vẹn của mục tiêu.

---

## Cấu Trúc Thư Mục Repository

```text
.
├── network/                    # Phân tích lưu lượng mạng & WiFi (Lab Only)
│   ├── advanced_techniques.py  # Phát hiện ARP Poisoning, SSL/TLS, Port Scan, DNS Tunneling
│   ├── advanced_wifi_analyzer.py # Bắt và phân tích gói tin mạng WiFi (Scapy)
│   └── demo_wifi.py            # Mô phỏng phân loại gói tin mạng nội bộ an toàn
├── app_security/               # An ninh ứng dụng (SAST & Web Security Scanner)
│   ├── source_code_analyzer.py # Phân tích tĩnh mã nguồn phát hiện SQLi, Secrets, XSS, Cmd Injection
│   └── web_security_scanner.py # Launcher cho Web Security Scanner engine
├── system/                     # An ninh hệ thống & thiết bị ngoại vi
│   └── usb_scanner_windows.py  # Quét an ninh ổ đĩa USB trên Windows tích hợp Defender Engine
├── security_scanner.py         # All-in-One Web Security Scanner (Hợp nhất toàn bộ 6 Phase)
├── core/                       # Core engine: Config, Scope, RateLimiter, HTTPClient, Request, Response
├── crawler/                    # BFS Crawler đa tầng, Form Parser, JS Discovery, Endpoint Discovery
├── fingerprint/                # Nhận diện Web Server, Ngôn ngữ, Thư viện và Framework
├── models/                     # Endpoint, Finding, ScanResult models
├── checks/                     # 20 module kiểm tra an ninh (Headers, XSS, SQLi, SSRF, JWT, API...)
├── reporting/                  # Secret Masker, Console Report, JSON & HTML Interactive Report
├── src/                        # Công cụ hỗ trợ: autoFill_form, md2word, quickstart, toolkit_cli
├── Pentest/                    # Môi trường Web Lab thử nghiệm an toàn (Flask Vuln Lab)
└── docs/                       # Tài liệu hướng dẫn chi tiết & sơ đồ kiến trúc
```

---

## Hướng Dẫn Cài Đặt

### 1. Yêu cầu hệ thống
- **Python**: Phiên bản `3.10` trở lên.
- **Hệ điều hành**: Windows 10/11, Linux (Ubuntu/Debian) hoặc macOS.

### 2. Cài đặt môi trường ảo & dependencies
```bash
# Clone repository
git clone https://github.com/NguyenDinhDang/My-tool.git
cd My-tool

# Khởi tạo môi trường ảo Python
python -m venv .venv

# Kích hoạt môi trường ảo:
# Trên Windows:
.\.venv\Scripts\activate
# Trên Linux/macOS:
source .venv/bin/activate

# Cài đặt các thư viện cần thiết
pip install -r requirements.txt
```

### ⚠️ Lưu ý đặc biệt đối với phân tích mạng trên Windows (Npcap)
Các module trong thư mục `network/` sử dụng thư viện `scapy` để bắt gói tin mạng ở tầng liên kết dữ liệu (Data Link Layer). Trên hệ điều hành Windows:
1. Bạn cần cài đặt **[Npcap](https://npcap.com/#download)**.
2. Trong quá trình cài đặt Npcap, **bắt buộc phải tick chọn**:
   - `[x] Install Npcap in WinPcap API-compatible Mode`
3. Khi chạy các script bắt gói tin mạng, hãy mở Terminal với quyền **Administrator**.

---

## Hướng Dẫn Vận Hành Từng Module

### 1. Web Security Scanner (All-in-One)
Công cụ quét an ninh web toàn diện, tự động crawl bề mặt tấn công và kiểm thử 20 hạng mục an ninh:

```bash
# Quét ứng dụng web mục tiêu (mặc định mở menu xác nhận Safe/Active Mode)
python security_scanner.py http://127.0.0.1:5000

# Hoặc khởi chạy thông qua package app_security:
python app_security/web_security_scanner.py http://127.0.0.1:5000

# Xuất báo cáo HTML và JSON tùy chọn:
python security_scanner.py http://127.0.0.1:5000 --html report.html --json report.json
```

**Quy trình xác nhận tương tác 2 bước:**
1. **Bước 1**: Nhập lại chính xác domain (ví dụ: `127.0.0.1`) để xác nhận bạn có quyền kiểm thử.
2. **Bước 2**: Lựa chọn chế độ:
   - Nhấn `1` (hoặc Enter): Kích hoạt **SAFE MODE** (chỉ thực hiện request GET, marker vô hại).
   - Nhấn `2`: Yêu cầu kích hoạt **ACTIVE MODE** (gửi payload kiểm tra Stored XSS, Time-based SQLi/Command Injection, Path Traversal; yêu cầu xác nhận lần 2 trước khi chạy).

---

### 2. Phân Tích Tĩnh Mã Nguồn (SAST - Source Code Analyzer)
Quét toàn bộ thư mục dự án để phát hiện các mẫu lỗ hổng phổ biến (SQL Injection, Command Injection, Hardcoded Secrets/Passwords, XSS, Insecure Deserialization):

```bash
# Quét thư mục hiện tại
python app_security/source_code_analyzer.py .

# Quét một thư mục dự án cụ thể
python app_security/source_code_analyzer.py ./my_project
```
*Kết quả chi tiết được lưu tự động vào `sast_report.json`.*

---

### 3. Phân Tích Mạng & WiFi (Network Analysis - Lab Only)
Các công cụ giám sát và phân tích lưu lượng mạng phòng thủ trong môi trường Lab:

```bash
# Kiểm tra khả năng bắt gói tin mạng và mô phỏng lọc traffic
python network/demo_wifi.py

# Khởi chạy bộ kỹ thuật phát hiện tấn công mạng nâng cao (ARP Spoofing, SSL Fingerprint)
python network/advanced_techniques.py

# Giám sát và phân tích gói tin WiFi theo thời gian thực (Cần quyền Admin / Npcap)
python network/advanced_wifi_analyzer.py -i "Wi-Fi"
```

---

### 4. Quét An Ninh Ổ Đĩa USB Trên Windows (Endpoint Security)
Kiểm tra các tệp tin nguy hiểm, shortcut độc hại (`.lnk`), script tự khởi chạy (`autorun.inf`) trên ổ USB và kích hoạt Windows Defender Engine quét sâu:

```bash
# Quét nhanh cấu trúc file và shortcut trên ổ USB (ví dụ ổ E:\)
python system/usb_scanner_windows.py E:\

# Quét sâu kết hợp Windows Defender Engine
python system/usb_scanner_windows.py E:\ --full
```

---

### 5. Automation Toolkit & Chuyển Đổi Tài Liệu
Bộ công cụ hỗ trợ chuyển đổi Markdown sang tài liệu Word chuyên nghiệp và tự động hóa kiểm thử:

```bash
# Xem danh sách các công cụ có sẵn
python toolkit.py info

# Chuyển đổi file Markdown (hỗ trợ Mermaid diagram, bảng, code blocks) sang file Word:
python toolkit.py md2word samples/mermaid_sample.md -o output/result.docx

# Tự động điền Google Form được chỉ định (dùng Selenium chuẩn):
python toolkit.py autofill -u "https://docs.google.com/forms/d/e/.../viewform" -n 5
```

---

## Môi Trường Kiểm Thử Lab & Unit Tests

Dự án tích hợp sẵn ứng dụng web mẫu tại thư mục `Pentest/` và bộ kiểm thử tự động gồm 45 unit tests:

```bash
# Chạy ứng dụng Lab mục tiêu trên localhost
python Pentest/app.py

# Chạy toàn bộ test suite kiểm thử tự động:
pytest -v
```

---

## Tác Giả & Giấy Phép

- **Tác giả**: **Đặng Đình Nguyên**
- **Giấy phép**: Mã nguồn được phát hành theo giấy phép mã nguồn mở [MIT License](LICENSE).
