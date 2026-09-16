#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Main CLI entrypoint for Web Security Scanner.
Tuân thủ nghiêm ngặt 7 Nguyên tắc An toàn Bắt buộc:
1. Xác nhận pháp lý bắt buộc trước khi quét (gõ lại chính xác domain; xác nhận lần 2 nếu bật --active).
2. Safe mode là mặc định tuyệt đối (không tự bật --active ngầm).
3. Global Request Budget toàn cục cho phiên quét (chạm ngưỡng dừng an toàn, không crash, vẫn xuất báo cáo).
4. Không tự ý hạ cấp check khi thiếu điều kiện (trả về NOT_TESTED).
5. Không log / không in secret ra report (tự động mask Bearer, cookies, keys, password).
6. Khai báo rõ ràng RISK_LEVEL ("safe" hoặc "active_only") ở từng module.
7. Không destructive payload dưới bất kỳ mode nào (không DROP/DELETE, không reverse shell, không brute-force).
"""

import argparse
import os
import sys
import time
from urllib.parse import urlparse
from typing import List, Optional

from core.config import Config
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from crawler.crawler import Crawler
from fingerprint import fingerprint_response
from models.finding import Finding
from models.result import ScanResult
from checks import run_checks
from reporting.console import ConsoleReporter
from reporting.json_report import JSONReporter
from reporting.html_report import HTMLReporter


def verify_legal_consent(
    target_domain: str,
    is_active: bool,
    confirm_domain_arg: Optional[str] = None,
    confirm_active_arg: Optional[str] = None,
) -> bool:
    """
    Xác nhận pháp lý trước khi scan:
    1. Yêu cầu người dùng gõ lại chính xác target domain để xác nhận có quyền scan.
    2. Nếu bật --active, yêu cầu xác nhận lần 2 kèm cảnh báo rõ danh sách các check intrusive.
    """
    print("\n" + "=" * 72)
    print("🛡️  SECURITY SCANNER - XÁC NHẬN PHÁP LÝ & QUYỀN TRUY CẬP HỆ THỐNG")
    print("=" * 72)
    print("CẢNH BÁO BẮT BUỘC:")
    print("Bạn chỉ được phép quét an ninh trên mục tiêu mà bạn sở hữu hoặc đã được")
    print("cấp văn bản ủy quyền hợp pháp. Mọi hành vi quét trái phép đều vi phạm pháp luật.")
    print("-" * 72)

    # 1. Xác nhận domain
    if confirm_domain_arg is not None:
        user_domain = confirm_domain_arg.strip()
    else:
        try:
            prompt_msg = f"Nhập lại domain để xác nhận bạn có quyền scan (vd: {target_domain}): "
            user_domain = input(prompt_msg).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Đã hủy thao tác.")
            return False

    if user_domain.lower() != target_domain.lower():
        print(f"\n[!] XÁC NHẬN THẤT BẠI: Domain '{user_domain}' không khớp với target domain '{target_domain}'.")
        print("[!] Hủy bỏ phiên quét để đảm bảo an toàn pháp lý.")
        return False

    print(f"[✓] Đã xác nhận quyền scan hợp pháp cho domain: {target_domain}")

    # 2. Xác nhận Active Mode nếu được bật
    if is_active:
        print("\n" + "=" * 72)
        print("⚠️  CẢNH BÁO: BẠN ĐANG YÊU CẦU KÍCH HOẠT CHẾ ĐỘ ACTIVE MODE")
        print("=" * 72)
        print("ACTIVE MODE sẽ gửi các payload intrusive hơn SAFE MODE, bao gồm:")
        print("  - Stored XSS: Tự động submit dữ liệu/form thật vào ứng dụng mục tiêu.")
        print("  - Time-based SQLi & Command Injection: Gây độ trễ (delay 2-3s) có kiểm soát.")
        print("  - Path Traversal: Thăm dò file hệ thống có trong whitelist an toàn (/etc/hostname, win.ini).")
        print("  - SSRF: Gửi payload tới callback URL được chỉ định (--callback-url).")
        print("  - Open Redirect: Kiểm tra tham số điều hướng với domain thử nghiệm an toàn (.invalid).")
        print("  - CSRF & IDOR: Phân tích token form và kiểm tra phân quyền giữa 2 phiên người dùng.")
        print("  - JWT Weak Configuration: Kiểm tra thuật toán ký 'none' và thời hạn exp.")
        print("  - File Upload: Kiểm tra bộ lọc upload bằng file ảnh PNG vô hại đổi đuôi tệp.")
        print("  - API & GraphQL: Thăm dò Introspection query công khai (chỉ query, không dump data).")
        print("  - Rate Limiting Burst: Thử nghiệm tối đa 5 request liên tiếp kiểm tra 429.")
        print("Lưu ý: Công cụ TUYỆT ĐỐI KHÔNG chứa destructive payloads (DROP/DELETE, reverse shell).")
        print("-" * 72)

        if confirm_active_arg is not None:
            active_conf = confirm_active_arg.strip()
        else:
            try:
                active_conf = input(
                    f"XÁC NHẬN LẦN 2: Nhập lại domain '{target_domain}' hoặc gõ 'ACTIVE' để tiếp tục: "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Đã hủy thao tác.")
                return False

        if active_conf.lower() not in (target_domain.lower(), "active"):
            print("\n[!] XÁC NHẬN ACTIVE MODE THẤT BẠI: Người dùng không đồng ý. Hủy bỏ phiên quét.")
            return False

        print(f"[✓] Đã xác nhận kích hoạt ACTIVE MODE thành công.")

    return True


# Đạo hữu xin nương tay, đại trận hộ sơn (Scan Orchestrator) tổng tài điều phối âm dương ngũ hành, xử lý kiếp số thiên lôi (Budget & Safety Gate) đang vận hành ổn định, chớ dại mà động vào kẻo linh lực nghịch chuyển, tẩu hỏa nhập ma.
def run_scan(config: Config) -> ScanResult:
    start_time = time.time()
    result = ScanResult(
        target=config.target,
        mode=config.mode,
        start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
    )

    client = HTTPClient(config=config)
    crawler = Crawler(config=config, http_client=client)

    # A. Bắt đầu Crawl thu thập bề mặt tấn công
    print(f"[*] Bắt đầu thu thập bề mặt tấn công (Crawler) cho {config.target}...")
    try:
        crawler.crawl()
    except ScanBudgetExceeded as e:
        print(f"\n[!] GIỚI HẠN REQUEST TOÀN CỤC ĐÃ ĐẠT TRONG CRAWLER: {e}")
    except Exception as e:
        print(f"[!] Gặp sự cố trong Crawler: {e}")

    result.attack_surface = crawler.endpoints_map

    # B. Nhận diện công nghệ (Fingerprinting)
    try:
        root_resp = client.get(config.target)
        fp = fingerprint_response(
            headers=root_resp.headers,
            cookies=root_resp.cookies,
            html_content=root_resp.text or "",
        )
        if fp.get("server") and fp["server"].get("name") != "Unknown":
            srv = fp["server"]
            result.findings.append(Finding(
                type="Server Detection",
                severity="INFO",
                status="INFO",
                detail=f"Phát hiện web server: {srv['name']}",
                evidence=str(srv.get("evidence", "")),
                confidence=srv.get("confidence", "HIGH"),
                endpoint=config.target,
                recommendation="Cân nhắc ẩn banner/header phiên bản máy chủ nếu không cần thiết.",
            ))
        for tech in fp.get("technologies", []):
            result.findings.append(Finding(
                type="Technology Detection",
                severity="INFO",
                status="INFO",
                detail=f"Phát hiện công nghệ: {tech['name']} (version: {tech.get('version') or 'N/A'})",
                evidence=str(tech.get("evidence", "")),
                confidence=tech.get("confidence", "HIGH"),
                endpoint=config.target,
                recommendation="Đảm bảo cập nhật bản vá mới nhất cho công nghệ phát hiện.",
            ))
        for fw in fp.get("frameworks", []):
            result.findings.append(Finding(
                type="Framework Detection",
                severity="INFO",
                status="INFO",
                detail=f"Phát hiện framework: {fw['name']} (version: {fw.get('version') or 'N/A'})",
                evidence=str(fw.get("evidence", "")),
                confidence=fw.get("confidence", "HIGH"),
                endpoint=config.target,
                recommendation="Ẩn thông tin framework khỏi HTTP response headers.",
            ))
    except ScanBudgetExceeded as e:
        print(f"\n[!] GIỚI HẠN REQUEST TOÀN CỤC ĐÃ ĐẠT: {e}")
    except Exception:
        pass

    # C. Chạy Vulnerability Checks
    print(f"[*] Bắt đầu thực hiện các bài kiểm tra an ninh ({config.mode.upper()} MODE)...")
    try:
        check_findings = run_checks(client, config, result.attack_surface)
        result.findings.extend(check_findings)
    except ScanBudgetExceeded as e:
        print(f"\n[!] GIỚI HẠN REQUEST TOÀN CỤC ĐÃ ĐẠT TRONG QUÁ TRÌNH KIỂM TRA: {e}")
    except Exception as e:
        print(f"[!] Lỗi trong quá trình chạy checks: {e}")

    # D. Hoàn tất thông số ScanResult
    result.duration = round(time.time() - start_time, 2)
    result.total_requests = client.total_requests

    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Web Security Automation Scanner - Safe & Intrusive (Active) Testing Toolkit",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", nargs="?", default=None, help="Target URL (vd: http://example.com)")
    parser.add_argument("--target", dest="target_opt", help="Target URL (tùy chọn cờ thay thế)")
    parser.add_argument("--active", action="store_true", default=False, help="Bật Active Mode (gửi payload intrusive). Mặc định là SAFE mode.")
    parser.add_argument("--max-requests", type=int, default=None, help="Giới hạn số request tối đa cho phiên quét (Mặc định: 500 ở SAFE, 1500 ở ACTIVE).")
    parser.add_argument("--rps", type=float, default=5.0, help="Số lượng request tối đa mỗi giây (Rate limit).")
    parser.add_argument("--max-depth", type=int, default=3, help="Độ sâu tối đa khi crawl.")
    parser.add_argument("--max-pages", type=int, default=50, help="Số trang tối đa khi crawl.")
    parser.add_argument("--output-dir", default="output", help="Thư mục xuất báo cáo.")
    parser.add_argument("--json", dest="json_path", help="Đường dẫn file báo cáo JSON (mặc định: <output-dir>/scan_report.json).")
    parser.add_argument("--html", dest="html_path", help="Đường dẫn file báo cáo HTML (mặc định: <output-dir>/scan_report.html).")
    parser.add_argument("--confirm-domain", dest="confirm_domain", default=None, help="Xác nhận trước domain target (dùng cho automated testing/CI).")
    parser.add_argument("--confirm-active", dest="confirm_active", default=None, help="Xác nhận trước active mode (dùng cho automated testing/CI).")
    parser.add_argument("--callback-url", dest="callback_url", default=None, help="URL callback máy chủ riêng phục vụ kiểm tra SSRF out-of-band.")
    parser.add_argument("--auth-cookie-a", dest="auth_cookie_a", default=None, help="Cookie phiên xác thực người dùng A (phục vụ IDOR).")
    parser.add_argument("--auth-cookie-b", dest="auth_cookie_b", default=None, help="Cookie phiên xác thực người dùng B (phục vụ IDOR).")
    parser.add_argument("--auth-header-a", dest="auth_header_a", default=None, help="Header xác thực người dùng A (vd: 'Authorization: Bearer <token>') phục vụ IDOR.")
    parser.add_argument("--auth-header-b", dest="auth_header_b", default=None, help="Header xác thực người dùng B (vd: 'Authorization: Bearer <token>') phục vụ IDOR.")

    args = parser.parse_args(argv)

    raw_target = args.target or args.target_opt
    if not raw_target:
        parser.print_help()
        print("\n[!] Lỗi: Vui lòng cung cấp URL mục tiêu (target).")
        return 1

    # Chuẩn hóa target URL
    target = raw_target.strip()
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "http://" + target

    parsed = urlparse(target)
    target_domain = parsed.hostname
    if not target_domain:
        print(f"[!] Lỗi: URL mục tiêu không hợp lệ: {raw_target}")
        return 1

    # 1. Xác nhận pháp lý bắt buộc trước khi quét
    consent = verify_legal_consent(
        target_domain=target_domain,
        is_active=args.active,
        confirm_domain_arg=args.confirm_domain,
        confirm_active_arg=args.confirm_active,
    )
    if not consent:
        return 1

    # 2. Khởi tạo Config (Safe mode là mặc định tuyệt đối)
    mode = "active" if args.active else "safe"
    max_reqs = args.max_requests
    if max_reqs is None:
        max_reqs = 1500 if mode == "active" else 500

    config = Config(
        target=target,
        mode=mode,
        max_requests_per_scan=max_reqs,
        requests_per_second=args.rps,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        callback_url=args.callback_url,
        auth_cookie_a=args.auth_cookie_a,
        auth_cookie_b=args.auth_cookie_b,
        auth_header_a=args.auth_header_a,
        auth_header_b=args.auth_header_b,
    )

    # 3. Chạy phiên quét
    print(f"\n[*] Bắt đầu phiên quét an ninh cho {target} [Chế độ: {mode.upper()}]...")
    result = run_scan(config)

    # 4. Xuất báo cáo (Console, JSON, HTML)
    print(ConsoleReporter.render(result))

    os.makedirs(args.output_dir, exist_ok=True)
    json_file = args.json_path or os.path.join(args.output_dir, "scan_report.json")
    html_file = args.html_path or os.path.join(args.output_dir, "scan_report.html")

    JSONReporter.generate(result, output_path=json_file)
    HTMLReporter.generate(result, output_path=html_file)

    print("\n[✓] Đã xuất báo cáo quét an ninh:")
    print(f"  - JSON Report: {os.path.abspath(json_file)}")
    print(f"  - HTML Report: {os.path.abspath(html_file)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
